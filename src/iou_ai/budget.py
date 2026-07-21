"""Fail-closed, append-only monthly budget accounting for model calls.

All monetary values are integer microdollars (one millionth of a US dollar).
The ledger reserves the worst-case price before a request is sent and replaces
that reservation with the price calculated from provider-reported token usage
when the request is settled.  Missing or malformed usage is charged at the
full reservation.

The billing month is the UTC calendar month containing the reservation.  A
settlement is always attributed to that reservation month, even if it arrives
after the month boundary.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path
from typing import Any, Literal, Mapping


MICRODOLLARS_PER_DOLLAR = 1_000_000
TOKENS_PER_MILLION = 1_000_000
DEFAULT_HARD_LIMIT_MICRODOLLARS = 7_500_000
DEFAULT_WARNING_THRESHOLDS_MICRODOLLARS = (5_500_000, 6_750_000)


class BudgetError(RuntimeError):
    """Base class for budget subsystem failures."""


class BudgetConfigurationError(BudgetError):
    """Raised for invalid limits, quotas, or pricing policies."""


class BudgetExceeded(BudgetError):
    """Raised when a reservation would cross the monthly hard limit."""


class QuotaExceeded(BudgetError):
    """Raised when a provider/model monthly call quota is exhausted."""


class UnknownQuota(BudgetError):
    """Raised when no explicit call quota exists for a provider/model."""


class KillSwitchActive(BudgetError):
    """Raised when the local model-call kill switch is present or unreadable."""


class DuplicateRequest(BudgetError):
    """Raised when a request key has already been reserved this month."""


class ReservationNotFound(BudgetError):
    """Raised when a reservation identifier is unknown."""


class ReservationAlreadyClosed(BudgetError):
    """Raised when a reservation already has a terminal event."""


class PricingNotEffective(BudgetError):
    """Raised when a pricing policy is not effective for a request date."""


def _require_nonnegative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BudgetConfigurationError(f"{name} must be a non-negative integer")
    return value


def usd_to_microdollars(value: str | int | Decimal) -> int:
    """Convert USD to integer microdollars, rounding fractions upward.

    Floats are deliberately rejected so binary floating-point values cannot
    silently weaken the hard cap.  Configuration should use strings such as
    ``"7.50"`` or :class:`~decimal.Decimal`.
    """

    if isinstance(value, bool) or isinstance(value, float):
        raise BudgetConfigurationError("USD values must be strings, integers, or Decimal")
    try:
        dollars = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BudgetConfigurationError(f"invalid USD value: {value!r}") from exc
    if not dollars.is_finite() or dollars < 0:
        raise BudgetConfigurationError("USD value must be finite and non-negative")
    return int(
        (dollars * MICRODOLLARS_PER_DOLLAR).to_integral_value(rounding=ROUND_CEILING)
    )


def microdollars_to_usd(value: int) -> Decimal:
    """Return an exact Decimal USD value for integer microdollars."""

    amount = _require_nonnegative_int(value, "microdollars")
    return Decimal(amount) / MICRODOLLARS_PER_DOLLAR


def _ceil_rate(tokens: int, rate_microdollars_per_million: int) -> int:
    numerator = tokens * rate_microdollars_per_million
    return (numerator + TOKENS_PER_MILLION - 1) // TOKENS_PER_MILLION


@dataclass(frozen=True, slots=True)
class PricingPolicy:
    """Versioned token pricing with an explicit effective-date interval.

    ``effective_until`` is exclusive.  A missing cached-input rate means that
    cached tokens are conservatively priced at the normal input rate.
    """

    provider: str
    model: str
    version: str
    effective_from: date
    effective_until: date | None
    input_rate_microdollars_per_million: int
    output_rate_microdollars_per_million: int
    cached_input_rate_microdollars_per_million: int | None = None

    def __post_init__(self) -> None:
        for name in ("provider", "model", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise BudgetConfigurationError(f"pricing {name} must be non-empty")
        if not isinstance(self.effective_from, date):
            raise BudgetConfigurationError("effective_from must be a date")
        if self.effective_until is not None:
            if not isinstance(self.effective_until, date):
                raise BudgetConfigurationError("effective_until must be a date or None")
            if self.effective_until <= self.effective_from:
                raise BudgetConfigurationError(
                    "effective_until must be later than effective_from"
                )
        _require_nonnegative_int(
            self.input_rate_microdollars_per_million,
            "input_rate_microdollars_per_million",
        )
        _require_nonnegative_int(
            self.output_rate_microdollars_per_million,
            "output_rate_microdollars_per_million",
        )
        if self.cached_input_rate_microdollars_per_million is not None:
            _require_nonnegative_int(
                self.cached_input_rate_microdollars_per_million,
                "cached_input_rate_microdollars_per_million",
            )

    @property
    def cached_rate(self) -> int:
        return (
            self.input_rate_microdollars_per_million
            if self.cached_input_rate_microdollars_per_million is None
            else self.cached_input_rate_microdollars_per_million
        )

    def is_effective(self, on: date) -> bool:
        return self.effective_from <= on and (
            self.effective_until is None or on < self.effective_until
        )

    def quote(
        self,
        *,
        input_tokens: int,
        output_tokens: int,
        cached_input_tokens: int = 0,
    ) -> int:
        """Conservatively quote reported usage in integer microdollars."""

        input_count = _require_nonnegative_int(input_tokens, "input_tokens")
        output_count = _require_nonnegative_int(output_tokens, "output_tokens")
        cached_count = _require_nonnegative_int(
            cached_input_tokens, "cached_input_tokens"
        )
        if cached_count > input_count:
            raise BudgetConfigurationError(
                "cached_input_tokens cannot exceed input_tokens"
            )
        uncached_count = input_count - cached_count
        return (
            _ceil_rate(uncached_count, self.input_rate_microdollars_per_million)
            + _ceil_rate(cached_count, self.cached_rate)
            + _ceil_rate(output_count, self.output_rate_microdollars_per_million)
        )


@dataclass(frozen=True, slots=True)
class Reservation:
    reservation_id: str
    event_id: str
    month: str
    provider: str
    model: str
    request_key: str
    reserved_microdollars: int
    pricing_version: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class Settlement:
    reservation_id: str
    event_id: str
    event_type: Literal["settle", "abandon"]
    month: str
    provider: str
    model: str
    reserved_microdollars: int
    charged_microdollars: int
    usage_valid: bool
    closed_at: datetime


@dataclass(frozen=True, slots=True)
class CallCount:
    provider: str
    model: str
    used: int
    quota: int | None


@dataclass(frozen=True, slots=True)
class BudgetStatus:
    month: str
    hard_limit_microdollars: int
    charged_microdollars: int
    active_reserved_microdollars: int
    effective_spend_microdollars: int
    remaining_microdollars: int
    warning_level: Literal["ok", "warning", "critical", "exhausted"]
    crossed_warning_thresholds_microdollars: tuple[int, ...]
    call_counts: tuple[CallCount, ...]


@dataclass(frozen=True, slots=True)
class LedgerEvent:
    sequence: int
    event_id: str
    event_type: Literal["reserve", "settle", "abandon"]
    reservation_id: str
    occurred_at: datetime
    month: str
    provider: str
    model: str
    request_key: str
    amount_microdollars: int
    pricing_version: str
    usage_valid: bool | None
    details: Mapping[str, Any]


class BudgetLedger:
    """SQLite-backed, append-only budget ledger.

    A provider/model without an explicit entry in ``monthly_call_quotas`` is
    rejected.  This prevents a typo or newly added model from bypassing call
    limits.  The default kill-switch path is ``AI_CALLS_DISABLED`` beside the
    database; its presence blocks new reservations but never blocks settlement.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        hard_limit_microdollars: int = DEFAULT_HARD_LIMIT_MICRODOLLARS,
        monthly_call_quotas: Mapping[tuple[str, str], int] | None = None,
        warning_thresholds_microdollars: tuple[int, ...] = (
            DEFAULT_WARNING_THRESHOLDS_MICRODOLLARS
        ),
        kill_switch_path: str | Path | None = None,
        daily_limit_microdollars: int | None = None,
        sqlite_timeout_seconds: float = 30.0,
    ) -> None:
        self.db_path = Path(db_path)
        self.hard_limit_microdollars = _require_nonnegative_int(
            hard_limit_microdollars, "hard_limit_microdollars"
        )
        if self.hard_limit_microdollars == 0:
            raise BudgetConfigurationError("hard_limit_microdollars must be positive")
        thresholds = tuple(
            _require_nonnegative_int(item, "warning threshold")
            for item in warning_thresholds_microdollars
        )
        if tuple(sorted(set(thresholds))) != thresholds:
            raise BudgetConfigurationError(
                "warning thresholds must be strictly increasing and unique"
            )
        if any(item >= self.hard_limit_microdollars for item in thresholds):
            raise BudgetConfigurationError(
                "warning thresholds must be below the hard limit"
            )
        self.warning_thresholds_microdollars = thresholds

        if daily_limit_microdollars is None:
            self.daily_limit_microdollars: int | None = None
        else:
            daily = _require_nonnegative_int(
                daily_limit_microdollars, "daily_limit_microdollars"
            )
            if daily == 0:
                raise BudgetConfigurationError(
                    "daily_limit_microdollars must be positive"
                )
            self.daily_limit_microdollars = daily

        quotas: dict[tuple[str, str], int] = {}
        for key, value in (monthly_call_quotas or {}).items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not all(isinstance(part, str) and part.strip() for part in key)
            ):
                raise BudgetConfigurationError(
                    "quota keys must be non-empty (provider, model) tuples"
                )
            quotas[key] = _require_nonnegative_int(value, f"quota for {key!r}")
        self.monthly_call_quotas = quotas
        self.kill_switch_path = (
            Path(kill_switch_path)
            if kill_switch_path is not None
            else self.db_path.with_name("AI_CALLS_DISABLED")
        )
        if isinstance(sqlite_timeout_seconds, bool) or sqlite_timeout_seconds <= 0:
            raise BudgetConfigurationError("sqlite_timeout_seconds must be positive")
        self.sqlite_timeout_seconds = float(sqlite_timeout_seconds)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path,
            timeout=self.sqlite_timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            f"PRAGMA busy_timeout = {int(self.sqlite_timeout_seconds * 1000)}"
        )
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL
                        CHECK (event_type IN ('reserve', 'settle', 'abandon')),
                    reservation_id TEXT NOT NULL,
                    occurred_at_utc TEXT NOT NULL,
                    month_key TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    amount_microdollars INTEGER NOT NULL
                        CHECK (amount_microdollars >= 0),
                    pricing_version TEXT NOT NULL,
                    pricing_effective_from TEXT NOT NULL,
                    pricing_effective_until TEXT,
                    input_rate_microdollars_per_million INTEGER NOT NULL
                        CHECK (input_rate_microdollars_per_million >= 0),
                    output_rate_microdollars_per_million INTEGER NOT NULL
                        CHECK (output_rate_microdollars_per_million >= 0),
                    cached_input_rate_microdollars_per_million INTEGER NOT NULL
                        CHECK (cached_input_rate_microdollars_per_million >= 0),
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    cached_input_tokens INTEGER,
                    usage_valid INTEGER,
                    details_json TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS one_reservation_per_request
                    ON ledger_events(month_key, provider, model, request_key)
                    WHERE event_type = 'reserve';

                CREATE UNIQUE INDEX IF NOT EXISTS one_terminal_per_reservation
                    ON ledger_events(reservation_id)
                    WHERE event_type IN ('settle', 'abandon');

                CREATE INDEX IF NOT EXISTS reservations_by_month
                    ON ledger_events(month_key, event_type);

                CREATE TRIGGER IF NOT EXISTS ledger_events_are_append_only_update
                    BEFORE UPDATE ON ledger_events
                    BEGIN
                        SELECT RAISE(ABORT, 'ledger_events is append-only');
                    END;

                CREATE TRIGGER IF NOT EXISTS ledger_events_are_append_only_delete
                    BEFORE DELETE ON ledger_events
                    BEGIN
                        SELECT RAISE(ABORT, 'ledger_events is append-only');
                    END;
                """
            )
        finally:
            connection.close()

    @staticmethod
    def _normalize_now(now: datetime | None) -> datetime:
        current = datetime.now(timezone.utc) if now is None else now
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise BudgetConfigurationError("timestamps must be timezone-aware")
        return current.astimezone(timezone.utc)

    @staticmethod
    def _month_key(instant: datetime) -> str:
        return instant.strftime("%Y-%m")

    @staticmethod
    def _day_key(instant: datetime) -> str:
        return instant.strftime("%Y-%m-%d")

    @staticmethod
    def _json_details(details: Mapping[str, Any] | None) -> str:
        if details is None:
            return "{}"
        if not isinstance(details, Mapping):
            raise BudgetConfigurationError("details must be a mapping")
        try:
            return json.dumps(
                dict(details), sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
        except (TypeError, ValueError) as exc:
            raise BudgetConfigurationError("details must be JSON-serializable") from exc

    def _assert_calls_enabled(self) -> None:
        try:
            disabled = self.kill_switch_path.exists()
        except OSError as exc:
            raise KillSwitchActive(
                f"cannot verify kill switch {self.kill_switch_path}: {exc}"
            ) from exc
        if disabled:
            raise KillSwitchActive(
                f"model calls disabled by kill switch: {self.kill_switch_path}"
            )

    def _quota_for(self, provider: str, model: str) -> int:
        try:
            return self.monthly_call_quotas[(provider, model)]
        except KeyError as exc:
            raise UnknownQuota(
                f"no monthly call quota configured for {provider}/{model}"
            ) from exc

    @staticmethod
    def _spend_parts(
        connection: sqlite3.Connection, month: str
    ) -> tuple[int, int]:
        row = connection.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN terminal.sequence IS NOT NULL
                                  THEN terminal.amount_microdollars ELSE 0 END), 0)
                    AS charged,
                COALESCE(SUM(CASE WHEN terminal.sequence IS NULL
                                  THEN reserve.amount_microdollars ELSE 0 END), 0)
                    AS active_reserved
            FROM ledger_events AS reserve
            LEFT JOIN ledger_events AS terminal
              ON terminal.reservation_id = reserve.reservation_id
             AND terminal.event_type IN ('settle', 'abandon')
            WHERE reserve.event_type = 'reserve'
              AND reserve.month_key = ?
            """,
            (month,),
        ).fetchone()
        return int(row["charged"]), int(row["active_reserved"])

    @staticmethod
    def _day_effective_spend(connection: sqlite3.Connection, day: str) -> int:
        row = connection.execute(
            """
            SELECT COALESCE(SUM(
                       CASE WHEN terminal.sequence IS NOT NULL
                            THEN terminal.amount_microdollars
                            ELSE reserve.amount_microdollars END), 0) AS effective
            FROM ledger_events AS reserve
            LEFT JOIN ledger_events AS terminal
              ON terminal.reservation_id = reserve.reservation_id
             AND terminal.event_type IN ('settle', 'abandon')
            WHERE reserve.event_type = 'reserve'
              AND substr(reserve.occurred_at_utc, 1, 10) = ?
            """,
            (day,),
        ).fetchone()
        return int(row["effective"])

    @staticmethod
    def _call_count(
        connection: sqlite3.Connection, month: str, provider: str, model: str
    ) -> int:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count
              FROM ledger_events
             WHERE event_type = 'reserve'
               AND month_key = ?
               AND provider = ?
               AND model = ?
            """,
            (month, provider, model),
        ).fetchone()
        return int(row["count"])

    @staticmethod
    def _validate_identity(provider: str, model: str, request_key: str) -> None:
        for name, value, limit in (
            ("provider", provider, 100),
            ("model", model, 200),
            ("request_key", request_key, 512),
        ):
            if not isinstance(value, str) or not value.strip():
                raise BudgetConfigurationError(f"{name} must be a non-empty string")
            if len(value) > limit:
                raise BudgetConfigurationError(f"{name} is too long")

    def reserve(
        self,
        *,
        provider: str,
        model: str,
        request_key: str,
        worst_case_microdollars: int,
        pricing_policy: PricingPolicy,
        now: datetime | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> Reservation:
        """Atomically reserve worst-case cost before a provider request.

        The transaction uses ``BEGIN IMMEDIATE`` so competing processes cannot
        both observe the same remaining budget and over-reserve it.
        """

        self._validate_identity(provider, model, request_key)
        amount = _require_nonnegative_int(
            worst_case_microdollars, "worst_case_microdollars"
        )
        if not isinstance(pricing_policy, PricingPolicy):
            raise BudgetConfigurationError("pricing_policy must be a PricingPolicy")
        if pricing_policy.provider != provider or pricing_policy.model != model:
            raise BudgetConfigurationError(
                "pricing policy provider/model does not match reservation"
            )
        instant = self._normalize_now(now)
        if not pricing_policy.is_effective(instant.date()):
            raise PricingNotEffective(
                f"pricing {pricing_policy.version!r} is not effective on {instant.date()}"
            )
        detail_json = self._json_details(details)
        quota = self._quota_for(provider, model)
        self._assert_calls_enabled()

        month = self._month_key(instant)
        reservation_id = uuid.uuid4().hex
        event_id = uuid.uuid4().hex
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            # Recheck after taking the write lock, minimizing the kill-switch race.
            self._assert_calls_enabled()

            existing = connection.execute(
                """
                SELECT reservation_id
                  FROM ledger_events
                 WHERE event_type = 'reserve'
                   AND month_key = ? AND provider = ? AND model = ?
                   AND request_key = ?
                """,
                (month, provider, model, request_key),
            ).fetchone()
            if existing is not None:
                raise DuplicateRequest(
                    f"request key already reserved as {existing['reservation_id']}"
                )

            used_calls = self._call_count(connection, month, provider, model)
            if used_calls >= quota:
                raise QuotaExceeded(
                    f"monthly call quota exhausted for {provider}/{model}: "
                    f"{used_calls}/{quota}"
                )

            charged, active_reserved = self._spend_parts(connection, month)
            effective_spend = charged + active_reserved
            if effective_spend + amount > self.hard_limit_microdollars:
                raise BudgetExceeded(
                    f"reservation would exceed {month} hard limit: "
                    f"{effective_spend} + {amount} > {self.hard_limit_microdollars} "
                    "microdollars"
                )

            if self.daily_limit_microdollars is not None:
                day = self._day_key(instant)
                day_spend = self._day_effective_spend(connection, day)
                if day_spend + amount > self.daily_limit_microdollars:
                    raise BudgetExceeded(
                        f"reservation would exceed {day} daily limit: "
                        f"{day_spend} + {amount} > {self.daily_limit_microdollars} "
                        "microdollars"
                    )

            connection.execute(
                """
                INSERT INTO ledger_events (
                    event_id, event_type, reservation_id, occurred_at_utc,
                    month_key, provider, model, request_key,
                    amount_microdollars, pricing_version,
                    pricing_effective_from, pricing_effective_until,
                    input_rate_microdollars_per_million,
                    output_rate_microdollars_per_million,
                    cached_input_rate_microdollars_per_million,
                    input_tokens, output_tokens, cached_input_tokens,
                    usage_valid, details_json
                ) VALUES (?, 'reserve', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          NULL, NULL, NULL, NULL, ?)
                """,
                (
                    event_id,
                    reservation_id,
                    instant.isoformat(),
                    month,
                    provider,
                    model,
                    request_key,
                    amount,
                    pricing_policy.version,
                    pricing_policy.effective_from.isoformat(),
                    (
                        pricing_policy.effective_until.isoformat()
                        if pricing_policy.effective_until is not None
                        else None
                    ),
                    pricing_policy.input_rate_microdollars_per_million,
                    pricing_policy.output_rate_microdollars_per_million,
                    pricing_policy.cached_rate,
                    detail_json,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

        return Reservation(
            reservation_id=reservation_id,
            event_id=event_id,
            month=month,
            provider=provider,
            model=model,
            request_key=request_key,
            reserved_microdollars=amount,
            pricing_version=pricing_policy.version,
            created_at=instant,
        )

    def reserve_for_tokens(
        self,
        *,
        provider: str,
        model: str,
        request_key: str,
        max_input_tokens: int,
        max_output_tokens: int,
        pricing_policy: PricingPolicy,
        guaranteed_cached_input_tokens: int = 0,
        now: datetime | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> Reservation:
        """Quote and reserve a bounded request from its maximum token counts."""

        amount = pricing_policy.quote(
            input_tokens=max_input_tokens,
            output_tokens=max_output_tokens,
            cached_input_tokens=guaranteed_cached_input_tokens,
        )
        return self.reserve(
            provider=provider,
            model=model,
            request_key=request_key,
            worst_case_microdollars=amount,
            pricing_policy=pricing_policy,
            now=now,
            details=details,
        )

    @staticmethod
    def _active_reservation(
        connection: sqlite3.Connection, reservation_id: str
    ) -> sqlite3.Row:
        reserve = connection.execute(
            """
            SELECT * FROM ledger_events
             WHERE event_type = 'reserve' AND reservation_id = ?
            """,
            (reservation_id,),
        ).fetchone()
        if reserve is None:
            raise ReservationNotFound(f"unknown reservation: {reservation_id}")
        terminal = connection.execute(
            """
            SELECT event_id, event_type FROM ledger_events
             WHERE reservation_id = ? AND event_type IN ('settle', 'abandon')
            """,
            (reservation_id,),
        ).fetchone()
        if terminal is not None:
            raise ReservationAlreadyClosed(
                f"reservation {reservation_id} already closed by "
                f"{terminal['event_type']} event {terminal['event_id']}"
            )
        return reserve

    @staticmethod
    def _valid_usage(
        input_tokens: object,
        output_tokens: object,
        cached_input_tokens: object,
    ) -> bool:
        values = (input_tokens, output_tokens, cached_input_tokens)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            return False
        if any(value < 0 for value in values):
            return False
        return cached_input_tokens <= input_tokens

    @staticmethod
    def _policy_from_row(row: sqlite3.Row) -> PricingPolicy:
        return PricingPolicy(
            provider=row["provider"],
            model=row["model"],
            version=row["pricing_version"],
            effective_from=date.fromisoformat(row["pricing_effective_from"]),
            effective_until=(
                date.fromisoformat(row["pricing_effective_until"])
                if row["pricing_effective_until"] is not None
                else None
            ),
            input_rate_microdollars_per_million=row[
                "input_rate_microdollars_per_million"
            ],
            output_rate_microdollars_per_million=row[
                "output_rate_microdollars_per_million"
            ],
            cached_input_rate_microdollars_per_million=row[
                "cached_input_rate_microdollars_per_million"
            ],
        )

    def settle(
        self,
        reservation_id: str,
        *,
        input_tokens: object = None,
        output_tokens: object = None,
        cached_input_tokens: object = 0,
        now: datetime | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> Settlement:
        """Settle from provider usage; invalid or missing usage costs the reserve."""

        return self._close(
            reservation_id,
            event_type="settle",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
            now=now,
            details=details,
        )

    def abandon(
        self,
        reservation_id: str,
        *,
        reason: str,
        now: datetime | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> Settlement:
        """Close an uncertain request and conservatively charge its full reserve."""

        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise BudgetConfigurationError("abandon reason must be 1-500 characters")
        merged = dict(details or {})
        merged["reason"] = reason
        return self._close(
            reservation_id,
            event_type="abandon",
            input_tokens=None,
            output_tokens=None,
            cached_input_tokens=None,
            now=now,
            details=merged,
        )

    def _close(
        self,
        reservation_id: str,
        *,
        event_type: Literal["settle", "abandon"],
        input_tokens: object,
        output_tokens: object,
        cached_input_tokens: object,
        now: datetime | None,
        details: Mapping[str, Any] | None,
    ) -> Settlement:
        if not isinstance(reservation_id, str) or not reservation_id:
            raise BudgetConfigurationError("reservation_id must be non-empty")
        instant = self._normalize_now(now)
        detail_json = self._json_details(details)
        event_id = uuid.uuid4().hex
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            reserve = self._active_reservation(connection, reservation_id)
            reserved = int(reserve["amount_microdollars"])
            usage_valid = event_type == "settle" and self._valid_usage(
                input_tokens, output_tokens, cached_input_tokens
            )
            if usage_valid:
                policy = self._policy_from_row(reserve)
                charged = policy.quote(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cached_input_tokens=cached_input_tokens,
                )
                recorded_input = input_tokens
                recorded_output = output_tokens
                recorded_cached = cached_input_tokens
            else:
                charged = reserved
                recorded_input = None
                recorded_output = None
                recorded_cached = None

            connection.execute(
                """
                INSERT INTO ledger_events (
                    event_id, event_type, reservation_id, occurred_at_utc,
                    month_key, provider, model, request_key,
                    amount_microdollars, pricing_version,
                    pricing_effective_from, pricing_effective_until,
                    input_rate_microdollars_per_million,
                    output_rate_microdollars_per_million,
                    cached_input_rate_microdollars_per_million,
                    input_tokens, output_tokens, cached_input_tokens,
                    usage_valid, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    reservation_id,
                    instant.isoformat(),
                    reserve["month_key"],
                    reserve["provider"],
                    reserve["model"],
                    reserve["request_key"],
                    charged,
                    reserve["pricing_version"],
                    reserve["pricing_effective_from"],
                    reserve["pricing_effective_until"],
                    reserve["input_rate_microdollars_per_million"],
                    reserve["output_rate_microdollars_per_million"],
                    reserve["cached_input_rate_microdollars_per_million"],
                    recorded_input,
                    recorded_output,
                    recorded_cached,
                    1 if usage_valid else 0,
                    detail_json,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

        return Settlement(
            reservation_id=reservation_id,
            event_id=event_id,
            event_type=event_type,
            month=reserve["month_key"],
            provider=reserve["provider"],
            model=reserve["model"],
            reserved_microdollars=reserved,
            charged_microdollars=charged,
            usage_valid=usage_valid,
            closed_at=instant,
        )

    def reconcile_abandoned(
        self,
        *,
        older_than: timedelta,
        now: datetime | None = None,
    ) -> tuple[Settlement, ...]:
        """Charge and close every active reservation at least ``older_than`` old."""

        if not isinstance(older_than, timedelta) or older_than.total_seconds() < 0:
            raise BudgetConfigurationError("older_than must be a non-negative timedelta")
        instant = self._normalize_now(now)
        cutoff = instant - older_than
        connection = self._connect()
        settlements: list[Settlement] = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT reserve.*
                  FROM ledger_events AS reserve
                  LEFT JOIN ledger_events AS terminal
                    ON terminal.reservation_id = reserve.reservation_id
                   AND terminal.event_type IN ('settle', 'abandon')
                 WHERE reserve.event_type = 'reserve'
                   AND terminal.sequence IS NULL
                   AND reserve.occurred_at_utc <= ?
                 ORDER BY reserve.sequence
                """,
                (cutoff.isoformat(),),
            ).fetchall()
            for reserve in rows:
                event_id = uuid.uuid4().hex
                detail_json = json.dumps(
                    {
                        "reason": "stale_reservation_reconciled",
                        "cutoff_utc": cutoff.isoformat(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                connection.execute(
                    """
                    INSERT INTO ledger_events (
                        event_id, event_type, reservation_id, occurred_at_utc,
                        month_key, provider, model, request_key,
                        amount_microdollars, pricing_version,
                        pricing_effective_from, pricing_effective_until,
                        input_rate_microdollars_per_million,
                        output_rate_microdollars_per_million,
                        cached_input_rate_microdollars_per_million,
                        input_tokens, output_tokens, cached_input_tokens,
                        usage_valid, details_json
                    ) VALUES (?, 'abandon', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              NULL, NULL, NULL, 0, ?)
                    """,
                    (
                        event_id,
                        reserve["reservation_id"],
                        instant.isoformat(),
                        reserve["month_key"],
                        reserve["provider"],
                        reserve["model"],
                        reserve["request_key"],
                        reserve["amount_microdollars"],
                        reserve["pricing_version"],
                        reserve["pricing_effective_from"],
                        reserve["pricing_effective_until"],
                        reserve["input_rate_microdollars_per_million"],
                        reserve["output_rate_microdollars_per_million"],
                        reserve["cached_input_rate_microdollars_per_million"],
                        detail_json,
                    ),
                )
                settlements.append(
                    Settlement(
                        reservation_id=reserve["reservation_id"],
                        event_id=event_id,
                        event_type="abandon",
                        month=reserve["month_key"],
                        provider=reserve["provider"],
                        model=reserve["model"],
                        reserved_microdollars=reserve["amount_microdollars"],
                        charged_microdollars=reserve["amount_microdollars"],
                        usage_valid=False,
                        closed_at=instant,
                    )
                )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return tuple(settlements)

    def status(self, *, now: datetime | None = None) -> BudgetStatus:
        """Return conservative spend, warning state, and per-model call counts."""

        instant = self._normalize_now(now)
        month = self._month_key(instant)
        connection = self._connect()
        try:
            charged, active_reserved = self._spend_parts(connection, month)
            rows = connection.execute(
                """
                SELECT provider, model, COUNT(*) AS used
                  FROM ledger_events
                 WHERE event_type = 'reserve' AND month_key = ?
                 GROUP BY provider, model
                 ORDER BY provider, model
                """,
                (month,),
            ).fetchall()
        finally:
            connection.close()

        counts_by_key = {
            (row["provider"], row["model"]): int(row["used"]) for row in rows
        }
        all_keys = sorted(set(counts_by_key) | set(self.monthly_call_quotas))
        call_counts = tuple(
            CallCount(
                provider=provider,
                model=model,
                used=counts_by_key.get((provider, model), 0),
                quota=self.monthly_call_quotas.get((provider, model)),
            )
            for provider, model in all_keys
        )
        effective = charged + active_reserved
        crossed = tuple(
            threshold
            for threshold in self.warning_thresholds_microdollars
            if effective >= threshold
        )
        if effective >= self.hard_limit_microdollars:
            level: Literal["ok", "warning", "critical", "exhausted"] = "exhausted"
        elif len(crossed) >= 2:
            level = "critical"
        elif crossed:
            level = "warning"
        else:
            level = "ok"
        return BudgetStatus(
            month=month,
            hard_limit_microdollars=self.hard_limit_microdollars,
            charged_microdollars=charged,
            active_reserved_microdollars=active_reserved,
            effective_spend_microdollars=effective,
            remaining_microdollars=max(0, self.hard_limit_microdollars - effective),
            warning_level=level,
            crossed_warning_thresholds_microdollars=crossed,
            call_counts=call_counts,
        )

    def events(self, *, month: str | None = None) -> tuple[LedgerEvent, ...]:
        """Read an ordered audit snapshot without exposing mutation methods."""

        connection = self._connect()
        try:
            if month is None:
                rows = connection.execute(
                    "SELECT * FROM ledger_events ORDER BY sequence"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM ledger_events WHERE month_key = ? ORDER BY sequence",
                    (month,),
                ).fetchall()
        finally:
            connection.close()
        return tuple(
            LedgerEvent(
                sequence=row["sequence"],
                event_id=row["event_id"],
                event_type=row["event_type"],
                reservation_id=row["reservation_id"],
                occurred_at=datetime.fromisoformat(row["occurred_at_utc"]),
                month=row["month_key"],
                provider=row["provider"],
                model=row["model"],
                request_key=row["request_key"],
                amount_microdollars=row["amount_microdollars"],
                pricing_version=row["pricing_version"],
                usage_valid=(
                    bool(row["usage_valid"])
                    if row["usage_valid"] is not None
                    else None
                ),
                details=json.loads(row["details_json"]),
            )
            for row in rows
        )
