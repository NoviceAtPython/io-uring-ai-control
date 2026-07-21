from __future__ import annotations

import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from iou_ai.budget import (  # noqa: E402
    BudgetConfigurationError,
    BudgetExceeded,
    BudgetLedger,
    DuplicateRequest,
    KillSwitchActive,
    PricingNotEffective,
    PricingPolicy,
    QuotaExceeded,
    ReservationAlreadyClosed,
    UnknownQuota,
    microdollars_to_usd,
    usd_to_microdollars,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def pricing(
    *,
    provider: str = "openai",
    model: str = "gpt-test",
    start: date = date(2026, 1, 1),
    until: date | None = date(2027, 1, 1),
) -> PricingPolicy:
    return PricingPolicy(
        provider=provider,
        model=model,
        version="2026-07-test",
        effective_from=start,
        effective_until=until,
        input_rate_microdollars_per_million=2_000_000,
        output_rate_microdollars_per_million=10_000_000,
        cached_input_rate_microdollars_per_million=500_000,
    )


class BudgetLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "budget.sqlite3"
        self.kill_switch = self.root / "STOP_AI"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def ledger(
        self,
        *,
        hard_limit: int = 1_000,
        quota: int = 10,
        provider: str = "openai",
        model: str = "gpt-test",
        warnings: tuple[int, ...] = (500, 900),
    ) -> BudgetLedger:
        return BudgetLedger(
            self.db_path,
            hard_limit_microdollars=hard_limit,
            monthly_call_quotas={(provider, model): quota},
            warning_thresholds_microdollars=warnings,
            kill_switch_path=self.kill_switch,
        )

    def reserve(
        self,
        ledger: BudgetLedger,
        request_key: str,
        amount: int,
        *,
        at: datetime = NOW,
        policy: PricingPolicy | None = None,
    ):
        return ledger.reserve(
            provider="openai",
            model="gpt-test",
            request_key=request_key,
            worst_case_microdollars=amount,
            pricing_policy=policy or pricing(),
            now=at,
        )

    def test_decimal_safe_conversion_and_pricing_quote(self) -> None:
        self.assertEqual(usd_to_microdollars("7.50"), 7_500_000)
        self.assertEqual(usd_to_microdollars(Decimal("7.5000001")), 7_500_001)
        self.assertEqual(microdollars_to_usd(7_500_000), Decimal("7.5"))
        with self.assertRaises(BudgetConfigurationError):
            usd_to_microdollars(7.5)  # type: ignore[arg-type]

        quote = pricing().quote(
            input_tokens=1_500_000,
            cached_input_tokens=500_000,
            output_tokens=100_000,
        )
        self.assertEqual(quote, 3_250_000)

    def test_active_reservations_count_toward_hard_cap_and_warnings(self) -> None:
        ledger = self.ledger(hard_limit=100, warnings=(50, 80))
        first = self.reserve(ledger, "first", 60)
        self.assertEqual(first.reserved_microdollars, 60)
        status = ledger.status(now=NOW)
        self.assertEqual(status.active_reserved_microdollars, 60)
        self.assertEqual(status.effective_spend_microdollars, 60)
        self.assertEqual(status.warning_level, "warning")

        with self.assertRaises(BudgetExceeded):
            self.reserve(ledger, "too-large", 41)
        self.reserve(ledger, "exactly-fills", 40)
        status = ledger.status(now=NOW)
        self.assertEqual(status.effective_spend_microdollars, 100)
        self.assertEqual(status.remaining_microdollars, 0)
        self.assertEqual(status.warning_level, "exhausted")

    def test_daily_limit_caps_spend_per_utc_day_and_resets_next_day(self) -> None:
        ledger = BudgetLedger(
            self.db_path,
            hard_limit_microdollars=1_000,
            monthly_call_quotas={("openai", "gpt-test"): 100},
            warning_thresholds_microdollars=(500, 900),
            kill_switch_path=self.kill_switch,
            daily_limit_microdollars=150,
        )
        self.reserve(ledger, "d1-a", 100, at=NOW)
        with self.assertRaises(BudgetExceeded):
            self.reserve(ledger, "d1-over", 60, at=NOW)  # 100 + 60 > 150 daily
        self.reserve(ledger, "d1-fill", 50, at=NOW)  # 100 + 50 == 150 daily
        # A fresh UTC day resets the daily window; the monthly cap still accrues.
        next_day = NOW + timedelta(days=1)
        self.reserve(ledger, "d2-a", 120, at=next_day)
        self.assertEqual(
            ledger.status(now=next_day).effective_spend_microdollars, 270
        )

    def test_valid_provider_usage_settles_to_calculated_cost(self) -> None:
        ledger = self.ledger(hard_limit=2_000, warnings=(1_000, 1_500))
        reservation = self.reserve(ledger, "valid-usage", 1_000)
        settlement = ledger.settle(
            reservation.reservation_id,
            input_tokens=100,
            output_tokens=10,
            cached_input_tokens=0,
            now=NOW + timedelta(minutes=1),
        )
        # ceil(100 * $2/M) + ceil(10 * $10/M) = 200 + 100 microdollars.
        self.assertEqual(settlement.charged_microdollars, 300)
        self.assertTrue(settlement.usage_valid)
        status = ledger.status(now=NOW)
        self.assertEqual(status.charged_microdollars, 300)
        self.assertEqual(status.active_reserved_microdollars, 0)

    def test_missing_or_invalid_usage_charges_full_reservation(self) -> None:
        ledger = self.ledger(hard_limit=1_000, warnings=(500, 900))
        missing = self.reserve(ledger, "missing", 200)
        invalid = self.reserve(ledger, "invalid", 250)

        missing_result = ledger.settle(missing.reservation_id, now=NOW)
        invalid_result = ledger.settle(
            invalid.reservation_id,
            input_tokens=10,
            output_tokens=-1,
            cached_input_tokens=0,
            now=NOW,
        )
        self.assertFalse(missing_result.usage_valid)
        self.assertEqual(missing_result.charged_microdollars, 200)
        self.assertFalse(invalid_result.usage_valid)
        self.assertEqual(invalid_result.charged_microdollars, 250)
        self.assertEqual(ledger.status(now=NOW).charged_microdollars, 450)

    def test_call_quota_counts_every_reservation_even_after_settlement(self) -> None:
        ledger = self.ledger(quota=1)
        reservation = self.reserve(ledger, "only-call", 100)
        ledger.settle(
            reservation.reservation_id,
            input_tokens=0,
            output_tokens=0,
            cached_input_tokens=0,
            now=NOW,
        )
        with self.assertRaises(QuotaExceeded):
            self.reserve(ledger, "second-call", 100)
        self.assertEqual(ledger.status(now=NOW).call_counts[0].used, 1)

    def test_unknown_model_quota_fails_closed(self) -> None:
        ledger = BudgetLedger(
            self.db_path,
            hard_limit_microdollars=1_000,
            monthly_call_quotas={},
            warning_thresholds_microdollars=(),
            kill_switch_path=self.kill_switch,
        )
        with self.assertRaises(UnknownQuota):
            self.reserve(ledger, "no-quota", 10)

    def test_duplicate_request_key_is_rejected_without_extra_charge(self) -> None:
        ledger = self.ledger()
        self.reserve(ledger, "same-digest", 100)
        with self.assertRaises(DuplicateRequest):
            self.reserve(ledger, "same-digest", 100)
        self.assertEqual(ledger.status(now=NOW).effective_spend_microdollars, 100)
        self.assertEqual(len(ledger.events()), 1)

    def test_kill_switch_blocks_reservations_but_allows_settlement(self) -> None:
        ledger = self.ledger()
        reservation = self.reserve(ledger, "before-stop", 100)
        self.kill_switch.write_text("operator stop\n", encoding="utf-8")
        with self.assertRaises(KillSwitchActive):
            self.reserve(ledger, "after-stop", 100)

        settlement = ledger.settle(
            reservation.reservation_id,
            input_tokens=1,
            output_tokens=1,
            now=NOW,
        )
        self.assertTrue(settlement.usage_valid)

    def test_abandon_and_stale_reconciliation_charge_full_reserve(self) -> None:
        ledger = self.ledger()
        explicit = self.reserve(ledger, "explicit", 120, at=NOW)
        stale = self.reserve(ledger, "stale", 130, at=NOW)

        abandoned = ledger.abandon(
            explicit.reservation_id,
            reason="transport outcome unknown",
            now=NOW + timedelta(minutes=5),
        )
        self.assertEqual(abandoned.event_type, "abandon")
        self.assertEqual(abandoned.charged_microdollars, 120)

        reconciled = ledger.reconcile_abandoned(
            older_than=timedelta(hours=1), now=NOW + timedelta(hours=2)
        )
        self.assertEqual(len(reconciled), 1)
        self.assertEqual(reconciled[0].reservation_id, stale.reservation_id)
        self.assertEqual(reconciled[0].charged_microdollars, 130)
        status = ledger.status(now=NOW)
        self.assertEqual(status.charged_microdollars, 250)
        self.assertEqual(status.active_reserved_microdollars, 0)

    def test_reservation_cannot_be_closed_twice(self) -> None:
        ledger = self.ledger()
        reservation = self.reserve(ledger, "close-once", 100)
        ledger.abandon(reservation.reservation_id, reason="test", now=NOW)
        with self.assertRaises(ReservationAlreadyClosed):
            ledger.settle(
                reservation.reservation_id,
                input_tokens=0,
                output_tokens=0,
                now=NOW,
            )

    def test_pricing_policy_must_be_effective(self) -> None:
        ledger = self.ledger()
        expired = pricing(start=date(2025, 1, 1), until=date(2026, 1, 1))
        with self.assertRaises(PricingNotEffective):
            self.reserve(ledger, "expired-price", 100, policy=expired)
        self.assertEqual(len(ledger.events()), 0)

    def test_settlement_stays_in_original_utc_calendar_month(self) -> None:
        ledger = self.ledger(hard_limit=1_000, warnings=(500, 900))
        july = datetime(2026, 7, 31, 23, 59, tzinfo=timezone.utc)
        august = datetime(2026, 8, 1, 0, 1, tzinfo=timezone.utc)
        reservation = self.reserve(ledger, "month-boundary", 800, at=july)
        ledger.settle(
            reservation.reservation_id,
            input_tokens=100,
            output_tokens=10,
            now=august,
        )
        self.assertEqual(ledger.status(now=july).charged_microdollars, 300)
        self.assertEqual(ledger.status(now=august).effective_spend_microdollars, 0)

    def test_sqlite_table_rejects_update_and_delete(self) -> None:
        ledger = self.ledger()
        self.reserve(ledger, "immutable", 100)
        connection = sqlite3.connect(self.db_path)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "UPDATE ledger_events SET amount_microdollars = 0"
                )
            connection.rollback()
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("DELETE FROM ledger_events")
            connection.rollback()
        finally:
            connection.close()
        self.assertEqual(len(ledger.events()), 1)

    def test_begin_immediate_serializes_competing_reservations(self) -> None:
        # Two independently configured ledger instances represent two processes.
        first_ledger = self.ledger(hard_limit=100, warnings=(70, 90))
        second_ledger = self.ledger(hard_limit=100, warnings=(70, 90))
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        outcomes: list[str] = []

        def attempt(ledger: BudgetLedger, key: str) -> None:
            barrier.wait()
            try:
                self.reserve(ledger, key, 60)
            except BudgetExceeded:
                outcome = "rejected"
            else:
                outcome = "reserved"
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=attempt, args=(first_ledger, "racer-a")),
            threading.Thread(target=attempt, args=(second_ledger, "racer-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())

        self.assertCountEqual(outcomes, ["reserved", "rejected"])
        status = first_ledger.status(now=NOW)
        self.assertEqual(status.effective_spend_microdollars, 60)
        self.assertEqual(len(first_ledger.events()), 1)


if __name__ == "__main__":
    unittest.main()
