"""Safe, read-only intake for the public io-uring archive on kernel.org.

The collector uses public-inbox's documented ``new.atom`` feed and per-message
``<Message-ID>/raw`` endpoint.  Public messages are untrusted input: only a
small deterministic structural projection may be handed to the AI pipeline.

Protocol references (verified 2026-07-16):

* https://lore.kernel.org/io-uring/new.atom
* https://public-inbox.org/meta/_/text/help/
* https://kernel.googlesource.com/pub/scm/infra/public-inbox/
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Callable, Mapping, Protocol, Sequence
import unicodedata
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
import xml.etree.ElementTree as ET


LORE_HOST = "lore.kernel.org"
LORE_ORIGIN = f"https://{LORE_HOST}"
IO_URING_FEED_URL = f"{LORE_ORIGIN}/io-uring/new.atom"
USER_AGENT = (
    "io-uring-ai-control/0.1 "
    "(read-only U-M io_uring research collector; public archive intake)"
)

DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_FEED_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_RAW_MAX_BYTES = 4 * 1024 * 1024
MAX_FEED_ENTRIES = 100
MAX_MESSAGES_PER_RUN = 100
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_SEEN_IDS = 100_000
MAX_BODY_CHARACTERS = 2 * 1024 * 1024
MAX_DIFF_LINES = 50_000
MAX_EVIDENCE_PATHS = 32
MAX_EVIDENCE_HUNKS = 32

ATOM = "{http://www.w3.org/2005/Atom}"
HEX_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
SIMPLE_GIT_DIFF_RE = re.compile(
    r"\Adiff --git a/([A-Za-z0-9_.+\-/]+) b/([A-Za-z0-9_.+\-/]+)\Z"
)


class LkmlError(RuntimeError):
    """Base class for the public archive intake."""


class LkmlUrlError(LkmlError):
    """A URL escaped the strict lore.kernel.org/io-uring allowlist."""


class LkmlFetchError(LkmlError):
    """The single bounded HTTPS request failed."""


class LkmlParseError(LkmlError):
    """Untrusted feed or message content was malformed or inconsistent."""


class LkmlStateError(LkmlError):
    """The local cursor or immutable artifact store failed validation."""


@dataclass(frozen=True, slots=True)
class FetchedResource:
    status_code: int
    final_url: str
    headers: Mapping[str, str]
    body: bytes


class HttpsFetcher(Protocol):
    def get(
        self,
        url: str,
        *,
        accept: str,
        user_agent: str,
        timeout_seconds: float,
        max_bytes: int,
    ) -> FetchedResource: ...


class _AllowlistedRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Follow a small number of redirects only inside the approved archive."""

    def __init__(self, *, max_redirects: int = 3) -> None:
        super().__init__()
        self._max_redirects = max_redirects
        self._redirects = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._redirects += 1
        if self._redirects > self._max_redirects:
            raise LkmlFetchError("too many archive redirects")
        validate_lore_url(newurl, kind="any")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibHttpsFetcher:
    """Stdlib HTTPS client: one attempt, bounded read, no transparent gzip."""

    def get(
        self,
        url: str,
        *,
        accept: str,
        user_agent: str,
        timeout_seconds: float,
        max_bytes: int,
    ) -> FetchedResource:
        validate_lore_url(url, kind="any")
        if timeout_seconds <= 0 or max_bytes <= 0:
            raise ValueError("timeout_seconds and max_bytes must be positive")

        req = urllib_request.Request(
            url,
            headers={
                "Accept": accept,
                "Accept-Encoding": "identity",
                "User-Agent": user_agent,
            },
            method="GET",
        )
        # A fresh opener resets the redirect counter for every logical request.
        opener = urllib_request.build_opener(_AllowlistedRedirectHandler())
        try:
            with opener.open(req, timeout=timeout_seconds) as response:
                final_url = response.geturl()
                validate_lore_url(final_url, kind="any")
                headers = {str(k): str(v) for k, v in response.headers.items()}
                content_length = _header(headers, "content-length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError as exc:
                        raise LkmlFetchError("invalid archive Content-Length") from exc
                    if declared < 0 or declared > max_bytes:
                        raise LkmlFetchError("archive response exceeds byte cap")
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise LkmlFetchError("archive response exceeds byte cap")
                return FetchedResource(
                    status_code=int(response.status),
                    final_url=final_url,
                    headers=headers,
                    body=body,
                )
        except LkmlError:
            raise
        except urllib_error.HTTPError as exc:
            # Do not copy the potentially hostile response body into the error.
            raise LkmlFetchError(f"archive returned HTTP {int(exc.code)}") from None
        except (urllib_error.URLError, TimeoutError, OSError) as exc:
            raise LkmlFetchError("archive HTTPS request failed") from exc


@dataclass(frozen=True, slots=True)
class FeedEntry:
    message_id: str
    message_id_sha256: str
    public_url: str
    updated: str


@dataclass(frozen=True, slots=True)
class ParsedFeed:
    updated: str
    entries: tuple[FeedEntry, ...]


@dataclass(frozen=True, slots=True)
class DiffCounts:
    files: int
    hunks: int
    additions: int
    deletions: int

    def to_dict(self) -> dict[str, int]:
        return {
            "files": self.files,
            "hunks": self.hunks,
            "additions": self.additions,
            "deletions": self.deletions,
        }


@dataclass(frozen=True, slots=True)
class LkmlEvidence:
    schema_version: str
    trust: str
    message_id_sha256: str
    raw_sha256: str
    subject: str
    author_domain: str
    date: str
    public_url: str
    diff_file_paths: tuple[str, ...]
    hunk_headers: tuple[str, ...]
    diff_counts: DiffCounts
    structural_summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "trust": self.trust,
            "message_id_sha256": self.message_id_sha256,
            "raw_sha256": self.raw_sha256,
            "subject": self.subject,
            "author_domain": self.author_domain,
            "date": self.date,
            "public_url": self.public_url,
            "diff_file_paths": list(self.diff_file_paths),
            "hunk_headers": list(self.hunk_headers),
            "diff_counts": self.diff_counts.to_dict(),
            "structural_summary": self.structural_summary,
        }


@dataclass(frozen=True, slots=True)
class StoredLkmlEvidence:
    evidence: LkmlEvidence
    raw_path: Path
    evidence_path: Path
    evidence_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "message_id_sha256": self.evidence.message_id_sha256,
            "raw_sha256": self.evidence.raw_sha256,
            "evidence_sha256": self.evidence_sha256,
            "raw_path": str(self.raw_path),
            "evidence_path": str(self.evidence_path),
        }


@dataclass(frozen=True, slots=True)
class CollectionReport:
    feed_updated: str
    fetched_messages: int
    stored_messages: int
    duplicate_messages: int
    out_of_scope_messages: int
    malformed_messages: int
    artifacts: tuple[StoredLkmlEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_updated": self.feed_updated,
            "fetched_messages": self.fetched_messages,
            "stored_messages": self.stored_messages,
            "duplicate_messages": self.duplicate_messages,
            "out_of_scope_messages": self.out_of_scope_messages,
            "malformed_messages": self.malformed_messages,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


@dataclass(frozen=True, slots=True)
class CollectorConfig:
    state_dir: Path
    feed_url: str = IO_URING_FEED_URL
    user_agent: str = USER_AGENT
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    feed_max_bytes: int = DEFAULT_FEED_MAX_BYTES
    raw_max_bytes: int = DEFAULT_RAW_MAX_BYTES
    max_messages: int = 25

    def __post_init__(self) -> None:
        validate_lore_url(self.feed_url, kind="feed")
        if not self.user_agent.strip():
            raise ValueError("user_agent must not be blank")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.feed_max_bytes <= 0 or self.raw_max_bytes <= 0:
            raise ValueError("byte caps must be positive")
        if not 1 <= self.max_messages <= MAX_MESSAGES_PER_RUN:
            raise ValueError(f"max_messages must be 1..{MAX_MESSAGES_PER_RUN}")


@dataclass(slots=True)
class _Cursor:
    seen_message_id_sha256: set[str] = field(default_factory=set)
    feed_updated: str | None = None
    last_successful_poll: str | None = None


class LkmlStore:
    """Content-addressed immutable artifacts plus an atomic dedupe cursor."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.cursor_path = self.root / "state.json"

    def load_cursor(self) -> _Cursor:
        if not self.cursor_path.exists():
            return _Cursor()
        try:
            if self.cursor_path.stat().st_size > MAX_STATE_BYTES:
                raise LkmlStateError("LKML cursor exceeds byte cap")
            data = json.loads(self.cursor_path.read_text(encoding="utf-8"))
        except LkmlStateError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LkmlStateError("LKML cursor is unreadable") from exc
        if not isinstance(data, dict) or data.get("schema_version") != "lkml-state.v1":
            raise LkmlStateError("LKML cursor schema is invalid")
        seen = data.get("seen_message_id_sha256")
        if not isinstance(seen, list) or len(seen) > MAX_SEEN_IDS:
            raise LkmlStateError("LKML cursor seen-id list is invalid")
        if any(not isinstance(item, str) or not HEX_SHA256_RE.fullmatch(item) for item in seen):
            raise LkmlStateError("LKML cursor contains an invalid digest")
        for name in ("feed_updated", "last_successful_poll"):
            value = data.get(name)
            if value is not None and not isinstance(value, str):
                raise LkmlStateError(f"LKML cursor {name} is invalid")
        return _Cursor(
            seen_message_id_sha256=set(seen),
            feed_updated=data.get("feed_updated"),
            last_successful_poll=data.get("last_successful_poll"),
        )

    def save_cursor(self, cursor: _Cursor) -> None:
        if len(cursor.seen_message_id_sha256) > MAX_SEEN_IDS:
            raise LkmlStateError("LKML cursor capacity reached")
        payload = {
            "schema_version": "lkml-state.v1",
            "feed_url": IO_URING_FEED_URL,
            "feed_updated": cursor.feed_updated,
            "last_successful_poll": cursor.last_successful_poll,
            "seen_message_id_sha256": sorted(cursor.seen_message_id_sha256),
        }
        encoded = (
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_STATE_BYTES:
            raise LkmlStateError("LKML cursor serialization exceeds byte cap")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temp_name = tempfile.mkstemp(prefix=".state-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temp_name, self.cursor_path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def store(self, raw: bytes, evidence: LkmlEvidence) -> StoredLkmlEvidence:
        raw_digest, raw_path = self._store_immutable("raw", ".eml", raw)
        if raw_digest != evidence.raw_sha256:
            raise LkmlStateError("raw artifact digest changed before storage")
        evidence_bytes = json.dumps(
            evidence.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        evidence_digest, evidence_path = self._store_immutable(
            "evidence", ".json", evidence_bytes
        )
        return StoredLkmlEvidence(
            evidence=evidence,
            raw_path=raw_path,
            evidence_path=evidence_path,
            evidence_sha256=evidence_digest,
        )

    def _store_immutable(self, kind: str, suffix: str, content: bytes) -> tuple[str, Path]:
        digest = hashlib.sha256(content).hexdigest()
        directory = self.root / kind / "sha256" / digest[:2]
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = directory / f"{digest}{suffix}"

        fd, temp_name = tempfile.mkstemp(prefix=".artifact-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                # Hard-link publication is atomic and never replaces an
                # existing content-addressed artifact.
                os.link(temp_name, target)
            except FileExistsError:
                if not _file_has_digest(target, digest, len(content)):
                    raise LkmlStateError("existing immutable artifact is corrupt")
        finally:
            try:
                # Windows cannot unlink a read-only hard-link name.  Publish
                # while private/writable, remove the temporary name, and only
                # then make the surviving content-addressed name read-only.
                os.chmod(temp_name, stat.S_IRUSR | stat.S_IWUSR)
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
        os.chmod(target, stat.S_IRUSR)
        return digest, target


class LoreIoUringCollector:
    """Fetch recent public messages and persist only bounded scoped evidence."""

    def __init__(
        self,
        config: CollectorConfig,
        *,
        fetcher: HttpsFetcher | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.fetcher = fetcher or UrllibHttpsFetcher()
        self.store = LkmlStore(config.state_dir)
        self._now = now or (lambda: datetime.now(timezone.utc))

    def run(self) -> CollectionReport:
        cursor = self.store.load_cursor()
        feed_resource = self.fetcher.get(
            self.config.feed_url,
            accept="application/atom+xml, application/xml;q=0.9",
            user_agent=self.config.user_agent,
            timeout_seconds=self.config.timeout_seconds,
            max_bytes=self.config.feed_max_bytes,
        )
        _validate_resource(
            feed_resource,
            kind="feed",
            max_bytes=self.config.feed_max_bytes,
            content_types={"application/atom+xml", "application/xml", "text/xml"},
        )
        feed = parse_atom_feed(feed_resource.body)

        fetched = stored = duplicates = out_of_scope = malformed = 0
        artifacts: list[StoredLkmlEvidence] = []
        considered = 0
        in_run: set[str] = set()
        # Public-inbox emits newest first; process oldest first for a stable
        # cursor and predictable evidence order.
        for entry in reversed(feed.entries):
            digest = entry.message_id_sha256
            if digest in cursor.seen_message_id_sha256 or digest in in_run:
                duplicates += 1
                continue
            if considered >= self.config.max_messages:
                break
            considered += 1
            in_run.add(digest)

            raw_url = raw_url_for_entry(entry.public_url)
            raw_resource = self.fetcher.get(
                raw_url,
                accept="message/rfc822, text/plain;q=0.9",
                user_agent=self.config.user_agent,
                timeout_seconds=self.config.timeout_seconds,
                max_bytes=self.config.raw_max_bytes,
            )
            _validate_resource(
                raw_resource,
                kind="raw",
                max_bytes=self.config.raw_max_bytes,
                content_types={"message/rfc822", "text/plain", "application/mbox"},
            )
            fetched += 1
            try:
                evidence = evidence_from_raw(raw_resource.body, entry)
            except LkmlParseError:
                malformed += 1
                cursor.seen_message_id_sha256.add(digest)
                continue
            if evidence is None:
                out_of_scope += 1
                cursor.seen_message_id_sha256.add(digest)
                continue

            artifacts.append(self.store.store(raw_resource.body, evidence))
            stored += 1
            cursor.seen_message_id_sha256.add(digest)

        cursor.feed_updated = feed.updated
        cursor.last_successful_poll = _format_datetime(self._now())
        self.store.save_cursor(cursor)
        return CollectionReport(
            feed_updated=feed.updated,
            fetched_messages=fetched,
            stored_messages=stored,
            duplicate_messages=duplicates,
            out_of_scope_messages=out_of_scope,
            malformed_messages=malformed,
            artifacts=tuple(artifacts),
        )


def validate_lore_url(url: str, *, kind: str = "any") -> str:
    """Validate and canonicalize an allowed feed, message, or raw URL."""

    if kind not in {"any", "feed", "message", "raw"}:
        raise ValueError("unknown lore URL kind")
    if not isinstance(url, str) or not url or any(ord(ch) < 32 for ch in url):
        raise LkmlUrlError("archive URL is invalid")
    try:
        split = urllib_parse.urlsplit(url)
        port = split.port
    except ValueError as exc:
        raise LkmlUrlError("archive URL authority is invalid") from exc
    if (
        split.scheme != "https"
        or split.hostname != LORE_HOST
        or port not in {None, 443}
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
    ):
        raise LkmlUrlError("archive URL is outside the HTTPS allowlist")
    if BAD_PERCENT_RE.search(split.path) or "\\" in split.path:
        raise LkmlUrlError("archive URL path is invalid")

    if split.path == "/io-uring/new.atom":
        if kind not in {"any", "feed"}:
            raise LkmlUrlError("feed URL used where a message was required")
        return IO_URING_FEED_URL

    if not split.path.startswith("/io-uring/"):
        raise LkmlUrlError("archive URL is outside the io-uring archive")
    is_raw = split.path.endswith("/raw")
    is_message = split.path.endswith("/") and not is_raw
    if not (is_raw or is_message):
        raise LkmlUrlError("archive URL is not a message endpoint")
    if kind == "raw" and not is_raw:
        raise LkmlUrlError("raw message URL required")
    if kind == "message" and not is_message:
        raise LkmlUrlError("public message URL required")
    if kind == "feed":
        raise LkmlUrlError("message URL used where feed was required")

    tail = split.path[len("/io-uring/") :]
    tail = tail[: -len("/raw")] if is_raw else tail[:-1]
    if not tail or tail in {"new.atom", "_"}:
        raise LkmlUrlError("archive message identifier is empty")
    message_id = _decode_url_message_id(tail)
    try:
        normalize_message_id(message_id)
    except LkmlParseError as exc:
        raise LkmlUrlError("archive Message-ID is invalid") from exc
    suffix = "/raw" if is_raw else "/"
    return f"{LORE_ORIGIN}/io-uring/{tail}{suffix}"


def raw_url_for_entry(public_url: str) -> str:
    canonical = validate_lore_url(public_url, kind="message")
    raw_url = f"{canonical}raw"
    return validate_lore_url(raw_url, kind="raw")


def parse_atom_feed(content: bytes) -> ParsedFeed:
    if len(content) > DEFAULT_FEED_MAX_BYTES:
        raise LkmlParseError("Atom feed exceeds parser byte cap")
    # A DTD may be preceded by arbitrarily large whitespace.  Scan the whole
    # already-bounded document before handing it to ElementTree so entity
    # expansion never starts.
    lowered = content.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise LkmlParseError("Atom DTDs and entities are forbidden")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise LkmlParseError("Atom feed is malformed") from exc
    if root.tag != f"{ATOM}feed":
        raise LkmlParseError("Atom root is not a feed")
    updated_element = root.find(f"{ATOM}updated")
    if updated_element is None or not updated_element.text:
        raise LkmlParseError("Atom feed has no updated timestamp")
    updated = _parse_iso_datetime(updated_element.text)

    elements = root.findall(f"{ATOM}entry")
    if len(elements) > MAX_FEED_ENTRIES:
        raise LkmlParseError("Atom feed contains too many entries")
    entries: list[FeedEntry] = []
    for element in elements:
        entry_updated_element = element.find(f"{ATOM}updated")
        if entry_updated_element is None or not entry_updated_element.text:
            raise LkmlParseError("Atom entry has no updated timestamp")
        entry_updated = _parse_iso_datetime(entry_updated_element.text)
        href: str | None = None
        for link in element.findall(f"{ATOM}link"):
            rel = link.attrib.get("rel", "alternate")
            candidate = link.attrib.get("href")
            if rel == "alternate" and candidate:
                href = candidate
                break
        if href is None:
            raise LkmlParseError("Atom entry has no public message link")
        public_url = validate_lore_url(href, kind="message")
        tail = urllib_parse.urlsplit(public_url).path[len("/io-uring/") : -1]
        message_id = normalize_message_id(_decode_url_message_id(tail))
        entries.append(
            FeedEntry(
                message_id=message_id,
                message_id_sha256=_sha256_text(message_id),
                public_url=public_url,
                updated=entry_updated,
            )
        )
    return ParsedFeed(updated=updated, entries=tuple(entries))


def evidence_from_raw(raw: bytes, entry: FeedEntry) -> LkmlEvidence | None:
    """Parse one RFC email and return a bounded in-scope projection.

    ``None`` means a patch had diffs but none under ``io_uring/`` or
    ``fs/io_uring``.  The caller may mark it seen without storing the raw mail.
    """

    if not raw or len(raw) > DEFAULT_RAW_MAX_BYTES:
        raise LkmlParseError("raw message exceeds parser byte cap")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # email defects vary by Python release
        raise LkmlParseError("raw message cannot be parsed") from exc

    actual_message_id = normalize_message_id(str(message.get("Message-ID", "")))
    if actual_message_id != entry.message_id:
        raise LkmlParseError("raw Message-ID does not match the Atom link")
    subject = sanitize_text(str(message.get("Subject", "(no subject)")), 240)
    if not subject:
        subject = "(no subject)"
    author_domain = _author_domain(str(message.get("From", "")))
    date_header = str(message.get("Date", ""))
    if date_header:
        try:
            parsed_date = parsedate_to_datetime(date_header)
            date = _format_datetime(parsed_date)
        except (TypeError, ValueError, OverflowError) as exc:
            raise LkmlParseError("raw message Date header is invalid") from exc
    else:
        date = entry.updated

    body = _plain_text_body(message)
    diff = _parse_scoped_diff(body)
    if diff.has_any_diff and not diff.paths:
        return None
    kind = "in-scope-patch" if diff.paths else "io-uring-discussion"
    summary = sanitize_text(
        (
            f"kind={kind}; files={diff.counts.files}; hunks={diff.counts.hunks}; "
            f"additions={diff.counts.additions}; deletions={diff.counts.deletions}; "
            f"scan_truncated={'yes' if diff.truncated else 'no'}"
        ),
        320,
    )
    return LkmlEvidence(
        schema_version="lkml-evidence.v1",
        trust="untrusted_public_input",
        message_id_sha256=entry.message_id_sha256,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        subject=subject,
        author_domain=author_domain,
        date=date,
        public_url=entry.public_url,
        diff_file_paths=diff.paths,
        hunk_headers=diff.hunks,
        diff_counts=diff.counts,
        structural_summary=summary,
    )


@dataclass(frozen=True, slots=True)
class _ParsedDiff:
    has_any_diff: bool
    paths: tuple[str, ...]
    hunks: tuple[str, ...]
    counts: DiffCounts
    truncated: bool


def _parse_scoped_diff(body: str) -> _ParsedDiff:
    paths_seen: set[str] = set()
    displayed_paths: list[str] = []
    displayed_hunks: list[str] = []
    has_any_diff = False
    current_scoped = False
    in_hunk = False
    hunk_count = additions = deletions = 0
    truncated = False

    lines = body.splitlines()
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES]
        truncated = True
    for line in lines:
        if line.startswith("diff --git "):
            has_any_diff = True
            in_hunk = False
            match = SIMPLE_GIT_DIFF_RE.fullmatch(line)
            current_scoped = False
            if match is not None:
                left, right = match.groups()
                if left == right and is_scoped_kernel_path(right):
                    current_scoped = True
                    if right not in paths_seen:
                        paths_seen.add(right)
                        if len(displayed_paths) < MAX_EVIDENCE_PATHS:
                            displayed_paths.append(right)
            continue
        if line.startswith("@@"):
            in_hunk = current_scoped
            if current_scoped:
                hunk_count += 1
                if len(displayed_hunks) < MAX_EVIDENCE_HUNKS:
                    displayed_hunks.append(sanitize_text(line, 200))
            continue
        if not (current_scoped and in_hunk):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1

    return _ParsedDiff(
        has_any_diff=has_any_diff,
        paths=tuple(displayed_paths),
        hunks=tuple(displayed_hunks),
        counts=DiffCounts(
            files=len(paths_seen),
            hunks=hunk_count,
            additions=additions,
            deletions=deletions,
        ),
        truncated=truncated,
    )


def is_scoped_kernel_path(path: str) -> bool:
    if not path or len(path) > 240 or path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    return (
        path.startswith("io_uring/")
        or path.startswith("fs/io_uring/")
        or path == "fs/io_uring.c"
    )


def normalize_message_id(value: str) -> str:
    value = value.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    if not value or len(value) > 998:
        raise LkmlParseError("Message-ID length is invalid")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in value) or "@" not in value:
        raise LkmlParseError("Message-ID contains forbidden characters")
    # public-inbox permits escaped slashes inside Message-IDs.  Preserve those,
    # but reject dot path components so percent-decoding cannot escape the
    # archive route on a differently configured reverse proxy.
    if any(component in {"", ".", ".."} for component in value.split("/")):
        raise LkmlParseError("Message-ID contains a forbidden path component")
    return value


def sanitize_text(value: str, limit: int) -> str:
    if limit <= 0:
        raise ValueError("limit must be positive")
    normalized = unicodedata.normalize("NFKC", value)
    without_controls = "".join(
        " " if unicodedata.category(ch).startswith("C") else ch for ch in normalized
    )
    collapsed = " ".join(without_controls.split())
    return collapsed[:limit]


def _plain_text_body(message) -> str:
    parts = list(message.walk()) if message.is_multipart() else [message]
    text_parts: list[str] = []
    characters = 0
    for part in parts:
        if part.is_multipart() or part.get_content_type() not in {
            "text/plain",
            "text/x-patch",
            "text/x-diff",
        }:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            undecoded = part.get_payload()
            if not isinstance(undecoded, str):
                continue
            text = undecoded
        else:
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError as exc:
                raise LkmlParseError("raw message uses an unknown charset") from exc
        remaining = MAX_BODY_CHARACTERS - characters
        if remaining <= 0:
            break
        text_parts.append(text[:remaining])
        characters += min(len(text), remaining)
    return "\n".join(text_parts)


def _author_domain(value: str) -> str:
    _, address = parseaddr(value)
    if "@" not in address:
        raise LkmlParseError("raw message From header has no domain")
    domain = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise LkmlParseError("raw message author domain is invalid") from exc
    if len(ascii_domain) > 253 or not ascii_domain:
        raise LkmlParseError("raw message author domain is invalid")
    labels = ascii_domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise LkmlParseError("raw message author domain is invalid")
    return ascii_domain


def _validate_resource(
    resource: FetchedResource,
    *,
    kind: str,
    max_bytes: int,
    content_types: set[str],
) -> None:
    validate_lore_url(resource.final_url, kind=kind)
    if resource.status_code != 200:
        raise LkmlFetchError(f"archive returned HTTP {resource.status_code}")
    if len(resource.body) > max_bytes:
        raise LkmlFetchError("archive response exceeds byte cap")
    encoding = _header(resource.headers, "content-encoding")
    if encoding is not None and encoding.lower().strip() not in {"", "identity"}:
        raise LkmlFetchError("compressed archive responses are forbidden")
    content_type = (_header(resource.headers, "content-type") or "").split(";", 1)[0]
    if content_type.strip().lower() not in content_types:
        raise LkmlFetchError("archive returned an unexpected content type")


def _decode_url_message_id(encoded: str) -> str:
    try:
        return urllib_parse.unquote_to_bytes(encoded).decode("ascii")
    except (UnicodeDecodeError, ValueError) as exc:
        raise LkmlUrlError("archive Message-ID encoding is invalid") from exc


def _parse_iso_datetime(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise LkmlParseError("Atom timestamp is invalid") from exc
    return _format_datetime(parsed)


def _format_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        raise LkmlParseError("timestamp must include a timezone")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _header(headers: Mapping[str, str], name: str) -> str | None:
    folded = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == folded:
            return str(value)
    return None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _file_has_digest(path: Path, digest: str, expected_size: int) -> bool:
    try:
        if path.stat().st_size != expected_size:
            return False
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(64 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest() == digest
    except OSError as exc:
        raise LkmlStateError("immutable artifact cannot be verified") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("/var/lib/iou-ai-lkml"),
        help="private directory for the cursor and content-addressed artifacts",
    )
    parser.add_argument("--max-messages", type=int, default=25)
    args = parser.parse_args(argv)
    report = LoreIoUringCollector(
        CollectorConfig(state_dir=args.state_dir, max_messages=args.max_messages)
    ).run()
    print(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
