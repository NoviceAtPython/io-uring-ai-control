from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from typing import Any, Mapping


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iou_ai.lkml import (  # noqa: E402
    IO_URING_FEED_URL,
    CollectorConfig,
    FetchedResource,
    LkmlFetchError,
    LkmlParseError,
    LkmlUrlError,
    LoreIoUringCollector,
    evidence_from_raw,
    is_scoped_kernel_path,
    parse_atom_feed,
    raw_url_for_entry,
    validate_lore_url,
)


MESSAGE_ID = "20260716080000.1234-1-researcher@example.com"
PUBLIC_URL = f"https://lore.kernel.org/io-uring/{MESSAGE_ID}/"
RAW_URL = f"{PUBLIC_URL}raw"


def atom_feed(
    urls: list[str], *, updated: str = "2026-07-16T08:05:00Z"
) -> bytes:
    entries = "".join(
        f"""
        <entry>
          <title>[PATCH] io_uring test</title>
          <updated>2026-07-16T08:00:00Z</updated>
          <link rel="alternate" href="{url}" />
          <id>urn:uuid:{index}</id>
        </entry>
        """
        for index, url in enumerate(urls)
    )
    return (
        f"""<?xml version="1.0" encoding="utf-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <title>io-uring archive</title>
          <updated>{updated}</updated>
          {entries}
        </feed>"""
    ).encode("utf-8")


def raw_message(
    *,
    message_id: str = MESSAGE_ID,
    path: str = "io_uring/cancel.c",
    date: str = "Thu, 16 Jul 2026 08:00:00 +0000",
) -> bytes:
    return (
        "From mboxrd@z Thu Jan  1 00:00:00 1970\n"
        "From: Alice Example <alice@EXAMPLE.com>\n"
        "To: io-uring@vger.kernel.org\n"
        "Subject: [PATCH] io_uring\x01 cancellation hardening\n"
        f"Date: {date}\n"
        f"Message-ID: <{message_id}>\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: 8bit\n"
        "\n"
        "Deterministic patch prose that must not enter structural_summary.\n"
        "---\n"
        f"diff --git a/{path} b/{path}\n"
        "index 1111111..2222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -10,2 +10,3 @@ static int cancel_one(struct req *req)\n"
        "-old_line();\n"
        "+new_line();\n"
        "+check_result();\n"
    ).encode("utf-8")


class FakeFetcher:
    def __init__(self, responses: Mapping[str, FetchedResource | Exception]) -> None:
        self.responses = dict(responses)
        self.calls: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        accept: str,
        user_agent: str,
        timeout_seconds: float,
        max_bytes: int,
    ) -> FetchedResource:
        self.calls.append(
            {
                "url": url,
                "accept": accept,
                "user_agent": user_agent,
                "timeout_seconds": timeout_seconds,
                "max_bytes": max_bytes,
            }
        )
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        return result


def feed_resource(
    body: bytes,
    *,
    final_url: str = IO_URING_FEED_URL,
) -> FetchedResource:
    return FetchedResource(
        status_code=200,
        final_url=final_url,
        headers={"Content-Type": "application/atom+xml"},
        body=body,
    )


def message_resource(
    body: bytes,
    *,
    final_url: str = RAW_URL,
) -> FetchedResource:
    return FetchedResource(
        status_code=200,
        final_url=final_url,
        headers={"Content-Type": "text/plain; charset=us-ascii"},
        body=body,
    )


class UrlAndFeedTests(unittest.TestCase):
    def test_only_exact_https_lore_io_uring_endpoints_are_allowed(self) -> None:
        self.assertEqual(validate_lore_url(IO_URING_FEED_URL, kind="feed"), IO_URING_FEED_URL)
        self.assertEqual(validate_lore_url(PUBLIC_URL, kind="message"), PUBLIC_URL)
        self.assertEqual(validate_lore_url(RAW_URL, kind="raw"), RAW_URL)
        self.assertEqual(raw_url_for_entry(PUBLIC_URL), RAW_URL)

        bad_urls = [
            "http://lore.kernel.org/io-uring/new.atom",
            "https://evil.example/io-uring/new.atom",
            "https://lore.kernel.org/all/example@example.com/",
            "https://user@lore.kernel.org/io-uring/example@example.com/",
            "https://lore.kernel.org/io-uring/new.atom?query=1",
            "https://lore.kernel.org/io-uring/example@example.com/#fragment",
            "https://lore.kernel.org/io-uring/%2e%2e%2Fall%2Fexample@example.com/",
        ]
        for url in bad_urls:
            with self.subTest(url=url), self.assertRaises(LkmlUrlError):
                validate_lore_url(url)

    def test_malformed_and_entity_bearing_xml_are_rejected(self) -> None:
        with self.assertRaises(LkmlParseError):
            parse_atom_feed(b"<feed>")
        with self.assertRaises(LkmlParseError):
            parse_atom_feed(
                b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x "boom">]><feed />'
            )

    def test_off_domain_entry_link_is_rejected_before_message_fetch(self) -> None:
        with self.assertRaises(LkmlUrlError):
            parse_atom_feed(atom_feed(["https://evil.example/io-uring/a@b/"]))


class EvidenceTests(unittest.TestCase):
    def test_projection_contains_only_bounded_structural_evidence(self) -> None:
        entry = parse_atom_feed(atom_feed([PUBLIC_URL])).entries[0]
        raw = raw_message()

        evidence = evidence_from_raw(raw, entry)

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.trust, "untrusted_public_input")
        self.assertEqual(evidence.author_domain, "example.com")
        self.assertNotIn("\x01", evidence.subject)
        self.assertEqual(evidence.diff_file_paths, ("io_uring/cancel.c",))
        self.assertEqual(
            evidence.hunk_headers,
            ("@@ -10,2 +10,3 @@ static int cancel_one(struct req *req)",),
        )
        self.assertEqual(evidence.diff_counts.files, 1)
        self.assertEqual(evidence.diff_counts.hunks, 1)
        self.assertEqual(evidence.diff_counts.additions, 2)
        self.assertEqual(evidence.diff_counts.deletions, 1)
        self.assertNotIn("Deterministic patch prose", evidence.structural_summary)
        serialized = json.dumps(evidence.to_dict())
        self.assertNotIn("Alice Example", serialized)
        self.assertNotIn("alice@", serialized)
        self.assertEqual(evidence.raw_sha256, hashlib.sha256(raw).hexdigest())

    def test_unscoped_patch_and_traversal_path_are_excluded(self) -> None:
        entry = parse_atom_feed(atom_feed([PUBLIC_URL])).entries[0]
        self.assertIsNone(evidence_from_raw(raw_message(path="test/cancel.c"), entry))
        self.assertFalse(is_scoped_kernel_path("io_uring/../secret"))
        self.assertFalse(is_scoped_kernel_path("include/uapi/linux/io_uring.h"))
        self.assertTrue(is_scoped_kernel_path("fs/io_uring/cancel.c"))
        self.assertTrue(is_scoped_kernel_path("fs/io_uring.c"))

    def test_message_id_mismatch_and_bad_date_are_rejected(self) -> None:
        entry = parse_atom_feed(atom_feed([PUBLIC_URL])).entries[0]
        with self.assertRaises(LkmlParseError):
            evidence_from_raw(raw_message(message_id="different@example.com"), entry)
        with self.assertRaises(LkmlParseError):
            evidence_from_raw(raw_message(date="definitely not a date"), entry)


class CollectorTests(unittest.TestCase):
    def test_stores_immutable_content_addressed_artifacts_and_deduplicates(self) -> None:
        feed = atom_feed([PUBLIC_URL, PUBLIC_URL])
        raw = raw_message()
        fetcher = FakeFetcher(
            {
                IO_URING_FEED_URL: feed_resource(feed),
                RAW_URL: message_resource(raw),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            collector = LoreIoUringCollector(
                CollectorConfig(state_dir=Path(directory)),
                fetcher=fetcher,
                now=lambda: datetime(2026, 7, 16, 9, 0, tzinfo=timezone.utc),
            )

            first = collector.run()

            self.assertEqual(first.fetched_messages, 1)
            self.assertEqual(first.stored_messages, 1)
            self.assertEqual(first.duplicate_messages, 1)
            artifact = first.artifacts[0]
            self.assertTrue(artifact.raw_path.is_file())
            self.assertTrue(artifact.evidence_path.is_file())
            self.assertIn(
                f"raw{Path('/')}sha256{Path('/')}".replace("/", str(Path('/'))),
                str(artifact.raw_path).replace("\\", str(Path('/'))),
            )
            self.assertEqual(artifact.raw_path.read_bytes(), raw)
            state = json.loads((Path(directory) / "state.json").read_text("utf-8"))
            self.assertEqual(state["schema_version"], "lkml-state.v1")
            self.assertEqual(len(state["seen_message_id_sha256"]), 1)

            second = collector.run()

            self.assertEqual(second.fetched_messages, 0)
            self.assertEqual(second.stored_messages, 0)
            self.assertEqual(second.duplicate_messages, 2)
            raw_calls = [call for call in fetcher.calls if call["url"] == RAW_URL]
            self.assertEqual(len(raw_calls), 1)
            self.assertTrue(all("io-uring-ai-control/" in c["user_agent"] for c in fetcher.calls))

    def test_oversized_mock_response_is_rejected_even_if_fetcher_returns_it(self) -> None:
        oversized = atom_feed([PUBLIC_URL])
        fetcher = FakeFetcher(
            {IO_URING_FEED_URL: feed_resource(oversized)}
        )
        with tempfile.TemporaryDirectory() as directory:
            collector = LoreIoUringCollector(
                CollectorConfig(state_dir=Path(directory), feed_max_bytes=16),
                fetcher=fetcher,
            )
            with self.assertRaises(LkmlFetchError):
                collector.run()
        self.assertEqual(len(fetcher.calls), 1)

    def test_off_domain_redirect_target_is_rejected(self) -> None:
        fetcher = FakeFetcher(
            {
                IO_URING_FEED_URL: feed_resource(
                    atom_feed([PUBLIC_URL]),
                    final_url="https://evil.example/io-uring/new.atom",
                )
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(LkmlUrlError):
                LoreIoUringCollector(
                    CollectorConfig(state_dir=Path(directory)), fetcher=fetcher
                ).run()
        self.assertEqual(len(fetcher.calls), 1)

    def test_malformed_raw_message_is_quarantined_by_hash_and_not_retried(self) -> None:
        malformed_raw = raw_message(message_id="different@example.com")
        fetcher = FakeFetcher(
            {
                IO_URING_FEED_URL: feed_resource(atom_feed([PUBLIC_URL])),
                RAW_URL: message_resource(malformed_raw),
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            collector = LoreIoUringCollector(
                CollectorConfig(state_dir=Path(directory)), fetcher=fetcher
            )
            first = collector.run()
            second = collector.run()

            self.assertEqual(first.malformed_messages, 1)
            self.assertEqual(first.stored_messages, 0)
            self.assertEqual(second.duplicate_messages, 1)
            self.assertEqual(
                len([call for call in fetcher.calls if call["url"] == RAW_URL]), 1
            )

    def test_network_failure_has_no_automatic_retry(self) -> None:
        fetcher = FakeFetcher(
            {IO_URING_FEED_URL: LkmlFetchError("simulated network failure")}
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(LkmlFetchError):
                LoreIoUringCollector(
                    CollectorConfig(state_dir=Path(directory)), fetcher=fetcher
                ).run()
        self.assertEqual(len(fetcher.calls), 1)


if __name__ == "__main__":
    unittest.main()
