from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iou_ai.quarantine import QuarantineError, QuarantineStore


class QuarantineTests(unittest.TestCase):
    def test_put_is_content_addressed_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = QuarantineStore(directory)
            first_digest, first_path = store.put({"b": 2, "a": 1})
            second_digest, second_path = store.put({"a": 1, "b": 2})
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_path, second_path)
            self.assertTrue(Path(first_path).is_file())

    def test_get_rejects_traversal_and_mutated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = QuarantineStore(directory)
            digest, path = store.put({"safe": True})
            self.assertEqual(store.get(digest), {"safe": True})
            with self.assertRaises(QuarantineError):
                store.get("../" + digest)
            path.chmod(0o600)
            path.write_bytes(b"{}")
            with self.assertRaises(QuarantineError):
                store.get(digest)

    def test_iter_verified_ignores_unbound_names_and_limits_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = QuarantineStore(root)
            first, _ = store.put({"item": 1})
            second, _ = store.put({"item": 2})
            (root / "notes.txt").write_text("ignored", encoding="utf-8")
            self.assertEqual(
                {digest for digest, _ in store.iter_verified()},
                {first, second},
            )
            with self.assertRaises(QuarantineError):
                list(store.iter_verified(max_items=1))


if __name__ == "__main__":
    unittest.main()
