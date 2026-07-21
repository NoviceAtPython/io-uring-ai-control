from pathlib import Path
import sys
import tempfile
import unittest
from dataclasses import replace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iou_ai.config import ConfigError, load_config
from iou_ai.pipeline import _request_key



class ConfigTests(unittest.TestCase):
    def test_mock_config_is_pinned_and_capped(self) -> None:
        config = load_config(ROOT / "examples" / "config.mock.toml")
        self.assertEqual(config.runtime.mode, "mock")
        self.assertEqual(config.planner.model, "gpt-5.6-sol")
        self.assertEqual(config.reviewer.model, "claude-sonnet-5")
        self.assertEqual(str(config.budget.hard_limit_usd), "7.50")
        self.assertTrue(config.auditor.enabled)
        self.assertFalse(config.events.enabled)

    def test_deployed_event_projector_is_enabled_but_inert(self) -> None:
        config = load_config(ROOT / "deploy" / "config.shadow.toml")
        self.assertTrue(config.events.enabled)
        self.assertEqual(config.events.decision_ttl_minutes, 1440)
        self.assertTrue(
            config.events.outbox_dir.as_posix().endswith("/var/lib/iou-ai/events")
        )
        self.assertEqual(config.planner.reasoning_effort, "medium")
        self.assertEqual(config.planner.request_timeout_seconds, 600)

    def test_generation_controls_are_part_of_request_identity(self) -> None:
        config = load_config(ROOT / "deploy" / "config.shadow.toml")
        baseline = _request_key(
            "planner", config.planner, "system", "input", {"type": "object"}
        )
        tuned = _request_key(
            "planner",
            replace(config.planner, request_timeout_seconds=660),
            "system",
            "input",
            {"type": "object"},
        )
        self.assertNotEqual(baseline, tuned)

    def test_request_timeout_is_bounded(self) -> None:
        source = (ROOT / "examples" / "config.mock.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text(
                source.replace('reasoning_effort = "high"', 'request_timeout_seconds = 30'),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_live_mode_is_impossible(self) -> None:
        source = (ROOT / "examples" / "config.mock.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text(source.replace('mode = "mock"', 'mode = "live"'), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
