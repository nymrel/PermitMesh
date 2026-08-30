from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / ".github" / "nymrel-hourly" / "nymrel_patch_guard.py"


def load_guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location("nymrel_patch_guard", GUARD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load patch guard")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PatchGuardPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guard = load_guard()

    def test_dot_prefixed_protected_paths_remain_visible(self) -> None:
        workflow = self.guard.normalize_repo_path(".github/workflows/ci.yml")
        environment = self.guard.normalize_repo_path(".env")

        self.assertEqual(workflow, ".github/workflows/ci.yml")
        self.assertTrue(workflow.lower().startswith(self.guard.FORBIDDEN_PREFIXES))
        self.assertEqual(Path(environment).name.lower(), ".env")
        self.assertIn(Path(environment).name.lower(), self.guard.FORBIDDEN_BASENAMES)

    def test_agent_instruction_surfaces_are_protected(self) -> None:
        for path in ("AGENTS.md", "nested/AGENT.md", ".agent/lease.json"):
            with self.subTest(path=path):
                normalized = self.guard.normalize_repo_path(path)
                lowered = normalized.lower()
                protected = lowered.startswith(self.guard.FORBIDDEN_PREFIXES) or (
                    Path(lowered).name in self.guard.FORBIDDEN_BASENAMES
                )
                self.assertTrue(protected)

    def test_ambiguous_or_receipt_injecting_paths_are_rejected(self) -> None:
        for path in (
            "../outside.txt",
            "docs//note.md",
            "/absolute.txt",
            "C:/absolute.txt",
            "docs/line\nbreak.md",
            "docs/`receipt`.md",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.guard.normalize_repo_path(path)

    def test_normal_source_path_is_preserved(self) -> None:
        self.assertEqual(
            self.guard.normalize_repo_path("src/permitmesh/policy.py"),
            "src/permitmesh/policy.py",
        )


if __name__ == "__main__":
    unittest.main()
