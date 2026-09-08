from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / ".github" / "nymrel-hourly" / "nymrel_patch_guard.py"


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


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
            "docs\\windows-spelling.md",
            "docs/name:stream.md",
            "docs/trailing.",
            "nested/AUX.txt",
            "nested/PROGRA~1/file.txt",
            "x/" * self.guard.MAX_PATH_SEGMENTS + "file.txt",
            "x" * (self.guard.MAX_PATH_SEGMENT_CHARS + 1),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.guard.normalize_repo_path(path)

    def test_normal_source_path_is_preserved(self) -> None:
        self.assertEqual(
            self.guard.normalize_repo_path("src/permitmesh/policy.py"),
            "src/permitmesh/policy.py",
        )

    def test_secret_families_are_screened(self) -> None:
        candidates = (
            "ASIA" + ("A" * 16),
            "AIza" + ("A" * 30),
            "Bearer " + ("A" * 30),
            "api_key=" + ("A" * 30),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertTrue(
                    any(pattern.search(candidate) for pattern in self.guard.SECRET_PATTERNS)
                )


class PatchGuardRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guard = load_guard()

    def initialize_repository(self, path: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=path, check=True)
        subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.name", "PermitMesh Test"], cwd=path, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@permitmesh.invalid"], cwd=path, check=True
        )
        source = path / "src" / "example.py"
        source.parent.mkdir()
        source.write_text("VALUE = 1\n", encoding="utf-8", newline="\n")
        subprocess.run(["git", "add", "."], cwd=path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "baseline"], cwd=path, check=True)

    def run_guard(self, repository: Path, output: Path) -> tuple[int, str]:
        stdout = io.StringIO()
        with (
            working_directory(repository),
            patch.object(
                sys,
                "argv",
                ["nymrel_patch_guard.py", "--mode", "worktree", "--output-dir", str(output)],
            ),
            redirect_stdout(stdout),
        ):
            result = self.guard.main()
        return result, stdout.getvalue()

    def test_real_git_patch_allows_bounded_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            self.initialize_repository(repository)
            (repository / "src" / "example.py").write_text(
                "VALUE = 2\n", encoding="utf-8", newline="\n"
            )
            result, output = self.run_guard(repository, root / "proposal")
            self.assertEqual(0, result, output)
            self.assertTrue((root / "proposal" / "changes.patch").is_file())
            self.assertTrue((root / "proposal" / "change-summary.md").is_file())

    def test_real_git_patch_rejects_protected_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            self.initialize_repository(repository)
            workflow = repository / ".github" / "workflows" / "unsafe.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: unsafe\n", encoding="utf-8", newline="\n")
            result, output = self.run_guard(repository, root / "proposal")
            self.assertEqual(1, result)
            self.assertIn("protected path", output)


if __name__ == "__main__":
    unittest.main()
