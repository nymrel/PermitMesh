from __future__ import annotations

import argparse
import pathlib
import re
import subprocess

MAX_FILES = 8
MAX_LINES = 600
MAX_FILE_BYTES = 200_000
MAX_PATH_CHARS = 512
MAX_PATH_SEGMENTS = 128
MAX_PATH_SEGMENT_CHARS = 255
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
WINDOWS_SHORT_NAME_PATTERN = re.compile(r"~[1-9][0-9]*(?:\.|$)", re.IGNORECASE)

FORBIDDEN_PREFIXES = (
    ".agent/",
    ".agents/",
    ".claude/",
    ".cursor/",
    ".github/",
    ".gitlab/",
    ".idea/",
    ".vscode/",
    ".circleci/",
    ".azure/",
    ".devcontainer/",
    ".changeset/",
    "infra/",
    "infrastructure/",
    "deploy/",
    "deployment/",
    "releases/",
    "migrations/",
)
FORBIDDEN_BASENAMES = {
    ".env",
    ".env.example",
    ".gitmodules",
    ".npmrc",
    ".pypirc",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "deno.lock",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "gradle.properties",
    "build.gradle",
    "build.gradle.kts",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "vercel.json",
    "netlify.toml",
    "fly.toml",
    "render.yaml",
    "railway.json",
    "license",
    "license.md",
    "license.txt",
    "security.md",
    "agent.md",
    "agents.md",
    "copilot-instructions.md",
    "codeowners",
    "schema.prisma",
}
FORBIDDEN_SEGMENTS = {
    "auth",
    "authentication",
    "billing",
    "payment",
    "payments",
    "secrets",
    "credentials",
    "migration",
    "migrations",
    "deploy",
    "deployment",
    "release",
    "releases",
}
FORBIDDEN_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".sql",
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|access[_-]?token|token|secret|password)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9_./+=-]{12,}",
        re.IGNORECASE,
    ),
)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
    )


def append_output(path: str | None, value: str) -> None:
    if not path:
        return
    with pathlib.Path(path).open("a", encoding="utf-8") as handle:
        handle.write(value + "\n")


def normalize_repo_path(raw_name: str) -> str:
    if (
        not raw_name
        or len(raw_name) > MAX_PATH_CHARS
        or raw_name.startswith("/")
        or "\\" in raw_name
        or re.match(r"^[A-Za-z]:", raw_name) is not None
        or "`" in raw_name
        or any(
            ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF
            for character in raw_name
        )
    ):
        raise ValueError("path is not a bounded portable repository-relative path")
    parts = raw_name.split("/")
    if (
        len(parts) > MAX_PATH_SEGMENTS
        or any(part in {"", ".", ".."} for part in parts)
        or any(len(part) > MAX_PATH_SEGMENT_CHARS for part in parts)
        or any(":" in part or part.endswith((".", " ")) for part in parts)
        or any(WINDOWS_SHORT_NAME_PATTERN.search(part) is not None for part in parts)
        or any(part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES for part in parts)
    ):
        raise ValueError("path contains an unsafe or ambiguous segment")
    return raw_name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("worktree", "index"), required=True)
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--github-output")
    args = parser.parse_args()

    cached = args.mode == "index"
    diff_prefix = ("git", "diff", "--cached") if cached else ("git", "diff")

    if not cached:
        run("git", "add", "-N", "--", ".")

    if run(*diff_prefix, "--quiet", check=False).returncode == 0:
        append_output(args.github_output, "has_changes=false")
        print("No safe maintenance patch was produced.")
        return 0

    violations: list[str] = []

    deleted = [
        item.decode("utf-8", "surrogateescape")
        for item in run(*diff_prefix, "--name-only", "--diff-filter=D", "-z").stdout.split(b"\0")
        if item
    ]
    if deleted:
        violations.append("deletions are not allowed: " + ", ".join(deleted))

    names = [
        item.decode("utf-8", "surrogateescape")
        for item in run(
            *diff_prefix,
            "--name-only",
            "--diff-filter=ACMRTUXB",
            "-z",
        ).stdout.split(b"\0")
        if item
    ]
    if not names:
        violations.append("diff contains no allowed added or modified files")
    if len(names) > MAX_FILES:
        violations.append(f"changed file count {len(names)} exceeds limit {MAX_FILES}")

    summary = run(*diff_prefix, "--summary").stdout.decode("utf-8", "replace")
    for marker in ("delete mode", "rename ", "mode change", "create mode 120000"):
        if marker in summary:
            violations.append(f"unsupported git change detected: {marker.strip()}")

    total_lines = 0
    for raw in run(*diff_prefix, "--numstat", "-z").stdout.split(b"\0"):
        if not raw:
            continue
        parts = raw.decode("utf-8", "surrogateescape").split("\t", 2)
        if len(parts) != 3:
            violations.append("unable to parse git numstat")
            continue
        added, removed, numstat_path = parts
        if added == "-" or removed == "-":
            violations.append(f"binary change is not allowed: {numstat_path}")
            continue
        total_lines += int(added) + int(removed)
    if total_lines > MAX_LINES:
        violations.append(f"changed line count {total_lines} exceeds limit {MAX_LINES}")

    for index, raw_name in enumerate(names):
        try:
            normalized = normalize_repo_path(raw_name)
        except ValueError as exc:
            violations.append(f"invalid repository path at index {index}: {exc}")
            continue
        lower = normalized.lower()
        repository_path = pathlib.PurePosixPath(lower)
        basename = repository_path.name
        segments = set(repository_path.parts)

        if lower.startswith(FORBIDDEN_PREFIXES):
            violations.append(f"protected path: {raw_name}")
        if basename in FORBIDDEN_BASENAMES:
            violations.append(f"protected file: {raw_name}")
        if any(segment in FORBIDDEN_SEGMENTS for segment in segments):
            violations.append(f"protected path segment: {raw_name}")
        if lower.endswith(FORBIDDEN_SUFFIXES):
            violations.append(f"protected file type: {raw_name}")

        local = pathlib.Path(normalized)
        if local.exists() and local.is_symlink():
            violations.append(f"symlink is not allowed: {raw_name}")
        if local.exists() and local.is_file():
            size = local.stat().st_size
            if size > MAX_FILE_BYTES:
                violations.append(f"file {raw_name} is {size} bytes; limit is {MAX_FILE_BYTES}")

    check_result = run(*diff_prefix, "--check", check=False)
    if check_result.returncode != 0:
        violations.append(
            "git diff --check failed: " + check_result.stdout.decode("utf-8", "replace")[:1000]
        )

    diff_text = run(*diff_prefix, "--unified=0", "--no-ext-diff").stdout.decode("utf-8", "replace")
    added_text = "\n".join(
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    for pattern in SECRET_PATTERNS:
        if pattern.search(added_text):
            violations.append(f"possible credential/private-key pattern: {pattern.pattern}")

    if violations:
        print("Patch guard rejected the proposal:")
        for violation in sorted(set(violations)):
            print(f"- {violation}")
        return 1

    summary_lines = [
        "### Guarded change summary",
        "",
        f"- Files: {len(names)} / {MAX_FILES} maximum",
        f"- Changed lines: {total_lines} / {MAX_LINES} maximum",
        "- Protected-path, binary, symlink, deletion, rename, mode, size, "
        "whitespace, and credential-pattern checks: passed",
        "",
        "#### Files",
    ]
    summary_lines.extend(f"- `{name}`" for name in names)
    print("\n".join(summary_lines))

    if not cached:
        output_dir = pathlib.Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "changes.patch").write_bytes(
            run("git", "diff", "--binary", "--full-index").stdout
        )
        (output_dir / "change-summary.md").write_text(
            "\n".join(summary_lines) + "\n", encoding="utf-8"
        )
        append_output(args.github_output, "has_changes=true")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
