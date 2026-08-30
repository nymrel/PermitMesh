#!/usr/bin/env python3
"""Verify the exact wheel and sdist intended for a PermitMesh release."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import stat
import tarfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any

EXPECTED_NAME = "permitmesh"
EXPECTED_WHEEL_PACKAGE = PurePosixPath("permitmesh", "__init__.py")
FORBIDDEN_PARTS = {
    ".agent",
    ".benchmarks",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "reports",
    "reviews",
    "validation",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_member(name: str) -> PurePosixPath:
    member = PurePosixPath(name.replace("\\", "/"))
    if (
        member.is_absolute()
        or ".." in member.parts
        or (member.parts and member.parts[0].endswith(":"))
    ):
        raise ValueError(f"unsafe archive path: {name}")
    if any(part in FORBIDDEN_PARTS for part in member.parts):
        raise ValueError(f"forbidden release content: {name}")
    return member


def _project_metadata(root: Path) -> tuple[str, str]:
    document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = document["project"]
    return str(project["version"]), str(project["requires-python"])


def _source_version(root: Path) -> str:
    source = (root / "src" / "permitmesh" / "policy.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "IMPLEMENTATION_VERSION"
            for target in statement.targets
        ):
            value = ast.literal_eval(statement.value)
            if isinstance(value, str):
                return value
    raise ValueError("policy.py must define a literal IMPLEMENTATION_VERSION")


def _metadata_matches(
    metadata: Any,
    *,
    version: str,
    requires_python: str,
    artifact: str,
) -> None:
    if metadata["Name"] != EXPECTED_NAME:
        raise ValueError(f"unexpected {artifact} name: {metadata['Name']}")
    if metadata["Version"] != version:
        raise ValueError(f"unexpected {artifact} version: {metadata['Version']}")
    actual = {item.strip() for item in str(metadata["Requires-Python"]).split(",") if item.strip()}
    expected = {item.strip() for item in requires_python.split(",") if item.strip()}
    if actual != expected:
        raise ValueError(f"unexpected {artifact} Requires-Python: {metadata['Requires-Python']}")


def _verify_wheel(path: Path, version: str, requires_python: str) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        members: list[PurePosixPath] = []
        for info in archive.infolist():
            member = _validate_member(info.filename)
            if stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                raise ValueError(f"wheel must not contain symbolic links: {info.filename}")
            if "tests" in member.parts:
                raise ValueError(f"wheel must not contain tests: {info.filename}")
            members.append(member)
        if EXPECTED_WHEEL_PACKAGE not in members:
            raise ValueError("wheel does not contain the PermitMesh package")
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise ValueError("wheel must contain exactly one METADATA file")
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))

    _metadata_matches(
        metadata,
        version=version,
        requires_python=requires_python,
        artifact="wheel",
    )
    return {"file": path.name, "sha256": _sha256(path), "size": path.stat().st_size}


def _verify_sdist(path: Path, version: str, requires_python: str) -> dict[str, Any]:
    with tarfile.open(path, mode="r:gz") as archive:
        members: list[PurePosixPath] = []
        package_info = None
        for archive_member in archive.getmembers():
            member = _validate_member(archive_member.name)
            if archive_member.issym() or archive_member.islnk():
                raise ValueError(f"sdist must not contain links: {archive_member.name}")
            if not (archive_member.isfile() or archive_member.isdir()):
                raise ValueError(f"sdist contains unsupported member: {archive_member.name}")
            members.append(member)
            if archive_member.isfile() and member.name == "PKG-INFO":
                extracted = archive.extractfile(archive_member)
                if extracted is None:
                    raise ValueError("could not read sdist PKG-INFO")
                package_info = Parser().parsestr(extracted.read().decode("utf-8"))

    roots = {member.parts[0] for member in members if member.parts}
    if len(roots) != 1:
        raise ValueError("sdist must contain exactly one top-level directory")
    root = next(iter(roots))
    required = {
        PurePosixPath(root, "LICENSE"),
        PurePosixPath(root, "README.md"),
        PurePosixPath(root, "pyproject.toml"),
        PurePosixPath(root, "docs", "PROTOCOL.md"),
        PurePosixPath(root, "examples", "conformance-suite.json"),
        PurePosixPath(root, "schema", "permitmesh-contract.schema.json"),
        PurePosixPath(root, "src", "permitmesh", "__init__.py"),
    }
    missing = sorted(str(item) for item in required - set(members))
    if missing:
        raise ValueError(f"sdist is missing required files: {missing}")
    if version.replace("-", "_") not in root.replace("-", "_"):
        raise ValueError(f"sdist root does not encode version {version}: {root}")
    if package_info is None:
        raise ValueError("sdist does not contain PKG-INFO")
    _metadata_matches(
        package_info,
        version=version,
        requires_python=requires_python,
        artifact="sdist",
    )
    return {"file": path.name, "sha256": _sha256(path), "size": path.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    parser.add_argument("--tag")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    version, requires_python = _project_metadata(root)
    if _source_version(root) != version:
        raise ValueError("source IMPLEMENTATION_VERSION does not match project version")
    if args.tag and args.tag != f"v{version}":
        raise ValueError(f"tag {args.tag!r} does not match project version v{version}")

    wheels = sorted(args.dist.glob("*.whl"))
    sdists = sorted(args.dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("release directory must contain exactly one wheel and one sdist")

    receipt = {
        "schema_version": 1,
        "name": EXPECTED_NAME,
        "version": version,
        "requires_python": requires_python,
        "artifacts": [
            _verify_wheel(wheels[0], version, requires_python),
            _verify_sdist(sdists[0], version, requires_python),
        ],
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
