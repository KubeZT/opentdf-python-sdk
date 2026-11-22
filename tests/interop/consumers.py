"""Build the downstream executables used by the live interoperability tests."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path


def rust_consumer(sdk: Path, work: Path) -> list[str]:
    package_target = work / "rust-package"
    subprocess.run(
        [
            "cargo",
            "package",
            "--locked",
            "--allow-dirty",
            "--manifest-path",
            str(sdk / "Cargo.toml"),
            "--target-dir",
            str(package_target),
        ],
        check=True,
    )
    (package,) = (package_target / "package").glob("*.crate")
    # The archive comes from cargo package above.
    with tarfile.open(package) as archive:
        archive.extractall(work)
    dependency = work / package.stem
    project = work / "rust-consumer"
    (project / "src").mkdir(parents=True)
    (project / "Cargo.toml").write_text(
        '[package]\nname = "tdf-consumer"\nversion = "0.1.0"\n'
        'edition = "2024"\nrust-version = "1.88"\npublish = false\n'
        f'[dependencies]\nopentdf-rust-sdk = {{ path = "../{dependency.name}" }}\n',
        encoding="utf-8",
    )
    shutil.copyfile(dependency / "Cargo.lock", project / "Cargo.lock")
    shutil.copyfile(dependency / "examples/tdf_driver.rs", project / "src/main.rs")
    subprocess.run(
        ["cargo", "build", "--target-dir", str(package_target)],
        cwd=project,
        check=True,
    )
    executable = "tdf-consumer.exe" if os.name == "nt" else "tdf-consumer"
    return [str(package_target / "debug" / executable)]


def python_consumer(sdk: Path, work: Path) -> list[str]:
    source = work / "python-source"
    shutil.copytree(
        sdk,
        source,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "build",
            "dist",
            "*.egg-info",
            "__pycache__",
            ".hypothesis",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
        ),
    )
    dist = work / "python-dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist)],
        cwd=source,
        check=True,
    )
    (wheel,) = dist.glob("*.whl")
    venv = work / "python-consumer"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(python), "-I", "-m", "pip", "install", str(wheel)], check=True)
    subprocess.run([str(python), "-I", "-m", "pip", "check"], check=True)
    driver = work / "python_driver.py"
    shutil.copyfile(source / "tests/interop/tdf_driver.py", driver)
    return [str(python), "-I", str(driver)]


def packaged_commands(
    rust_root: Path, python_root: Path, work: Path
) -> dict[str, list[str]]:
    return {
        "rust": rust_consumer(rust_root, work),
        "python": python_consumer(python_root, work),
    }
