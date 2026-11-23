"""Build and verify the paired SDK release packages locally."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from consumers import packaged_commands
from matrix import sdk_roots


def clean_commit(root: Path) -> str:
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=root)
    if status:
        raise SystemExit(f"Commit the release changes in {root.name} before packaging")
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def main() -> None:
    rust, python = sdk_roots(__doc__ or "")
    sources = {root: clean_commit(root) for root in (rust, python)}
    version = (rust / "tests/vectors/sdk-version.txt").read_text().strip()
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise SystemExit("The shared release version must be major.minor.patch")

    destination = rust / "target/release-packages" / f"v{version}"
    if destination.exists():
        raise SystemExit(f"Release packages already exist at {destination}")

    with TemporaryDirectory(prefix="opentdf-release-") as temporary:
        work = Path(temporary)
        commands = packaged_commands(rust, python, work, release=True)
        for peer, command in commands.items():
            reported = subprocess.check_output([*command, "version"], text=True).strip()
            if reported != version:
                raise SystemExit(
                    f"{peer} package reports {reported}, expected {version}"
                )
        if any(clean_commit(root) != commit for root, commit in sources.items()):
            raise SystemExit("A source commit changed during packaging")

        (crate,) = (work / "rust-package/package").glob("*.crate")
        (wheel,) = (work / "python-dist").glob("*.whl")
        (sdist,) = (work / "python-dist").glob("*.tar.gz")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=destination.parent) as staging_path:
            staging = Path(staging_path) / "packages"
            staging.mkdir()
            for package in (crate, wheel, sdist):
                shutil.copyfile(package, staging / package.name)
            (staging / "SOURCE-COMMITS").write_text(
                "".join(f"{root.name} {commit}\n" for root, commit in sources.items()),
                encoding="ascii",
            )
            (staging / "SHA256SUMS").write_text(
                "".join(
                    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                    for path in sorted(staging.iterdir())
                ),
                encoding="ascii",
            )
            staging.rename(destination)
    print(destination)


if __name__ == "__main__":
    main()
