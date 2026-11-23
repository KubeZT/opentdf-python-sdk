# SDK releases

The Rust crate and Python distribution use the same release version.
Version 0.1.0 covers the two ZIP TDF profiles listed in the
[capability matrix](capabilities.md). The [profile acceptance plan](profiles.md)
tracks ACP 240 ZTDF, IC-TDF, and NanoTDF independently.

Preserve existing public entry points, option types, defaults, and error
categories in 0.1 patch releases. Verify new behavior through a separate
consumer built from each package.

## Build a release pair

Update the version in `Cargo.toml` and `pyproject.toml` and in both copies
of `tests/vectors/sdk-version.txt` when preparing a new version. Refresh
the Rust lockfiles if the version changes.

1. Run `make check` and `make test-conformance` in both checkouts. Run
   `make test-e2e` from either checkout against the pinned local KAS.
2. Commit the release changes in both checkouts. Run `make release-packages`
   with the Python development environment active. From Rust, pass
   `PYTHON=/path/to/venv/bin/python` if needed.
3. Check the paired output at `target/release-packages/v0.1.0/` in the
   Rust checkout. It contains the verified crate, wheel, source distribution,
   source commits, and SHA-256 checksums. Tag both recorded commits with the
   same version.

The paired command compiles a downstream Cargo project using the unpacked
crate and imports the wheel from a fresh virtual environment. A pin
mismatch fails before the output pair is written.

## Use the packages

For Rust, unpack the crate into a local dependency directory. Point the
consumer's `Cargo.toml` at that directory with `cargo add --path`.
For Python, install the wheel into the consumer's virtual environment
with `python -m pip install /path/to/opentdf_python_sdk-0.1.0-py3-none-any.whl`.
