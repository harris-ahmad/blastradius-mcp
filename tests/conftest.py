"""Turn an interpreter mismatch into a diagnosis instead of a puzzle.

A globally-installed pytest shadowing the venv's is easy to hit and confusing
to read: pip reports a dependency as present (it is — in the venv) while pytest
cannot import it (it is running on a different interpreter entirely).
"""
import sys

import pytest

_REQUIRED = ("httpx", "mcp", "pydantic")


def pytest_configure(config):
    missing = []
    for name in _REQUIRED:
        try:
            __import__(name)
        except ModuleNotFoundError:
            missing.append(name)

    if not missing:
        return

    raise pytest.UsageError(
        f"Cannot import: {', '.join(missing)}\n"
        f"\n"
        f"  pytest is running on: {sys.executable}\n"
        f"  (Python {sys.version_info.major}.{sys.version_info.minor})\n"
        f"\n"
        f"If that is not your virtualenv, a global pytest is shadowing it.\n"
        f"Run `python -m pytest` to force the active interpreter, or\n"
        f"`pip install -e \".[dev]\"` to install pytest into the venv itself."
    )
