"""AI-guided, fail-closed control plane for io_uring fuzzing."""

from __future__ import annotations

from importlib import metadata

try:
    # Single source of truth: the installed package version from pyproject.
    __version__ = metadata.version("io-uring-ai-control")
except metadata.PackageNotFoundError:  # not installed (e.g. running from a checkout)
    __version__ = "0.0.0+unknown"
