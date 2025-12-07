from __future__ import annotations

from ._version import  __version__
from .core import run_bingo, setup_environment

__all__ = [
    "run_bingo",
    "setup_environment",
    "__version__",
]