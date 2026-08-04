"""Compatibility layer for pre-QuietWard Python imports.

New code should import :mod:`quietward`. This namespace is retained only so
existing alpha installations and downstream tests do not break during the
product rename.
"""

from __future__ import annotations

import quietward as _quietward
from quietward import *  # noqa: F401,F403
from quietward import __all__, __version__

# Allow imports such as ``forge_sentinel.config`` to resolve to the renamed
# implementation package without maintaining a second copy of the modules.
__path__ = _quietward.__path__
