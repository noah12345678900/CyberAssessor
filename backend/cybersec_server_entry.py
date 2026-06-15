"""PyInstaller external entry point.

PyInstaller can only target a file path, not a ``package.module`` name —
and when given a file inside a package (e.g. ``cybersecurity_assessor/
__main__.py`` or ``cybersecurity_assessor/server.py``) it strips the
package context and the file's ``from . import ...`` lines fail at
runtime with ``ImportError: attempted relative import with no known
parent package``.

This wrapper lives at backend/ root (outside the package) so the
PyInstaller analyzer pulls ``cybersecurity_assessor`` in as a proper
package with all its relative imports intact. Not used by dev — dev
keeps running ``python -m cybersecurity_assessor`` (which hits
``cybersecurity_assessor/__main__.py``) or ``uv run cybersec-server``.
"""

from __future__ import annotations

from cybersecurity_assessor.server import run

if __name__ == "__main__":
    run()
