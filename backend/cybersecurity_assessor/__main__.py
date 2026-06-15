"""``python -m cybersecurity_assessor`` entry point.

Lets you run ``python -m cybersecurity_assessor`` as a dev-time
shorthand for ``python -m cybersecurity_assessor.server``. Not used by
PyInstaller — see ``backend/cybersec_server_entry.py`` for that path.
PyInstaller strips package context from *any* file it's pointed at,
including ``__main__.py``, so the bundled entry has to live outside
the package.
"""

from __future__ import annotations

from .server import run

if __name__ == "__main__":
    run()
