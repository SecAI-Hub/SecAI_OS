"""Collection-time test safety defaults.

Production UI startup requires a persistent Flask signing credential. Unit
tests intentionally opt into the loopback-only ephemeral development mode so
imports remain hermetic and never depend on appliance secrets.
"""

import os
import sys
from pathlib import Path


os.environ.setdefault("BIND_ADDR", "127.0.0.1:18480")
os.environ.setdefault("SECAI_ALLOW_EPHEMERAL_FLASK_SECRET", "1")
os.environ.setdefault("SECAI_ALLOW_EPHEMERAL_AGENT_KEYS", "1")
os.environ.setdefault("SECAI_ALLOW_MISSING_AGENT_POLICY", "1")

# The repository intentionally uses a non-installed ``services`` namespace
# during tests.  The pytest console entry point does not guarantee that the
# working directory is importable, so make the repository root explicit.
repo_root = str(Path(__file__).resolve().parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
