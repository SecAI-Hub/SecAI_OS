"""Read the calling service's inference credential without a shared-token fallback."""
import os
from pathlib import Path
import re
import stat

import requests


class InferenceCredentialUnavailable(requests.ConnectionError):
    """The local inference credential cannot be safely used."""


def inference_headers() -> dict[str, str]:
    descriptor = -1
    try:
        value = os.getenv("INFERENCE_TOKEN_PATH", "")
        if not value or not Path(value).is_absolute():
            raise ValueError("credential path required")
        path = Path(value)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size not in (64, 65):
            raise ValueError("invalid credential file")
        if mode not in (0o400, 0o600):
            # Sandbox credentials are individually mounted read-only from a
            # private host directory for the fixed non-root container UID.
            if not (
                os.getenv("SECURE_AI_DEPLOYMENT_MODE") == "sandbox"
                and mode in (0o444, 0o644)
                and os.fstatvfs(descriptor).f_flag & os.ST_RDONLY
            ):
                raise ValueError("invalid credential permissions")
        raw = os.read(descriptor, 66)
        if not re.fullmatch(rb"[0-9a-f]{64}\n?", raw):
            raise ValueError("invalid credential value")
        after = os.fstat(descriptor)
        current = path.lstat()
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError("credential changed during read")
        return {"Authorization": "Bearer " + raw[:64].decode("ascii")}
    except (OSError, ValueError):
        # Never leak the credential, its path, or a failed HTTP request body.
        raise InferenceCredentialUnavailable("local inference credential unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
