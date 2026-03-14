"""Secure memory helper — mlock sensitive data and wipe on release.

Provides a SecureBuffer class that:
  - Allocates a ctypes buffer and mlocks it into RAM (never swapped)
  - Overwrites the buffer with zeros on close/delete
  - Falls back gracefully when mlock is unavailable (logs warning)

Usage:
    from common.mlock_helper import SecureBuffer

    buf = SecureBuffer(secret_bytes)
    data = buf.read()      # returns bytes copy
    buf.close()            # zeroes + munlock
"""

import ctypes
import ctypes.util
import logging
import platform

log = logging.getLogger(__name__)

# --- Platform detection ---
_IS_LINUX = platform.system() == "Linux"

# libc bindings
_libc = None
if _IS_LINUX:
    _libc_name = ctypes.util.find_library("c")
    if _libc_name:
        _libc = ctypes.CDLL(_libc_name, use_errno=True)

# mlock/munlock signatures
if _libc:
    _libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _libc.mlock.restype = ctypes.c_int
    _libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _libc.munlock.restype = ctypes.c_int


def get_mlock_limit() -> int:
    """Return the current RLIMIT_MEMLOCK soft limit in bytes, or 0 if unavailable."""
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        return soft
    except Exception:
        return 0


def _mlock(addr: int, size: int) -> bool:
    """Lock memory region. Returns True on success."""
    if not _libc:
        return False
    ret = _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
    if ret != 0:
        errno = ctypes.get_errno()
        log.warning("mlock failed (errno=%d). Sensitive data may be swapped.", errno)
        return False
    return True


def _munlock(addr: int, size: int) -> bool:
    """Unlock memory region. Returns True on success."""
    if not _libc:
        return False
    ret = _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
    return ret == 0


class SecureBuffer:
    """An mlock'd buffer that zeroes itself on close."""

    def __init__(self, data: bytes):
        """Create a secure buffer from *data*. The original bytes object is NOT wiped."""
        self._size = len(data)
        self._buf = (ctypes.c_char * self._size)()
        ctypes.memmove(self._buf, data, self._size)
        self._locked = _mlock(ctypes.addressof(self._buf), self._size)
        self._closed = False
        if self._locked:
            log.debug("SecureBuffer: %d bytes mlocked", self._size)
        else:
            log.debug("SecureBuffer: %d bytes allocated (mlock unavailable)", self._size)

    def read(self) -> bytes:
        """Return a copy of the buffer contents."""
        if self._closed:
            raise ValueError("SecureBuffer is closed")
        return bytes(self._buf)

    @property
    def size(self) -> int:
        return self._size

    @property
    def is_locked(self) -> bool:
        return self._locked

    def close(self) -> None:
        """Zero the buffer and munlock."""
        if self._closed:
            return
        # Overwrite with zeros
        ctypes.memset(ctypes.addressof(self._buf), 0, self._size)
        # Unlock
        if self._locked:
            _munlock(ctypes.addressof(self._buf), self._size)
            self._locked = False
        self._closed = True
        log.debug("SecureBuffer: %d bytes zeroed and released", self._size)

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __len__(self):
        return self._size

    def __repr__(self):
        state = "closed" if self._closed else ("mlocked" if self._locked else "unlocked")
        return f"<SecureBuffer size={self._size} {state}>"
