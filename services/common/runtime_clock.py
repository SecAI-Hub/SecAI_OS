"""Explicit Linux suspend-inclusive lifetime clock; never fall back silently."""
from __future__ import annotations

import ctypes
import math
import signal
import sys
import time

from .bounded_state import StateUnavailable

DOMAIN = "linux-boottime-v1"


def clock_id() -> int:
    if not sys.platform.startswith("linux") or not hasattr(time, "CLOCK_BOOTTIME"):
        raise StateUnavailable("suspend-aware runtime clock unavailable")
    return time.CLOCK_BOOTTIME


def now() -> float:
    try:
        value = time.clock_gettime(clock_id())
    except (OSError, AttributeError) as error:
        raise StateUnavailable("suspend-aware runtime clock unavailable") from error
    if not math.isfinite(value) or value < 0:
        raise StateUnavailable("invalid suspend-aware runtime clock")
    return value


class Timespec(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("nanoseconds", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("interval", Timespec), ("value", Timespec)]


def arm_deadline(deadline: float) -> None:
    """Independent CLOCK_BOOTTIME timer delivers SIGALRM after suspend too."""
    if not math.isfinite(deadline) or deadline <= now():
        raise StateUnavailable("attempt deadline expired")
    library = ctypes.CDLL(None, use_errno=True)
    library.timer_create.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    library.timer_create.restype = ctypes.c_int
    library.timer_settime.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(Itimerspec), ctypes.c_void_p]
    library.timer_settime.restype = ctypes.c_int
    timer = ctypes.c_void_p()
    # A null sigevent selects the POSIX default SIGALRM delivery. This clock
    # does not request waking the host (CLOCK_BOOTTIME_ALARM would do that).
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    if library.timer_create(clock_id(), None, ctypes.byref(timer)) != 0:
        raise StateUnavailable("suspend-aware deadline timer unavailable")
    seconds = int(deadline)
    specification = Itimerspec(Timespec(0, 0), Timespec(seconds, int((deadline - seconds) * 1_000_000_000)))
    if library.timer_settime(timer, 1, ctypes.byref(specification), None) != 0:  # TIMER_ABSTIME
        raise StateUnavailable("suspend-aware deadline timer unavailable")
