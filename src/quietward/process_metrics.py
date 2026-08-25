from __future__ import annotations

import ctypes
import os
import sys
from typing import Any


def _windows_rss_bytes() -> int | None:
    try:
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_current_process = kernel32.GetCurrentProcess
        get_current_process.argtypes = []
        get_current_process.restype = wintypes.HANDLE
        process = get_current_process()

        function = getattr(kernel32, "K32GetProcessMemoryInfo", None)
        if function is None:
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            function = psapi.GetProcessMemoryInfo
        function.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        function.restype = wintypes.BOOL

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if not function(process, ctypes.byref(counters), counters.cb):
            return None
        return max(0, int(counters.WorkingSetSize))
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def current_rss_bytes() -> int | None:
    if os.name == "nt":
        return _windows_rss_bytes()

    statm = "/proc/self/statm"
    if sys.platform.startswith("linux"):
        try:
            with open(statm, "r", encoding="ascii") as stream:
                resident_pages = int(stream.read().split()[1])
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            return max(0, resident_pages * page_size)
        except (OSError, ValueError, IndexError):
            return None

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF)
        value = int(usage.ru_maxrss)
        if sys.platform == "darwin":
            return max(0, value)
        return max(0, value * 1024)
    except (ImportError, OSError, ValueError):
        return None


def process_resource_snapshot() -> dict[str, Any]:
    rss = current_rss_bytes()
    return {
        "rss_bytes": rss,
        "rss_mib": round(rss / (1024 * 1024), 3) if rss is not None else None,
        "actions_executed": 0,
    }
