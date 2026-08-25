from __future__ import annotations

import ctypes
import json
import ntpath
import os
import socket
import struct
from dataclasses import dataclass
from typing import Any

from ctypes import wintypes

from .models import ProcessRecord, SocketRecord
from .windows_attribution import ListenerAttribution, build_listener_attribution
from .windows_parsers import parse_windows_sockets

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TCP_TABLE_OWNER_PID_LISTENER = 3
ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0
AF_INET = 2
AF_INET6 = 23
_MAX_PATH = 32768


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class WindowsNativeFastInventory:
    processes: tuple[ProcessRecord, ...]
    sockets: tuple[SocketRecord, ...]
    listener_attribution: dict[
        tuple[str, str, int, str | None], ListenerAttribution
    ]
    socket_output: str
    processes_ok: bool
    sockets_ok: bool
    errors: tuple[str, ...] = ()


def _path_markers(path: str) -> tuple[str, ...]:
    lowered = path.casefold()
    markers = {
        "user_writable_executable"
        for token in ("\\temp\\", "\\appdata\\", "\\downloads\\")
        if token in lowered
    }
    return tuple(sorted(markers))


def _configure_kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(PROCESSENTRY32W),
    ]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(PROCESSENTRY32W),
    ]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _image_path(kernel32, pid: int) -> str | None:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(_MAX_PATH)
        size = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(
            handle,
            0,
            buffer,
            ctypes.byref(size),
        ):
            return None
        value = buffer.value.strip()
        return value or None
    finally:
        kernel32.CloseHandle(handle)


def _collect_processes() -> tuple[ProcessRecord, ...]:
    if os.name != "nt":
        raise OSError("native Windows process inventory requires Windows")
    kernel32 = _configure_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    invalid = ctypes.c_void_p(-1).value
    snapshot_value = int(snapshot) if isinstance(snapshot, int) else ctypes.cast(snapshot, ctypes.c_void_p).value
    if not snapshot_value or snapshot_value == invalid:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    records: list[ProcessRecord] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            if pid > 0:
                ppid = max(0, int(entry.th32ParentProcessID))
                command_name = str(entry.szExeFile or "unknown").strip() or "unknown"
                raw_path = _image_path(kernel32, pid) or ""
                executable = ntpath.basename(raw_path) or command_name
                records.append(
                    ProcessRecord(
                        pid=pid,
                        ppid=ppid,
                        user="unavailable",
                        command_name=command_name,
                        executable=executable,
                        args_hash="unavailable",
                        suspicious_markers=_path_markers(raw_path),
                        privileged_context=False,
                    )
                )
            entry.dwSize = ctypes.sizeof(entry)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return tuple(sorted(records, key=lambda item: item.pid))


def _configure_iphlpapi():
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    iphlpapi.GetExtendedTcpTable.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD
    return iphlpapi


def _tcp_rows(iphlpapi, family: int, row_type) -> list[Any]:
    size = wintypes.DWORD(0)
    result = int(
        iphlpapi.GetExtendedTcpTable(
            None,
            ctypes.byref(size),
            False,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    )
    if result not in {NO_ERROR, ERROR_INSUFFICIENT_BUFFER}:
        raise OSError(result, "GetExtendedTcpTable size query failed")
    if size.value < ctypes.sizeof(wintypes.DWORD):
        return []
    buffer = ctypes.create_string_buffer(size.value)
    result = int(
        iphlpapi.GetExtendedTcpTable(
            buffer,
            ctypes.byref(size),
            False,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    )
    if result != NO_ERROR:
        raise OSError(result, "GetExtendedTcpTable failed")
    count = wintypes.DWORD.from_buffer_copy(buffer.raw[:4]).value
    row_size = ctypes.sizeof(row_type)
    offset = ctypes.sizeof(wintypes.DWORD)
    available = max(0, (len(buffer) - offset) // row_size)
    count = min(int(count), available)
    rows: list[Any] = []
    for index in range(count):
        start = offset + index * row_size
        rows.append(row_type.from_buffer_copy(buffer.raw[start : start + row_size]))
    return rows


def _port(value: int) -> int:
    return int(socket.ntohs(int(value) & 0xFFFF))


def _socket_rows(processes: tuple[ProcessRecord, ...]) -> list[dict[str, object]]:
    if os.name != "nt":
        raise OSError("native Windows socket inventory requires Windows")
    names = {
        item.pid: ntpath.splitext(item.command_name)[0]
        for item in processes
        if item.pid > 0
    }
    iphlpapi = _configure_iphlpapi()
    values: list[dict[str, object]] = []
    for row in _tcp_rows(iphlpapi, AF_INET, MIB_TCPROW_OWNER_PID):
        address = socket.inet_ntop(AF_INET, struct.pack("<I", int(row.dwLocalAddr)))
        pid = int(row.dwOwningPid)
        values.append(
            {
                "Protocol": "tcp",
                "LocalAddress": address,
                "LocalPort": _port(row.dwLocalPort),
                "OwningProcess": pid,
                "ProcessName": names.get(pid),
            }
        )
    for row in _tcp_rows(iphlpapi, AF_INET6, MIB_TCP6ROW_OWNER_PID):
        address = socket.inet_ntop(AF_INET6, bytes(row.ucLocalAddr))
        scope = int(row.dwLocalScopeId)
        if scope:
            address = f"{address}%{scope}"
        pid = int(row.dwOwningPid)
        values.append(
            {
                "Protocol": "tcp",
                "LocalAddress": address,
                "LocalPort": _port(row.dwLocalPort),
                "OwningProcess": pid,
                "ProcessName": names.get(pid),
            }
        )
    return values


def collect_windows_native_fast() -> WindowsNativeFastInventory:
    """Collect fresh process/listener state through read-only Windows APIs."""

    errors: list[str] = []
    processes: tuple[ProcessRecord, ...] = ()
    rows: list[dict[str, object]] = []
    processes_ok = False
    sockets_ok = False
    try:
        processes = _collect_processes()
        processes_ok = True
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        errors.append(f"native process inventory unavailable: {type(exc).__name__}")
    try:
        rows = _socket_rows(processes)
        sockets_ok = True
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        errors.append(f"native listener inventory unavailable: {type(exc).__name__}")
    socket_output = json.dumps(rows, separators=(",", ":"))
    sockets = parse_windows_sockets(socket_output) if sockets_ok else ()
    attribution = (
        build_listener_attribution(socket_output, processes)
        if sockets_ok
        else {}
    )
    return WindowsNativeFastInventory(
        processes=processes,
        sockets=sockets,
        listener_attribution=attribution,
        socket_output=socket_output,
        processes_ok=processes_ok,
        sockets_ok=sockets_ok,
        errors=tuple(errors),
    )
