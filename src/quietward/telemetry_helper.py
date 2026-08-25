"""Root-side Linux process telemetry helper; local socket only, no actions."""
from __future__ import annotations

import argparse, ctypes, grp, hashlib, json, os, re, selectors, signal, socket, struct, subprocess, threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0"
NETLINK_CONNECTOR = 11
CN_IDX_PROC = CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_FORK = 0x00000001
IN_CREATE, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO, IN_ISDIR = 0x100, 0x8, 0x40, 0x80, 0x40000000
INOTIFY_MASK = IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO

class Helper:
    def __init__(self, socket_path: Path, group: int, max_events: int = 4096) -> None:
        self.socket_path, self.group, self.events = socket_path, group, deque(maxlen=max_events)
        self.sequence = 0; self.stop = threading.Event(); self.auth_recent: dict[tuple[str,str], deque[float]] = {}
    def add_start(self, pid: int, *, parent_pid: int | None = None, execution: bool = False) -> None:
        try:
            status = Path(f"/proc/{pid}/status").read_text(errors="replace")[:8192]
            ppid = parent_pid if parent_pid is not None else int(next(line.split()[1] for line in status.splitlines() if line.startswith("PPid:")))
            uid = int(next(line.split()[1] for line in status.splitlines() if line.startswith("Uid:")))
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()[:16384].replace(b"\0", b" ").decode("utf-8", "replace")
            name = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()[:128]
        except (OSError, StopIteration, ValueError):
            # A fork notification is still valuable after an extremely short
            # child exits.  It contains no command data and cannot leak it.
            if parent_pid is None: return
            ppid, uid, raw, name = parent_pid, None, "", "exited-before-normalization"
        lowered = raw.lower()
        parent_raw = ""
        if execution and ppid > 0:
            try: parent_raw = Path(f"/proc/{ppid}/cmdline").read_bytes()[:16384].replace(b"\0", b" ").decode("utf-8", "replace").lower()
            except OSError: pass
        base64_decode = "base64" in lowered and (" -d" in lowered or "--decode" in lowered)
        encoded_payload_shape = bool(re.search(r"[a-z0-9+/]{20,}={0,2}", parent_raw))
        shell_chain = "| bash" in parent_raw or "| sh" in parent_raw
        temporary_decoded_drop = ">" in parent_raw and "/tmp/" in parent_raw
        encoded = execution and base64_decode and (shell_chain or (encoded_payload_shape and temporary_decoded_drop))
        self.sequence += 1
        self.events.append({"schema_version": SCHEMA_VERSION, "sequence": self.sequence, "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"), "event_type":"process_start", "data":{"pid":pid,"ppid":ppid,"uid":uid,"process_name":name,"observation_stage":"exec" if execution else "fork","interpreter":name if encoded else None,"encoded_shell_chain":encoded,"args_hash":hashlib.sha256(raw.encode()).hexdigest() if encoded else None,"raw_arguments_persisted":False}})
    def connector_loop(self) -> None:
        try:
            s=socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR); s.bind((os.getpid(), 1))
            hdr=struct.pack("IHHII", 40, 0x3, 0, os.getpid(), 0); cn=struct.pack("IIIIHH", CN_IDX_PROC,CN_VAL_PROC,0,0,4,0)
            s.send(hdr+cn+struct.pack("I", PROC_CN_MCAST_LISTEN))
            s.settimeout(.5)
            while not self.stop.is_set():
                try: data=s.recv(4096)
                except TimeoutError: continue
                if len(data) < 56: continue
                payload=data[36:]
                what=struct.unpack_from("I",payload,0)[0]
                if what == PROC_EVENT_FORK:
                    parent, child = struct.unpack_from("I", payload, 16)[0], struct.unpack_from("I", payload, 24)[0]
                    self.add_start(child, parent_pid=parent)
                elif what == PROC_EVENT_EXEC:
                    pid=struct.unpack_from("I",payload,16)[0]; self.add_start(pid, execution=True)
        except OSError as exc:
            print(f"quietward telemetry proc connector unavailable: {exc}", flush=True)
            return
        finally:
            try: s.close()
            except Exception: pass
    def add_flow(self, source: bytes, destination: bytes, destination_port: int) -> None:
        self.sequence += 1
        digest = lambda value: hashlib.sha256(value).hexdigest()[:20]
        self.events.append({"schema_version": SCHEMA_VERSION, "sequence": self.sequence, "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"), "event_type":"network_flow", "data":{"source_address_hash":digest(source),"destination_hash":digest(destination),"destination_port":destination_port,"protocol":"tcp","packet_payload_captured":False}})
    def add_file_activity(self, operation: str) -> None:
        self.sequence += 1
        self.events.append({"schema_version": SCHEMA_VERSION, "sequence": self.sequence, "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"), "event_type":"file_activity", "data":{"operation":operation,"scope":"monitored","raw_paths_persisted":False,"raw_file_content_persisted":False}})
    def auth_loop(self) -> None:
        # Fixed supported journal interface; output is normalized in memory and
        # the original log message is never sent to QuietWard or stored here.
        command=("/usr/bin/journalctl","--no-pager","--output=json","--follow","-u","ssh.service")
        try: process=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except OSError as exc:
            print(f"quietward telemetry journal source unavailable: {exc}", flush=True); return
        try:
            assert process.stdout is not None
            for line in process.stdout:
                if self.stop.is_set(): break
                try: row=json.loads(line); message=str(row.get("MESSAGE", ""))
                except (ValueError, TypeError): continue
                if "Failed password" not in message and "Invalid user" not in message: continue
                address=re.search(r" from ([0-9a-fA-F:.]+)", message); user=re.search(r"(?:for (?:invalid user )?|Invalid user )([^ ]+)", message)
                digest=lambda value:hashlib.sha256(value.encode()).hexdigest()[:20]
                source, identity = digest(address.group(1)) if address else "unknown", digest(user.group(1)) if user else "unknown"
                now=datetime.now(timezone.utc); key=(source,identity); history=self.auth_recent.setdefault(key,deque())
                history.append(now.timestamp())
                while history and now.timestamp()-history[0] > 60: history.popleft()
                if len(history) < 3: continue
                self.sequence += 1
                self.events.append({"schema_version":SCHEMA_VERSION,"sequence":self.sequence,"observed_at":now.isoformat().replace("+00:00","Z"),"event_type":"auth_failure","data":{"source_address_hash":source,"user_identity_hash":identity,"service":"ssh","failed_count":len(history),"window_seconds":now.timestamp()-history[0],"raw_source_address_persisted":False,"raw_username_persisted":False,"raw_log_message_persisted":False}})
        finally:
            process.terminate()
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired: process.kill()
    def inotify_loop(self) -> None:
        libc=ctypes.CDLL("libc.so.6", use_errno=True)
        fd=libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if fd < 0: return
        watched: dict[int, str] = {}
        def watch(path: str) -> None:
            descriptor=libc.inotify_add_watch(fd, path.encode(), INOTIFY_MASK)
            if descriptor >= 0: watched[descriptor]=path
        watch("/tmp")
        try:
            while not self.stop.wait(.05):
                try: data=os.read(fd, 65536)
                except BlockingIOError: continue
                offset=0
                while offset+16 <= len(data):
                    wd,mask,cookie,length=struct.unpack_from("iIII",data,offset); name=data[offset+16:offset+16+length].rstrip(b"\0").decode("utf-8","replace"); offset += 16+length
                    base=watched.get(wd)
                    if base is None: continue
                    target=os.path.join(base,name)
                    if mask & IN_ISDIR and mask & (IN_CREATE|IN_MOVED_TO): watch(target)
                    elif mask & (IN_CREATE|IN_CLOSE_WRITE|IN_MOVED_FROM|IN_MOVED_TO):
                        operation="rename" if mask & (IN_MOVED_FROM|IN_MOVED_TO) else "write" if mask & IN_CLOSE_WRITE else "create"
                        self.add_file_activity(operation)
        except OSError: pass
        finally: os.close(fd)
    def packet_loop(self) -> None:
        try:
            capture=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); capture.settimeout(.5)
            while not self.stop.is_set():
                try: frame=capture.recv(2048)
                except TimeoutError: continue
                if len(frame) < 54 or frame[12:14] != b"\x08\x00": continue
                offset=14; ihl=(frame[offset] & 15)*4
                if frame[offset+9] != 6 or len(frame) < offset+ihl+20: continue
                tcp=offset+ihl; flags=frame[tcp+13]
                if flags & 0x02 and not flags & 0x10:
                    port=struct.unpack_from("!H",frame,tcp+2)[0]
                    self.add_flow(frame[offset+12:offset+16],frame[offset+16:offset+20],port)
        except OSError as exc:
            print(f"quietward telemetry packet source unavailable: {exc}", flush=True)
            return
        finally:
            try: capture.close()
            except Exception: pass
    def serve(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chown(self.socket_path.parent, 0, self.group)
        os.chmod(self.socket_path.parent, 0o750)
        try: self.socket_path.unlink()
        except FileNotFoundError: pass
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); server.bind(str(self.socket_path)); os.chown(self.socket_path,0,self.group); os.chmod(self.socket_path,0o660); server.listen(8); server.settimeout(.5)
        threading.Thread(target=self.connector_loop,daemon=True).start()
        threading.Thread(target=self.packet_loop,daemon=True).start()
        threading.Thread(target=self.inotify_loop,daemon=True).start()
        threading.Thread(target=self.auth_loop,daemon=True).start()
        while not self.stop.is_set():
            try: client,_=server.accept()
            except TimeoutError: continue
            with client:
                try:
                    request=json.loads(client.recv(8192)); after=max(0,int(request.get("after",0))); limit=min(4096,max(1,int(request.get("limit",512))))
                    if request.get("schema_version") != SCHEMA_VERSION or request.get("op") != "drain": raise ValueError
                    rows=[r for r in self.events if r["sequence"]>after][:limit]
                    client.sendall(b"".join(json.dumps(row,separators=(",", ":")).encode()+b"\n" for row in rows))
                except (ValueError, TypeError, json.JSONDecodeError, OSError): pass
        server.close(); self.socket_path.unlink(missing_ok=True)
def main() -> None:
    p=argparse.ArgumentParser(); p.add_argument("--socket",type=Path,default=Path("/run/quietward/telemetry.sock")); p.add_argument("--group",required=True); args=p.parse_args()
    try: group = int(args.group)
    except ValueError: group = grp.getgrnam(args.group).gr_gid
    helper=Helper(args.socket, group); signal.signal(signal.SIGTERM,lambda *_:helper.stop.set()); signal.signal(signal.SIGINT,lambda *_:helper.stop.set()); helper.serve()
if __name__ == "__main__": main()
