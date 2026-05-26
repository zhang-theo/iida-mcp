#!/usr/bin/env python3
"""Headless idalib worker for iida-mcp.

The stdio proxy starts this process from an MCP tool call.  It opens one
database with idapro/idalib, starts the normal iida master/worker networking,
and keeps IDA API calls on the database-owning thread.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import signal
import socket
import sys
import threading
import time
import traceback
import urllib.request
from pathlib import Path

import idapro


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class MainThreadExecutor:
    """Run IDA API callbacks on the thread that opened the database."""

    def __init__(self, timeout: float = 180.0):
        self._owner = threading.get_ident()
        self._timeout = timeout
        self._queue: queue.Queue[dict] = queue.Queue()
        self._stopping = False

    def call(self, fn, write=False):
        if threading.get_ident() == self._owner:
            return fn()
        if self._stopping:
            raise RuntimeError("idalib worker is stopping")

        task = {
            "fn": fn,
            "event": threading.Event(),
            "result": None,
            "exc": None,
        }
        self._queue.put(task)
        if not task["event"].wait(self._timeout):
            raise TimeoutError(f"IDA main thread did not run callback within {self._timeout}s")
        if task["exc"] is not None:
            raise task["exc"]
        return task["result"]

    def pump_once(self, timeout: float = 0.1) -> bool:
        try:
            task = self._queue.get(timeout=timeout)
        except queue.Empty:
            return False

        try:
            task["result"] = task["fn"]()
        except Exception as ex:
            task["exc"] = ex
        finally:
            task["event"].set()
        return True

    def stop(self):
        self._stopping = True


def write_json(path: str, data: dict) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(target)


def touch(path: str) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(str(time.time()), encoding="utf-8")


def safe_base_name(value: str) -> str:
    name = Path(value).stem or "input"
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in name)


def path_hash(value: str) -> str:
    return hashlib.sha1(str(Path(value).resolve()).lower().encode("utf-8")).hexdigest()[:12]


def default_database(input_path: str, out_dir: str) -> str:
    return str(Path(out_dir) / f"{safe_base_name(input_path)}-{path_hash(input_path)}.i64")


def remove_database_files(database: str) -> None:
    if not database:
        return
    db_path = Path(database)
    base = db_path.with_suffix("")
    for candidate in [
        db_path,
        base.with_suffix(".i64"),
        base.with_suffix(".idb"),
        base.with_suffix(".id0"),
        base.with_suffix(".id1"),
        base.with_suffix(".id2"),
        base.with_suffix(".id3"),
        base.with_suffix(".id4"),
        base.with_suffix(".nam"),
        base.with_suffix(".til"),
        db_path.with_name(db_path.name + ".tmp"),
    ]:
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def normalize_path(value: str) -> str:
    return os.path.normcase(os.path.abspath(value))


def is_ida_database(path: str) -> bool:
    return Path(path).suffix.lower() in {".i64", ".idb"}


def post_mcp(method: str, params: dict | None = None, timeout: float = 2.0) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
    }
    if params is not None:
        body["params"] = params
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:13897/mcp",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_files() -> list:
    resp = post_mcp("tools/call", {"name": "list_files", "arguments": {}}, timeout=2.0)
    content = resp.get("result", {}).get("content") or []
    if not content:
        return []
    text = content[0].get("text", "")
    rows = json.loads(text) if text else []
    return rows if isinstance(rows, list) else []


def target_registered(input_path: str) -> bool:
    wanted = normalize_path(input_path)
    try:
        for row in list_files():
            if len(row) >= 5 and normalize_path(str(row[4])) == wanted:
                return True
    except Exception:
        return False
    return False


def wait_registered(input_path: str, timeout_sec: int, executor: MainThreadExecutor, stop_event: threading.Event) -> bool:
    deadline = time.time() + max(1, timeout_sec)
    while time.time() < deadline and not stop_event.is_set():
        if target_registered(input_path):
            return True
        executor.pump_once(0.1)
    return False


def wait_tcp(host: str, port: int, timeout_sec: int, executor: MainThreadExecutor, stop_event: threading.Event) -> bool:
    deadline = time.time() + max(1, timeout_sec)
    while time.time() < deadline and not stop_event.is_set():
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            executor.pump_once(0.1)
    return False


def file_id(idb_path: str) -> str:
    return hashlib.sha256(idb_path.encode("utf-8")).hexdigest()[:8]


def infer_binary_info(path: str) -> tuple[str, int]:
    if not path:
        return "", 0
    try:
        with open(path, "rb") as fp:
            ident = fp.read(20)
    except OSError:
        return "", 0
    if len(ident) >= 20 and ident[:4] == b"\x7fELF":
        elf_class = ident[4]
        endian = "<" if ident[5] == 1 else ">" if ident[5] == 2 else ""
        if not endian:
            return "", 0
        import struct

        machine = struct.unpack_from(endian + "H", ident, 18)[0]
        arch_map = {
            3: "metapc",
            8: "mips",
            20: "ppc",
            21: "ppc",
            40: "ARM",
            62: "metapc",
            183: "arm64",
            243: "riscv",
        }
        bits = 64 if elf_class == 2 else 32 if elf_class == 1 else 0
        return arch_map.get(machine, ""), bits
    if ident[:2] == b"MZ":
        return "metapc", 0
    return "", 0


def collect_file_info(input_fallback: str = "", database_fallback: str = "") -> dict:
    import ida_ida
    import ida_nalt
    import idaapi

    is64 = ida_ida.inf_is_64bit()
    if hasattr(ida_ida, "inf_is_32bit_exactly"):
        is32 = ida_ida.inf_is_32bit_exactly()
    else:
        is32 = not is64
    input_path = ida_nalt.get_input_file_path() or input_fallback
    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or database_fallback
    if not input_path:
        input_path = database_fallback
    if not idb_path:
        idb_path = input_path
    inferred_arch, inferred_bits = infer_binary_info(input_path or input_fallback)
    arch = (ida_ida.inf_get_procname() or "").strip() or inferred_arch
    bits = 64 if is64 else (32 if is32 else 16)
    if bits == 16 and inferred_bits:
        bits = inferred_bits
    return {
        "fid": file_id(idb_path),
        "name": os.path.basename(input_path) if input_path else os.path.basename(idb_path),
        "arch": arch,
        "bits": bits,
        "path": input_path,
        "idb": idb_path,
    }


def open_database(args) -> tuple[str, str]:
    input_path = str(Path(args.input).resolve()) if args.input else ""
    database = str(Path(args.database).resolve()) if args.database else ""
    input_is_database = bool(input_path and is_ida_database(input_path) and not database)

    if input_path and not Path(input_path).exists():
        raise FileNotFoundError(f"input file not found: {input_path}")
    if input_is_database:
        if args.fresh:
            raise ValueError("fresh requires a binary input or separate --database; refusing to delete input database")
        database = input_path
        open_target = database
        open_args = None
        idapro.enable_console_messages(bool(args.verbose))
        idapro.open_database(open_target, bool(args.auto_wait), args=open_args)
        return input_path, database

    if database and args.fresh:
        remove_database_files(database)

    if database and Path(database).exists() and not args.fresh:
        open_target = database
        open_args = None
    else:
        if not input_path:
            raise ValueError("input is required when database does not exist")
        if not database:
            database = default_database(input_path, args.out_dir)
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        if args.fresh:
            remove_database_files(database)
        open_target = input_path
        open_args = "-o" + database

    idapro.enable_console_messages(bool(args.verbose))
    idapro.open_database(open_target, bool(args.auto_wait), args=open_args)
    return input_path, database


def start_iida_network(file_info: dict):
    from iida_core import tools
    from iida_core.registry import FileEntry
    from iida_core.server import MCP_PORT, McpServer, try_bind_master, try_election_lock
    from iida_core.worker import Worker

    election_lock = try_election_lock()
    become_master = election_lock is not None and try_bind_master()
    if become_master:
        server = McpServer(tools, tools.execute_tool, election_lock=election_lock)
        entry = FileEntry(
            fid=file_info["fid"],
            name=file_info["name"],
            arch=file_info["arch"],
            bits=file_info["bits"],
            path=file_info["path"],
            pid=os.getpid(),
            conn=None,
            local=True,
        )
        server.registry.register(entry)
        server.start()
        return "master", server

    if election_lock is not None:
        try:
            election_lock.close()
        except Exception:
            pass

    worker = Worker(file_info, tools.execute_tool)
    worker.start()
    return "worker", worker


def start_cache_build() -> None:
    from iida_core.cache import get_cache

    try:
        get_cache().refresh_async()
    except Exception:
        pass


def stop_iida_network(role: str, node) -> None:
    if not node:
        return
    try:
        node.stop()
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="iida-mcp idalib worker")
    parser.add_argument("--input", required=True, help="Binary path to open")
    parser.add_argument("--database", default="", help="Optional IDB path to reuse/create")
    parser.add_argument("--out-dir", default=str(ROOT / "ida-headless-checks" / "codex-auto"))
    parser.add_argument("--out-json", default="")
    parser.add_argument("--ready-file", default="")
    parser.add_argument("--stop-file", default="")
    parser.add_argument("--ready-timeout-sec", type=int, default=180)
    parser.add_argument("--keepalive-sec", type=int, default=86400)
    parser.add_argument("--auto-wait", action="store_true")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--save-on-exit", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    stop_event = threading.Event()
    result = {
        "ok": False,
        "backend": "idalib",
        "pid": os.getpid(),
        "inputFile": str(Path(args.input).resolve()),
        "database": str(Path(args.database).resolve()) if args.database else "",
        "outJson": args.out_json,
        "readyFile": args.ready_file,
        "stopFile": args.stop_file,
        "mcpUrl": "http://127.0.0.1:13897/mcp",
        "role": "",
        "errors": [],
    }

    def request_stop(signum=None, frame=None):
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    executor = MainThreadExecutor()
    role = ""
    node = None
    opened = False

    try:
        from iida_core.thread_safe import clear_executor, set_executor
        from iida_core import tools

        set_executor(executor)
        input_path, database = open_database(args)
        opened = True
        result["database"] = database
        file_info = collect_file_info(input_path, database)
        tools.set_runtime_context(
            input_path=file_info["path"],
            idb_path=file_info["idb"],
            proc=file_info["arch"],
            bits=file_info["bits"],
        )
        result["file"] = file_info

        role, node = start_iida_network(file_info)
        result["role"] = role
        start_cache_build()

        if not wait_tcp("127.0.0.1", 13897, args.ready_timeout_sec, executor, stop_event):
            raise TimeoutError(f"iida-mcp HTTP endpoint was not ready within {args.ready_timeout_sec}s")
        if not wait_registered(file_info["path"], args.ready_timeout_sec, executor, stop_event):
            raise TimeoutError(f"target did not register within {args.ready_timeout_sec}s: {file_info['path']}")

        result["ok"] = True
        result["readyAfterSec"] = None
        write_json(args.out_json, result)
        touch(args.ready_file)

        ready_at = time.time()
        while not stop_event.is_set():
            if args.stop_file and Path(args.stop_file).exists():
                break
            if args.keepalive_sec > 0 and time.time() - ready_at >= args.keepalive_sec:
                break
            executor.pump_once(0.1)

        return 0
    except Exception:
        result["errors"].append(traceback.format_exc())
        write_json(args.out_json, result)
        touch(args.ready_file)
        return 1
    finally:
        executor.stop()
        stop_iida_network(role, node)
        try:
            from iida_core.thread_safe import clear_executor
            from iida_core import tools

            tools.clear_runtime_context()
            clear_executor()
        except Exception:
            pass
        if opened:
            try:
                idapro.close_database(bool(args.save_on_exit))
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
