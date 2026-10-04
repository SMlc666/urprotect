#!/usr/bin/env python3
"""Run one real-sample worker as a Linux child subreaper.

A process session/group is only a signal-delivery aid: descendants can call
setsid() and escape it. This supervisor instead becomes their Linux
PR_SET_CHILD_SUBREAPER adoption point, records every observed descendant, and
keeps rescanning/reaping until the tree is empty or a bounded cleanup deadline
expires. Named bionic containers are recorded separately and verified absent.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
from typing import Any

PR_SET_CHILD_SUBREAPER = 36
TERM_GRACE_SECONDS = 5.0
KILL_GRACE_SECONDS = 2.0
CONTAINER_CLEANUP_SECONDS = 6.0


def _enable_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _proc_row(pid: int) -> tuple[int, str, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    end = raw.rfind(")")
    if end < 0:
        return None
    fields = raw[end + 2 :].split()
    # fields start at proc stat field 3: state, ppid, ..., starttime (field 22).
    if len(fields) < 20:
        return None
    try:
        return int(fields[1]), fields[0], int(fields[19])
    except ValueError:
        return None


def _process_table() -> dict[int, tuple[int, str, int]]:
    table: dict[int, tuple[int, str, int]] = {}
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise RuntimeError(f"could not scan /proc: {error}") from error
    with entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            row = _proc_row(pid)
            if row is not None:
                table[pid] = row
    return table


def _descendants(root_pid: int) -> dict[int, int]:
    table = _process_table()
    children: dict[int, list[int]] = {}
    for pid, (parent, _state, start_time) in table.items():
        children.setdefault(parent, []).append(pid)
    found: dict[int, int] = {}
    pending = list(children.get(root_pid, ()))
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        row = table.get(pid)
        if row is None:
            continue
        found[pid] = row[2]
        pending.extend(children.get(pid, ()))
    return found


def _append_pid(registry: Path, pid: int, start_time: int) -> None:
    registry.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(registry, flags, 0o600)
    try:
        os.write(descriptor, f"{pid}\t{start_time}\n".encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _record_tree(root_pid: int, registry: Path, recorded: set[tuple[int, int]]) -> dict[int, int]:
    current = _descendants(root_pid)
    for pid, start_time in current.items():
        identity = (pid, start_time)
        if identity not in recorded:
            _append_pid(registry, pid, start_time)
            recorded.add(identity)
    return current


def _alive(pid: int, expected_start: int | None = None) -> bool:
    row = _proc_row(pid)
    if row is None or row[1] == "Z":
        return False
    return expected_start is None or row[2] == expected_start


def _signal_tree(root_pid: int, signum: int, registry: Path, recorded: set[tuple[int, int]]) -> dict[int, int]:
    current = _record_tree(root_pid, registry, recorded)
    for pid, start_time in current.items():
        if not _alive(pid, start_time):
            continue
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass
        except PermissionError:
            # The final process-tree check will turn a surviving process into a
            # bounded cleanup failure rather than treating a denied signal as success.
            pass
    return current


def _reap_adopted_children(root_pid: int, protected_pid: int | None) -> None:
    table = _process_table()
    for pid, (parent, state, _start_time) in table.items():
        if parent != root_pid or pid == protected_pid or state != "Z":
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, ProcessLookupError):
            pass


def _live_descendants(
    root_pid: int,
    registry: Path,
    recorded: set[tuple[int, int]],
) -> dict[int, int]:
    current = _record_tree(root_pid, registry, recorded)
    return {pid: start for pid, start in current.items() if _alive(pid, start)}


def _load_resource_rows(registry: Path | None) -> list[dict[str, Any]]:
    if registry is None or not registry.exists():
        return []
    if registry.is_symlink() or not registry.is_file():
        raise RuntimeError("worker container/image registry must be a regular non-symlink file")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(registry.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"worker container/image registry line {line_number} is malformed: {error}") from error
        kind = row.get("kind", "container") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or kind not in {"container", "image"}
            or not isinstance(row.get("name"), str)
            or not row["name"]
            or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for character in row["name"])
        ):
            raise RuntimeError(f"worker container/image registry line {line_number} has an invalid resource")
        if row.get("state", "registered") not in {"registered", "removed"}:
            raise RuntimeError(f"worker container/image registry line {line_number} has an invalid state")
        rows.append({**row, "kind": kind})
    return rows


def _active_resource_rows(registry: Path | None) -> list[dict[str, Any]]:
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for row in _load_resource_rows(registry):
        key = (row["kind"], row["name"])
        if row.get("state", "registered") == "removed":
            latest.pop(key, None)
        else:
            latest[key] = row
    return list(latest.values())


def _inspect_absent(command: list[str], name: str, deadline: float, kind: str = "container") -> bool:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    inspect_command = [*command]
    if kind == "image":
        inspect_command.extend(("image", "inspect", "--format", "{{json .}}", name))
    else:
        inspect_command.extend(("inspect", "--format", "{{json .State}}", name))
    try:
        result = subprocess.run(
            inspect_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=min(1.5, remaining),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode == 0:
        return False
    details = (result.stdout + result.stderr).decode("utf-8", errors="replace").lower()
    markers = (
        ("no such image", "image not found", "no such object")
        if kind == "image"
        else ("no such container", "container not found", "no such object")
    )
    return any(marker in details for marker in markers)


def _append_resource_state(registry: Path | None, name: str, kind: str, state: str) -> None:
    if registry is None:
        return
    if registry.is_symlink() or (registry.exists() and not registry.is_file()):
        raise RuntimeError("worker container/image registry is not a regular file")
    registry.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(registry, flags, 0o600)
    try:
        payload = json.dumps({"kind": kind, "name": name, "state": state}, sort_keys=True) + "\n"
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reap_named_containers(registry: Path | None) -> list[str]:
    """Reap registered containers and transient images before root cleanup."""
    try:
        rows = _active_resource_rows(registry)
    except (OSError, UnicodeError, RuntimeError) as error:
        return [str(error)]
    if not rows:
        return []
    try:
        command = shlex.split(os.environ.get("BIONIC_CONTAINER_RUNTIME", "docker"))
    except ValueError as error:
        return [f"invalid BIONIC_CONTAINER_RUNTIME: {error}"]
    if not command:
        return ["BIONIC_CONTAINER_RUNTIME resolved to an empty command"]
    deadline = time.monotonic() + CONTAINER_CLEANUP_SECONDS
    errors: list[str] = []
    for row in sorted(rows, key=lambda item: (item["kind"], item["name"])):
        name = row["name"]
        kind = row["kind"]
        label = f"{kind} {name}"
        if _inspect_absent(command, name, deadline, kind):
            try:
                _append_resource_state(registry, name, kind, "removed")
            except (OSError, RuntimeError) as error:
                errors.append(f"{label} absence was verified but registry could not be marked removed: {error}")
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            errors.append(f"{kind} cleanup deadline expired before removing {name}")
            continue
        remove_command = [*command, "image", "rm", "--force", name] if kind == "image" else [*command, "rm", "--force", name]
        try:
            removed = subprocess.run(
                remove_command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=min(2.0, remaining),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(f"could not remove named {label}: {error}")
            continue
        if removed.returncode != 0 and not _inspect_absent(command, name, deadline, kind):
            detail = (removed.stderr + removed.stdout).decode("utf-8", errors="replace").strip()
            errors.append(f"Docker removal did not remove {label}: {detail or removed.returncode}")
            continue
        if not _inspect_absent(command, name, deadline, kind):
            errors.append(f"named {label} remains or its absence could not be verified")
            continue
        try:
            _append_resource_state(registry, name, kind, "removed")
        except (OSError, RuntimeError) as error:
            errors.append(f"{label} was removed but registry could not be marked removed: {error}")
    return errors


def _cleanup_tree(
    root_pid: int,
    process_pid: int | None,
    pid_registry: Path,
    recorded: set[tuple[int, int]],
) -> bool:
    _signal_tree(root_pid, signal.SIGTERM, pid_registry, recorded)
    term_deadline = time.monotonic() + TERM_GRACE_SECONDS
    while time.monotonic() < term_deadline:
        live = _live_descendants(root_pid, pid_registry, recorded)
        _reap_adopted_children(root_pid, process_pid)
        if not live:
            return True
        time.sleep(0.05)

    _signal_tree(root_pid, signal.SIGKILL, pid_registry, recorded)
    kill_deadline = time.monotonic() + KILL_GRACE_SECONDS
    while time.monotonic() < kill_deadline:
        live = _live_descendants(root_pid, pid_registry, recorded)
        _reap_adopted_children(root_pid, process_pid)
        if not live:
            return True
        time.sleep(0.05)
    return not _live_descendants(root_pid, pid_registry, recorded)


def run_worker(command: list[str], pid_registry: Path, container_registry: Path | None) -> int:
    try:
        _enable_subreaper()
        _process_table()
        own = _proc_row(os.getpid())
        if own is None:
            raise RuntimeError("could not identify the worker supervisor in /proc")
        recorded: set[tuple[int, int]] = set()
        _append_pid(pid_registry, os.getpid(), own[2])
        recorded.add((os.getpid(), own[2]))
    except (OSError, RuntimeError) as error:
        print(f"worker supervisor setup failed: {error}", file=sys.stderr)
        return 125

    requested_signal: int | None = None

    def request_shutdown(signum: int, _frame: Any) -> None:
        nonlocal requested_signal
        requested_signal = signum

    old_handlers = {
        signum: signal.signal(signum, request_shutdown)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }
    try:
        process = subprocess.Popen(command, start_new_session=True, close_fds=True)
    except OSError as error:
        print(f"worker command could not start: {error}", file=sys.stderr)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        return 127

    child_pgid = process.pid
    interrupted = False
    leaked_descendants = False
    term_deadline: float | None = None
    kill_deadline: float | None = None
    try:
        while process.poll() is None:
            _record_tree(os.getpid(), pid_registry, recorded)
            if requested_signal is not None and not interrupted:
                interrupted = True
                term_deadline = time.monotonic() + TERM_GRACE_SECONDS
                try:
                    os.killpg(child_pgid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
            # A detached grandchild is adopted by this subreaper when its parent
            # exits, so a full rescan still sees it even after setsid().
            if interrupted:
                _signal_tree(os.getpid(), signal.SIGTERM, pid_registry, recorded)
                if term_deadline is not None and time.monotonic() >= term_deadline:
                    _signal_tree(os.getpid(), signal.SIGKILL, pid_registry, recorded)
                    if kill_deadline is None:
                        kill_deadline = time.monotonic() + KILL_GRACE_SECONDS
                    if time.monotonic() >= kill_deadline:
                        break
            _reap_adopted_children(os.getpid(), process.pid)
            time.sleep(0.05)

        worker_status = process.poll()
        if worker_status is None:
            # A process stuck in an uninterruptible kernel state outlived the
            # bounded kill window. Leave its identity in the registry so the
            # parent refuses to remove the worker root.
            return 1
        worker_status = process.wait()
        # The direct command can exit while a daemonized descendant remains.
        # Treat that as a leaked worker, terminate it within a fixed budget, and
        # report nonzero even if the original command returned success.
        leaked_descendants = bool(_live_descendants(os.getpid(), pid_registry, recorded))
        if leaked_descendants:
            _cleanup_tree(os.getpid(), process.pid, pid_registry, recorded)
        else:
            _reap_adopted_children(os.getpid(), process.pid)

        tree_clean = not _live_descendants(os.getpid(), pid_registry, recorded)
        container_errors = reap_named_containers(container_registry)
        if container_errors:
            for message in container_errors:
                print(f"worker container cleanup failed: {message}", file=sys.stderr)
        if interrupted:
            return 128 + (requested_signal or signal.SIGTERM)
        if not tree_clean or container_errors or leaked_descendants:
            return 1
        return worker_status if worker_status >= 0 else 128 - worker_status
    except RuntimeError as error:
        print(f"worker process-tree inspection failed: {error}", file=sys.stderr)
        return 1
    finally:
        # Reap adopted zombies and leave the supervisor alive until every live
        # descendant has been proven gone. A failed proof propagates as failure.
        _reap_adopted_children(os.getpid(), process.pid)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid-registry", type=Path)
    parser.add_argument("--container-registry", type=Path)
    parser.add_argument("--reap-containers", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.reap_containers is not None:
        errors = reap_named_containers(args.reap_containers)
        for error in errors:
            print(error, file=sys.stderr)
        return 1 if errors else 0
    if args.pid_registry is None:
        parser.error("--pid-registry is required to run a worker")
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a worker command is required after --")
    return run_worker(command, args.pid_registry, args.container_registry)


if __name__ == "__main__":
    raise SystemExit(main())
