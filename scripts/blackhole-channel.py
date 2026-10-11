#!/usr/bin/env python3
"""Measure blip-bridged under a silent TCP blackhole.

Driven by scripts/blackhole-channel, which stands up the netns, sshd, and
daemon. This process is the unprivileged client (same uid as the daemon).
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

WORKDIR = Path(os.environ["BH_WORKDIR"])
SOCK = os.environ["BH_SOCK"]
MAC_IP = os.environ["BH_MAC_IP"]
KEY = os.environ["BH_KEY"]
USER = os.environ["BH_USER"]
SHORT_SECS = int(os.environ["BH_SHORT"])
LONG_SECS = int(os.environ["BH_LONG"])
ROOT = Path(os.environ["BH_ROOT"])

# Match collector.ts (15 s) and blip-bridged (12 s request deadline).
WARM_TIMEOUT = 15.0
ONESHOT_TIMEOUT = 15.0
BAR_RESTART_S = 30.0
HANG_S = 25.0  # anything longer than warm+slack is a hang for the report

REQUEST = json.dumps({"argv": ["--json", "recent", "5"]}).encode() + b"\n"


def daemon_pid() -> int | None:
    try:
        return int((WORKDIR / "daemon.pid").read_text().strip())
    except (OSError, ValueError):
        return None


def daemon_alive() -> bool:
    """/proc, not kill(pid,0): the poller is unprivileged and the recorded
    pid may be the root sudo wrapper, which returns EPERM and looks dead."""
    pid = daemon_pid()
    if pid is None:
        return False
    return Path(f"/proc/{pid}").exists()


def blackhole(on: bool) -> None:
    helper = WORKDIR / ("bh-on" if on else "bh-off")
    subprocess.run(["sudo", str(helper)], check=True)


def _read_frame(conn: socket.socket, deadline: float) -> bytes:
    buf = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("warm socket deadline")
        conn.settimeout(remaining)
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
        nl = buf.find(b"\n")
        if nl < 0:
            continue
        try:
            meta = json.loads(buf[:nl])
        except json.JSONDecodeError:
            continue
        want = meta.get("len")
        if isinstance(want, int) and len(buf) >= nl + 1 + want:
            return bytes(buf[: nl + 1 + want])
    if not buf:
        raise ConnectionError("daemon closed without a frame")
    return bytes(buf)


def warm_once() -> dict:
    """One request on the unix socket. Does not fall back."""
    t0 = time.monotonic()
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(WARM_TIMEOUT)
        conn.connect(SOCK)
        conn.sendall(REQUEST)
        raw = _read_frame(conn, t0 + WARM_TIMEOUT)
        conn.close()
        head = raw.split(b"\n", 1)[0]
        meta = json.loads(head)
        ms = (time.monotonic() - t0) * 1000
        if meta.get("fallback") is True:
            return {
                "path": "fallback",
                "ms": ms,
                "ok": False,
                "fell_back": True,
                "reason": raw.split(b"\n", 1)[-1].decode("utf-8", "replace").strip(),
            }
        if meta.get("status") == 0:
            return {"path": "warm", "ms": ms, "ok": True, "reason": ""}
        return {"path": "warm-err", "ms": ms, "ok": False, "reason": f"status {meta.get('status')}"}
    except Exception as e:
        return {"path": "warm-err", "ms": (time.monotonic() - t0) * 1000, "ok": False, "reason": f"{type(e).__name__}: {e}"}


def oneshot_once() -> dict:
    """The shim's one-shot ssh, same flags, dedicated key."""
    t0 = time.monotonic()
    cmd = [
        "ssh", "-i", KEY, "-o", "IdentitiesOnly=yes",
        "-o", "ControlMaster=auto",
        "-o", f"ControlPath={os.path.expanduser('~')}/.ssh/cm-blip-%r@%h:%p",
        "-o", "ControlPersist=10m",
        "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
        "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
        "--", f"{USER}@{MAC_IP}", "imsg --json recent 5",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=ONESHOT_TIMEOUT)
        ms = (time.monotonic() - t0) * 1000
        err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        tail = err[-1] if err else ""
        if r.returncode == 0:
            return {"path": "oneshot", "ms": ms, "ok": True, "reason": ""}
        return {"path": "oneshot-err", "ms": ms, "ok": False, "reason": f"exit {r.returncode} {tail}"}
    except subprocess.TimeoutExpired:
        return {"path": "oneshot-hang", "ms": (time.monotonic() - t0) * 1000, "ok": False, "reason": "oneshot exceeded 15s"}
    except Exception as e:
        return {"path": "oneshot-err", "ms": (time.monotonic() - t0) * 1000, "ok": False, "reason": f"{type(e).__name__}: {e}"}


def mux_state() -> dict:
    """What ControlMaster sockets and ssh children look like right now."""
    home = Path.home()
    socks = [p.name for p in home.joinpath(".ssh").glob("cm-blip-*")]
    try:
        ps = subprocess.check_output(["ps", "-u", USER, "-o", "pid,cmd", "--no-headers"], text=True)
    except subprocess.CalledProcessError:
        ps = ""
    ssh = [ln.strip() for ln in ps.splitlines() if "ssh" in ln and "blackhole" not in ln]
    return {"control_sockets": socks, "ssh": ssh}


def collector_once() -> dict:
    """Warm, then one-shot on any fault — collector.ts / bridgeRun."""
    t0 = time.monotonic()
    warm = warm_once()
    if warm["ok"]:
        warm["total_ms"] = warm["ms"]
        return warm
    one = oneshot_once()
    one["total_ms"] = (time.monotonic() - t0) * 1000
    one["warm"] = warm
    one["fell_back"] = True
    one["warm_ms"] = warm["ms"]
    one["mux"] = mux_state()
    return one


def restart_daemon() -> None:
    subprocess.run(["sudo", str(WORKDIR / "bh-restart-daemon")], check=True)
    for _ in range(50):
        if Path(SOCK).is_socket() and daemon_alive():
            return
        time.sleep(0.1)


class Watch:
    def __init__(self) -> None:
        self.died_at: float | None = None
        self.restarted_at: float | None = None
        self.saw_dead = False

    def tick(self, t0: float) -> None:
        if daemon_alive():
            return
        if not self.saw_dead:
            self.saw_dead = True
            self.died_at = time.monotonic() - t0
            # Record only. Restarting here would sleep 30 s inside the
            # sample and kill a daemon the poller merely could not signal.


def summarize(name: str, polls: list[dict], watch: Watch, outage_s: float) -> dict:
    totals = [p.get("total_ms", p["ms"]) for p in polls]
    hung = [p for p in polls if p.get("total_ms", p["ms"]) >= HANG_S * 1000 or p["path"] == "oneshot-hang"]
    fallbacks = [p for p in polls if p.get("fell_back") or p["path"] == "fallback"]
    first_fallback = None
    if fallbacks:
        p = fallbacks[0]
        # When the warm side gave up, not when the oneshot finished.
        warm_ms = p.get("warm_ms") or p.get("warm", {}).get("ms") or p["ms"]
        first_fallback = p.get("at_s", 0) - (p.get("total_ms", p["ms"]) - warm_ms) / 1000
        if first_fallback < 0:
            first_fallback = p.get("at_s")
    worst = max(totals) if totals else None
    errors = [p for p in polls if not p.get("ok") and p["path"] not in ("fallback", "oneshot-err")]
    # oneshot-err during the outage is the expected offline
    return {
        "name": name,
        "outage_s": outage_s,
        "polls": len(polls),
        "first_fallback_s": first_fallback,
        "worst_ms": worst,
        "hangs": len(hung),
        "daemon_died_s": watch.died_at,
        "daemon_restarted_s": watch.restarted_at,
        "ok_count": sum(1 for p in polls if p.get("ok")),
        "errors": [p["reason"] for p in errors if p.get("reason")],
        "paths": [p["path"] for p in polls],
        "latencies_ms": [round(t, 1) for t in totals],
    }


def run_outage(name: str, seconds: float) -> tuple[dict, list[dict], dict]:
    """Blackhole for `seconds`, poll throughout, then restore and recover."""
    watch = Watch()
    polls: list[dict] = []
    t0 = time.monotonic()
    blackhole(True)
    # Lift on a timer, not after the in-flight poll returns — a 5 s outage
    # would otherwise stay DROPped for the whole 12 s deadline.
    def _lift() -> None:
        remaining = seconds - (time.monotonic() - t0)
        if remaining > 0:
            time.sleep(remaining)
        blackhole(False)
        print(f"  blackhole lifted at {time.monotonic()-t0:.2f}s", flush=True)
    threading.Thread(target=_lift, daemon=True).start()
    while time.monotonic() - t0 < seconds:
        p = collector_once()
        p["at_s"] = time.monotonic() - t0
        polls.append(p)
        watch.tick(t0)
        # Don't sleep: the poll itself is the sample. A 12 s deadline is
        # the thing we are measuring; padding would hide it.
    blackhole(False)
    outage = summarize(name, polls, watch, seconds)

    # Recovery: keep polling until a warm hit, or 45 s.
    rec: list[dict] = []
    r0 = time.monotonic()
    warm_again_s = None
    while time.monotonic() - r0 < 45:
        p = collector_once()
        p["at_s"] = time.monotonic() - r0
        rec.append(p)
        if p["path"] == "warm" and p.get("ok"):
            warm_again_s = p["at_s"]
            # one more to confirm it stays warm
            p2 = collector_once()
            rec.append(p2)
            break
        watch.tick(r0)
    recovery = {
        "warm_again_s": warm_again_s,
        "warm_again_ms": rec[-1].get("total_ms", rec[-1]["ms"]) if rec and rec[-1]["path"] == "warm" else None,
        "polls": [p["path"] for p in rec],
        "latencies_ms": [round(p.get("total_ms", p["ms"]), 1) for p in rec],
        "daemon_died_s": watch.died_at,
        "daemon_restarted_s": watch.restarted_at,
    }
    return outage, polls, recovery


def baseline(n: int = 8) -> dict:
    # First hit pays spawn; drop it from the warm average.
    samples = [collector_once() for _ in range(n)]
    warm = [p for p in samples if p["path"] == "warm" and p.get("ok")]
    if len(warm) < 2:
        raise SystemExit(f"baseline never warmed: {[p['path']+' '+p.get('reason','') for p in samples]}")
    # a dedicated one-shot with the channel already up (ControlMaster mux)
    ones = [oneshot_once() for _ in range(3)]
    return {
        "warm_ms": [round(p["ms"], 1) for p in warm[1:]],
        "warm_avg_ms": round(sum(p["ms"] for p in warm[1:]) / (len(warm) - 1), 1),
        "first_ms": round(samples[0]["ms"], 1),
        "oneshot_ms": [round(p["ms"], 1) for p in ones],
        "oneshot_avg_ms": round(sum(p["ms"] for p in ones) / len(ones), 1) if ones else None,
        "paths": [p["path"] for p in samples],
    }


def print_table(base: dict, short: dict | None, short_rec: dict | None,
                long: dict, long_rec: dict) -> None:
    def cell(v):
        if v is None:
            return "—"
        if isinstance(v, float):
            return f"{v:.1f}"
        return str(v)

    rows = [
        ("metric", "baseline", "5 s DROP" if SHORT_SECS else "short", "60 s DROP" if LONG_SECS >= 60 else f"{LONG_SECS} s DROP"),
        ("warm poll (ms)", cell(base["warm_avg_ms"]), "—", "—"),
        ("one-shot poll (ms)", cell(base["oneshot_avg_ms"]), "—", "—"),
    ]
    def add(label, s, l):
        rows.append((label, "—", cell(s), cell(l)))

    add("first fallback (s into outage)",
        short["first_fallback_s"] if short else None,
        long["first_fallback_s"])
    add("worst poll (ms)",
        short["worst_ms"] if short else None,
        long["worst_ms"])
    add("hangs (poll ≥ 25 s)",
        short["hangs"] if short else None,
        long["hangs"])
    add("daemon died (s into outage)",
        short["daemon_died_s"] if short else None,
        long["daemon_died_s"])
    add("daemon restarted (s)",
        short["daemon_restarted_s"] if short else None,
        long["daemon_restarted_s"])
    add("time back to warm (s after restore)",
        short_rec["warm_again_s"] if short_rec else None,
        long_rec["warm_again_s"])
    add("warm latency after restore (ms)",
        short_rec["warm_again_ms"] if short_rec else None,
        long_rec["warm_again_ms"])

    widths = [max(len(str(r[i])) for r in rows) for i in range(4)]
    for i, r in enumerate(rows):
        line = "  ".join(str(c).ljust(widths[j]) for j, c in enumerate(r))
        print(line)
        if i == 0:
            print("  ".join("-" * widths[j] for j in range(4)))


def main() -> int:
    print(f"socket {SOCK}", flush=True)
    print("warming the channel…", flush=True)
    base = baseline()
    print(f"baseline warm avg {base['warm_avg_ms']} ms  (first {base['first_ms']} ms); "
          f"one-shot avg {base['oneshot_avg_ms']} ms", flush=True)
    print(f"daemon alive={daemon_alive()} pid={daemon_pid()}", flush=True)
    print(f"mux after baseline {mux_state()}", flush=True)

    print("\n--- probes during DROP (not part of the timed outages) ---", flush=True)
    blackhole(True)
    for label, extra in (
        ("connect-timeout-only", ["-o", "ControlMaster=no", "-o", "ConnectTimeout=5"]),
        ("shim-mux", ["-o", "ControlMaster=auto",
                      "-o", f"ControlPath={os.path.expanduser('~')}/.ssh/cm-blip-%r@%h:%p",
                      "-o", "ControlPersist=10m", "-o", "ConnectTimeout=5"]),
    ):
        pt0 = time.monotonic()
        try:
            r = subprocess.run(
                ["ssh", "-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                 *extra, "--", f"{USER}@{MAC_IP}", "imsg --json recent 5"],
                capture_output=True, timeout=12)
            print(f"  probe {label}: {(time.monotonic()-pt0)*1000:.0f}ms exit={r.returncode} "
                  f"{(r.stderr or b'').decode('utf-8','replace').strip().splitlines()[-1:]}",
                  flush=True)
        except subprocess.TimeoutExpired:
            print(f"  probe {label}: hung >12s mux={mux_state()}", flush=True)
    blackhole(False)
    # Re-warm so the timed outages start from a live channel.
    collector_once()
    print(f"rewarmed; mux {mux_state()}", flush=True)

    short = short_rec = None
    if SHORT_SECS > 0:
        print(f"\n--- {SHORT_SECS}s silent DROP ---", flush=True)
        short, short_polls, short_rec = run_outage("short", SHORT_SECS)
        print(json.dumps({"outage": short, "recovery": short_rec}, indent=2), flush=True)

    print(f"\n--- {LONG_SECS}s silent DROP ---", flush=True)
    long, _long_polls, long_rec = run_outage("long", LONG_SECS)
    print(json.dumps({"outage": long, "recovery": long_rec}, indent=2), flush=True)

    print("\n=== results ===")
    print_table(base, short, short_rec, long, long_rec)

    report = {
        "simulated": True,
        "not_a_real_mac": True,
        "blackhole": "iptables DROP on the ssh peer (silent; no RST/EOF)",
        "baseline": base,
        "short": short,
        "short_recovery": short_rec,
        "long": long,
        "long_recovery": long_rec,
        "passed_as_is": None,
    }
    # Pass: no hang, fallback within one deadline on the long outage,
    # warm again after restore. A 5 s outage may never fall back (deadline
    # is 12 s) — that is success, not failure.
    hangs = (short or {}).get("hangs", 0) + long["hangs"]
    long_ok = long["first_fallback_s"] is not None and long["first_fallback_s"] <= 13
    recovered = long_rec["warm_again_s"] is not None
    report["passed_as_is"] = hangs == 0 and long_ok and recovered
    report_path = Path("/tmp/blip-blackhole-report.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"report {report_path}")
    print(f"\npassed_as_is={report['passed_as_is']}  hangs={hangs}  "
          f"long_fallback_s={long['first_fallback_s']}  "
          f"warm_again_s={long_rec['warm_again_s']}")
    return 0 if report["passed_as_is"] else 1


if __name__ == "__main__":
    sys.exit(main())
