#!/usr/bin/env python3
"""Pulse — a local macOS performance monitor.

Collects CPU, memory, temperature, GPU, disk, network, battery and process data
with built-in tools (no sudo, no pip installs), detects problems, and serves a
dashboard at http://127.0.0.1:8765.
"""
import json
import os
import plistlib
import pwd
import re
import signal
import socket
import statistics
import subprocess
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import fans as fanctl
import storage

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "probe")
DATA_DIR = os.environ.get("PULSE_DATA") or os.path.expanduser("~/Library/Application Support/Pulse")
os.makedirs(DATA_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
PORT = int(os.environ.get("PULSE_PORT", "8765"))
HOME = os.path.expanduser("~")
MY_UID = os.getuid()

SAMPLE_EVERY = 2.0          # seconds between samples while the dashboard is visible
IDLE_SAMPLE_EVERY = 10.0    # seconds between samples in the background (flags + alerts keep working)
HISTORY_SECONDS = 60 * 60   # keep one hour of samples in memory
NCPU = os.cpu_count() or 1

SEVERITY_RANK = {"info": 0, "warning": 1, "serious": 2, "critical": 3}


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace").stdout
    except Exception:
        return ""


def run_both(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.stdout + p.stderr
    except Exception:
        return ""


# --------------------------------------------------------------------------- settings
class Settings:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"ignored": [], "notify": True}
        try:
            with open(SETTINGS_FILE) as f:
                self.data.update(json.load(f))
        except Exception:
            pass

    def save(self):
        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump(self.data, f, indent=2)
        except Exception:
            pass

    def ignored(self):
        with self.lock:
            return set(self.data["ignored"])

    def set_ignored(self, key, on):
        with self.lock:
            s = set(self.data["ignored"])
            (s.add if on else s.discard)(key)
            self.data["ignored"] = sorted(s)
            self.save()

    def set_notify(self, on):
        with self.lock:
            self.data["notify"] = bool(on)
            self.save()


SETTINGS = Settings()
FANS = fanctl.FanController(SETTINGS)


# --------------------------------------------------------------------------- helpers
_user_cache = {}


def username(uid):
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _user_cache[uid] = str(uid)
    return _user_cache[uid]


def parse_cputime(s):
    """ps 'time' field: [dd-]hh:mm:ss.cc or mm:ss.cc -> seconds."""
    try:
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = [float(p) for p in s.split(":")]
        sec = 0.0
        for p in parts:
            sec = sec * 60 + p
        return days * 86400 + sec
    except Exception:
        return 0.0


def parse_etime(s):
    try:
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        sec = 0
        for p in s.split(":"):
            sec = sec * 60 + int(p)
        return days * 86400 + sec
    except Exception:
        return 0


def app_name(path):
    """'/Applications/Foo.app/Contents/MacOS/bar' -> 'Foo'; plain binaries -> basename."""
    i = path.find(".app/")
    if i != -1:
        return os.path.basename(path[:i])
    return os.path.basename(path) or path


SYSTEM_PREFIXES = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/",
                   "/usr/lib/", "/Library/Apple/", "/private/var/run/com.apple.security.cryptexd/",
                   "/System/Volumes/Preboot/Cryptexes/")

RISKY_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/",
                  os.path.join(HOME, "Downloads") + "/")


def is_system_path(path):
    return path.startswith(SYSTEM_PREFIXES)


def is_risky_path(path):
    if path.startswith(RISKY_PREFIXES):
        return True
    # Hidden folder directly in a place programs don't normally live, e.g. ~/Library/.x/agent
    if re.search(r"/Library/(Application Support|Caches|Containers)/\.[^/]+/", path):
        return True
    return False


def is_sim(path):
    return "CoreSimulator" in path or "SimulatorRuntime" in path or path.endswith("_sim")


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return ("%.0f %s" if unit in ("B", "KB") else "%.1f %s") % (n, unit)
        n /= 1024


# --------------------------------------------------------------------------- code signing
class Signatures:
    """Background, cached `codesign` lookups for non-system executables."""

    def __init__(self):
        self.cache = {}
        self.queue = deque()
        self.queued = set()
        self.lock = threading.Lock()
        threading.Thread(target=self._worker, daemon=True).start()

    def get(self, path):
        with self.lock:
            if path in self.cache:
                return self.cache[path]
            if path not in self.queued and path.startswith("/"):
                self.queued.add(path)
                self.queue.append(path)
        return None

    def _worker(self):
        while True:
            path = None
            with self.lock:
                if self.queue:
                    path = self.queue.popleft()
            if not path:
                time.sleep(0.5)
                continue
            out = run_both(["codesign", "-dv", "--verbose=2", path], timeout=8)
            info = {"signed": True, "adhoc": False, "apple": False, "team": None, "authority": None}
            if "not signed at all" in out:
                info["signed"] = False
            elif "No such file" in out or not out.strip():
                info = {"signed": None, "adhoc": False, "apple": False, "team": None, "authority": None}
            else:
                if "Signature=adhoc" in out:
                    info["adhoc"] = True
                m = re.search(r"^Authority=(.+)$", out, re.M)
                if m:
                    info["authority"] = m.group(1).strip()
                    info["apple"] = m.group(1).strip() in ("Software Signing", "Apple Mac OS Application Signing")
                m = re.search(r"^TeamIdentifier=(.+)$", out, re.M)
                if m and m.group(1).strip() != "not set":
                    info["team"] = m.group(1).strip()
            with self.lock:
                self.cache[path] = info
            time.sleep(0.05)


SIGS = Signatures()


# --------------------------------------------------------------------------- collector
class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.samples = deque(maxlen=int(HISTORY_SECONDS / SAMPLE_EVERY))
        self.prev_cpu = None
        self.prev_net = None
        self.prev_disk = None
        self.prev_t = None
        self.procs = []
        self.apps = []
        self.proc_hist = {}          # pid -> deque[(t, cpu%, rss)]
        self.prev_cputime = {}       # pid -> (t, cputime)
        self.seen_paths = set()
        self.warm = False
        self.ports = []
        self.startup = []
        self.battery = {}
        self.thermal_limit = 100
        self.disk_usage = {}
        self.proc_count = 0
        self.flags = {}              # key -> flag dict
        self.events = deque(maxlen=300)
        self.spikes = {}             # key -> expiry
        self.notified = {}
        self._prev_stuck = set()
        self.notify_queue = deque(maxlen=20)
        self.probe_proc = None
        self.last_client = 0
        self.last_run = {}
        self.was_active = False
        self.pstate = {}
        self.procs_fresh = False
        self.self_prev = None
        self.overhead = {"cpu": None, "rss": None}
        self.meta = self._meta()
        self.started = time.time()
        self.tick = 0

    # ---------------- static info
    def _meta(self):
        chip = run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
        model = run(["sysctl", "-n", "hw.model"]).strip()
        ver = run(["sw_vers", "-productVersion"]).strip()
        pcores = run(["sysctl", "-n", "hw.perflevel0.logicalcpu"]).strip()
        ecores = run(["sysctl", "-n", "hw.perflevel1.logicalcpu"]).strip()
        boot = run(["sysctl", "-n", "kern.boottime"])
        m = re.search(r"sec = (\d+)", boot)
        return {
            "host": socket.gethostname().replace(".local", ""),
            "chip": chip, "model": model, "macos": ver, "ncpu": NCPU,
            "pcores": int(pcores) if pcores.isdigit() else None,
            "ecores": int(ecores) if ecores.isdigit() else None,
            "boot": int(m.group(1)) if m else None,
            "interval": SAMPLE_EVERY, "uid": MY_UID,
        }

    # ---------------- collectors
    # One long-lived native probe answers requests over a pipe: no process spawning per sample.
    def _ask(self, cmd):
        for attempt in (1, 2):
            try:
                if self.probe_proc is None or self.probe_proc.poll() is not None:
                    self.probe_proc = subprocess.Popen([PROBE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                       text=True, bufsize=1)
                self.probe_proc.stdin.write(cmd + "\n")
                self.probe_proc.stdin.flush()
                return json.loads(self.probe_proc.stdout.readline())
            except Exception:
                try:
                    self.probe_proc.kill()
                except Exception:
                    pass
                self.probe_proc = None
        return None

    def active(self):
        """True while a dashboard is open and visible (it polls every 2s)."""
        return time.time() - self.last_client < 15

    def due(self, name, active_iv, idle_iv):
        now = time.time()
        iv = active_iv if self.active() else idle_iv
        if now - self.last_run.get(name, 0) >= iv - 0.3:
            self.last_run[name] = now
            return True
        return False

    def _battery(self):
        out = run(["ioreg", "-rn", "AppleSmartBattery"])
        if not out.strip():
            return {}

        def top(key):
            m = re.search(r'^\s*\|?\s*"%s" = (\S+)' % re.escape(key), out, re.M)
            return m.group(1) if m else None

        def inner(key):
            m = re.search(r'"%s"=(-?\d+)' % re.escape(key), out)
            return int(m.group(1)) if m else None

        def as_int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        b = {
            "percent": as_int(top("CurrentCapacity")),
            "charging": top("IsCharging") == "Yes",
            "external": top("ExternalConnected") == "Yes",
            "cycles": as_int(top("CycleCount")),
        }
        raw_max = as_int(top("AppleRawMaxCapacity")) or inner("AppleRawMaxCapacity")
        design = as_int(top("DesignCapacity")) or inner("DesignCapacity")
        if raw_max and design:
            b["health"] = round(100.0 * raw_max / design, 1)
        amps = as_int(top("InstantAmperage")) or as_int(top("Amperage"))
        volts = as_int(top("Voltage"))
        if amps is not None and amps > 2 ** 31:
            amps -= 2 ** 64
        sys_in = inner("SystemPowerIn")
        if b["external"] and sys_in:
            b["watts"] = round(sys_in / 1000.0, 1)
        elif amps is not None and volts:
            b["watts"] = round(abs(amps * volts) / 1e6, 1)
        tte = as_int(top("TimeRemaining"))
        if tte and tte < 6000 and not b["external"]:
            b["minutes_left"] = tte
        return b

    def _thermal(self):
        out = run(["pmset", "-g", "therm"])
        m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", out)
        return int(m.group(1)) if m else 100

    def _disk_usage(self):
        path = "/System/Volumes/Data" if os.path.exists("/System/Volumes/Data") else "/"
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        return {"total": total, "free": free, "used": total - free,
                "pct": round(100.0 * (total - free) / total, 1) if total else 0}

    def _ports(self):
        out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"], timeout=15)
        res = {}
        pid = cmd = None
        for line in out.splitlines():
            if not line:
                continue
            tag, val = line[0], line[1:]
            if tag == "p":
                pid = int(val)
            elif tag == "c":
                cmd = val
            elif tag == "n" and pid:
                host, _, port = val.rpartition(":")
                public = host in ("*", "0.0.0.0", "[::]", "")
                key = (pid, port)
                if key in res:
                    res[key]["public"] = res[key]["public"] or public
                else:
                    res[key] = {"pid": pid, "name": cmd, "port": int(port) if port.isdigit() else port,
                                "addr": host, "public": public}
        return sorted(res.values(), key=lambda r: (not r["public"], r["port"] if isinstance(r["port"], int) else 0))

    def _startup(self):
        items = []
        dirs = [(os.path.join(HOME, "Library/LaunchAgents"), "User agent"),
                ("/Library/LaunchAgents", "Global agent"),
                ("/Library/LaunchDaemons", "System daemon")]
        for d, kind in dirs:
            try:
                names = sorted(os.listdir(d))
            except OSError:
                continue
            for n in names:
                if not n.endswith(".plist"):
                    continue
                p = os.path.join(d, n)
                try:
                    with open(p, "rb") as f:
                        pl = plistlib.load(f)
                except Exception:
                    items.append({"label": n[:-6], "kind": kind, "file": p, "program": None,
                                  "exists": None, "risky": False, "disabled": False})
                    continue
                prog = pl.get("Program") or (pl.get("ProgramArguments") or [None])[0]
                exists = os.path.exists(prog) if prog and prog.startswith("/") else None
                items.append({
                    "label": pl.get("Label", n[:-6]), "kind": kind, "file": p, "program": prog,
                    "exists": exists, "risky": bool(prog and is_risky_path(prog)),
                    "disabled": bool(pl.get("Disabled")), "keepalive": bool(pl.get("KeepAlive")),
                })
        return items

    def _processes(self, now):
        data = self._ask("p")
        if not data:
            return None
        rows = data["procs"]
        # Other users' processes (root etc.) aren't readable without privileges; fill CPU/RSS
        # for just those pids from the setuid `ps` - one cheap call.
        missing = [str(r[0]) for r in rows if not r[7]]
        extra = {}
        if missing:
            out = run(["ps", "-o", "pid=,time=,rss=", "-p", ",".join(missing)], timeout=10)
            for line in out.splitlines():
                c = line.split()
                if len(c) == 3 and c[0].isdigit():
                    extra[int(c[0])] = (parse_cputime(c[1]) * 1e9, int(c[2]) * 1024)
        # Stuck (uninterruptible) state needs per-thread info; check once a minute.
        if self.due("pstate", 60, 300):
            self.pstate = {}
            for line in run(["ps", "-axo", "pid=,state="], timeout=10).splitlines():
                c = line.split()
                if len(c) == 2 and c[0].isdigit():
                    self.pstate[int(c[0])] = c[1]
        procs = []
        alive = set()
        for pid, ppid, uid, stat_, cpu_ns, rss, start, have, path in rows:
            if not have and pid in extra:
                cpu_ns, rss = extra[pid]
            prev = self.prev_cputime.get(pid)
            cpu = 0.0
            if prev and now > prev[0] and prev[2] == start:
                cpu = max(0.0, 100.0 * (cpu_ns - prev[1]) / 1e9 / (now - prev[0]))
            self.prev_cputime[pid] = (now, cpu_ns, start)
            alive.add(pid)
            state = "Z" if stat_ == 5 else self.pstate.get(pid, "R" if stat_ == 2 else "S")
            procs.append({
                "pid": pid, "ppid": ppid, "uid": uid, "user": username(uid),
                "state": state, "cpu": round(cpu, 1), "rss": rss,
                "age": max(0, int(now - start)) if start else 0, "path": path,
                "name": os.path.basename(path) or path, "app": app_name(path),
                "system": is_system_path(path),
            })
            h = self.proc_hist.get(pid)
            if h is None:
                h = self.proc_hist[pid] = deque(maxlen=120)
            h.append((now, cpu, rss))
        for pid in list(self.proc_hist):
            if pid not in alive:
                del self.proc_hist[pid]
                self.prev_cputime.pop(pid, None)
        # Pulse's own footprint (this Python process + the probe)
        me = os.times()
        cpu_self = me.user + me.system
        probe_pid = self.probe_proc.pid if self.probe_proc else None
        probe_ns = self.prev_cputime.get(probe_pid, (0, 0, 0))[1] if probe_pid else 0
        total = cpu_self + probe_ns / 1e9
        if self.self_prev:
            dt = now - self.self_prev[0]
            if dt > 0:
                self.overhead["cpu"] = round(100.0 * (total - self.self_prev[1]) / dt, 2)
        self.self_prev = (now, total)
        self.overhead["rss"] = sum(p["rss"] for p in procs if p["pid"] in (os.getpid(), probe_pid))
        return procs

    # ---------------- main loop
    def loop(self):
        while True:
            t0 = time.time()
            try:
                self.collect()
            except Exception as e:  # never let the sampler die
                self._event("warning", "monitor", "Collector error: %s" % e)
            # Fan curves need a fast control loop; otherwise sample slowly in the background.
            interval = SAMPLE_EVERY if self.active() or FANS.controlling() else IDLE_SAMPLE_EVERY
            # wake early if a dashboard opens while we're in idle mode
            end = t0 + interval
            while time.time() < end:
                time.sleep(min(0.5, max(0.05, end - time.time())))
                if not self.was_active and self.active():
                    break
            self.was_active = self.active()

    def collect(self):
        now = time.time()
        self.tick += 1
        probe = self._ask("s")
        net = tuple(probe["net"]) if probe else (0, 0)
        dio = tuple(probe["disk"]) if probe else (0, 0)
        gpu = probe.get("gpu") if probe else None
        dt = (now - self.prev_t) if self.prev_t else None

        s = {"t": round(now, 2), "load": round(os.getloadavg()[0], 2), "gpu": gpu}

        # CPU
        if probe and probe.get("cpu"):
            cores = probe["cpu"]
            if self.prev_cpu and len(self.prev_cpu) == len(cores):
                per, tu = [], [0, 0, 0]
                for a, b in zip(cores, self.prev_cpu):
                    du, ds, di, dn = (a[0] - b[0]), (a[1] - b[1]), (a[2] - b[2]), (a[3] - b[3])
                    tot = du + ds + di + dn or 1
                    per.append(round(100.0 * (du + ds + dn) / tot, 1))
                    tu[0] += du + dn
                    tu[1] += ds
                    tu[2] += tot
                s["cpu"] = {"user": round(100.0 * tu[0] / tu[2], 1),
                            "sys": round(100.0 * tu[1] / tu[2], 1),
                            "cores": per}
                s["cpu"]["total"] = round(s["cpu"]["user"] + s["cpu"]["sys"], 1)
            self.prev_cpu = cores

        # Memory (matches Activity Monitor's breakdown)
        if probe and probe.get("mem"):
            m = probe["mem"]
            pg = m["page"]
            app = max(0, m["internal"] - m["purgeable"]) * pg
            wired = m["wired"] * pg
            comp = m["compressed"] * pg
            cached = (m["external"] + m["purgeable"]) * pg
            used = app + wired + comp
            s["mem"] = {"total": m["total"], "app": app, "wired": wired, "comp": comp,
                        "cached": cached, "used": used, "free": max(0, m["total"] - used - cached),
                        "swap": m["swap_used"], "swap_total": m["swap_total"],
                        "pressure": m["pressure"], "pct": round(100.0 * used / m["total"], 1)}

        # Temperatures
        if probe and probe.get("temps"):
            tt = probe["temps"]
            die = [v for k, v in tt.items() if "tdie" in k]
            gpu_t = [v for k, v in tt.items() if re.search(r"TP\dg|GPU", k)]
            other = [v for k, v in tt.items() if "battery" not in k and "NAND" not in k and "tcal" not in k]
            cpu_set = die or other
            batt = [v for k, v in tt.items() if "battery" in k.lower()]
            ssd = [v for k, v in tt.items() if "NAND" in k]
            s["temp"] = {
                "cpu_max": round(max(cpu_set), 1) if cpu_set else None,
                "cpu_avg": round(sum(cpu_set) / len(cpu_set), 1) if cpu_set else None,
                "gpu": round(max(gpu_t), 1) if gpu_t else None,
                "battery": round(batt[0], 1) if batt else None,
                "ssd": round(max(ssd), 1) if ssd else None,
            }
            s["sensors"] = len(tt)

        # Fans
        if probe and probe.get("fans"):
            s["fans"] = probe["fans"]

        # Network / disk throughput
        if dt and self.prev_net:
            def delta(a, b):
                d = a - b
                return d + 2 ** 32 if -2 ** 32 < d < 0 else max(0, d)   # 32-bit counter wrap
            s["net"] = {"rx": delta(net[0], self.prev_net[0]) / dt, "tx": delta(net[1], self.prev_net[1]) / dt}
        if dt and self.prev_disk:
            s["disk"] = {"r": max(0, (dio[0] - self.prev_disk[0]) / dt),
                         "w": max(0, (dio[1] - self.prev_disk[1]) / dt)}
        self.prev_net, self.prev_disk, self.prev_t = net, dio, now

        # Slower collectors
        procs = self._processes(now) if self.due("procs", 4, 30) else None
        if self.due("battery", 10, 60):
            self.battery = self._battery()
            self.thermal_limit = self._thermal()
            self.disk_usage = self._disk_usage()
        if self.due("ports", 60, 600):
            self.ports = self._ports()
        if self.due("startup", 300, 1800):
            self.startup = self._startup()
        if self.battery.get("watts") is not None:
            s["power"] = self.battery["watts"]

        try:
            FANS.update(s, now)
        except Exception as e:
            FANS.error = str(e)

        with self.lock:
            if "cpu" in s:
                self.samples.append(s)
            if procs is not None:
                self._process_analysis(procs, now)
                self.procs_fresh = True
            self._analyze(s, now)
        if now - self.started > 45:
            self.warm = True

    # ---------------- analysis
    def _event(self, severity, kind, text, key=None):
        self.events.appendleft({"t": time.time(), "severity": severity, "kind": kind,
                                "text": text, "key": key})

    def _process_analysis(self, procs, now):
        self.proc_count = len(procs)
        # signatures for non-system executables
        for p in procs:
            if not p["system"]:
                sig = SIGS.get(p["path"])
                p["sig"] = sig
            else:
                p["sig"] = {"signed": True, "apple": True, "adhoc": False}
            # new program detection
            if p["path"] not in self.seen_paths:
                self.seen_paths.add(p["path"])
                if self.warm and not p["system"] and not p["name"].startswith("("):
                    self._event("info", "process", "New program started: %s (pid %d)" % (p["app"], p["pid"]),
                                key="proc:%s" % p["path"])
            h = self.proc_hist.get(p["pid"])
            p["cpu_hist"] = [round(x[1], 1) for x in list(h)[-30:]] if h else []
        # app groups
        groups = {}
        for p in procs:
            g = groups.get(p["app"])
            if g is None:
                g = groups[p["app"]] = {"app": p["app"], "cpu": 0.0, "rss": 0, "count": 0,
                                        "system": p["system"], "pids": []}
            g["cpu"] += p["cpu"]
            g["rss"] += p["rss"]
            g["count"] += 1
            if len(g["pids"]) < 50:
                g["pids"].append(p["pid"])
            g["system"] = g["system"] and p["system"]
        apps = sorted(groups.values(), key=lambda g: -(g["cpu"] + g["rss"] / 2 ** 30 * 5))
        for g in apps:
            g["cpu"] = round(g["cpu"], 1)
        self.apps = apps[:80]
        self.procs = procs

    def _set_flag(self, active, key, severity, category, title, detail, pid=None, action=None):
        """Raise/refresh a flag (active=True) or clear it."""
        f = self.flags.get(key)
        if active:
            if f is None:
                f = {"key": key, "since": time.time()}
                self.flags[key] = f
                if SEVERITY_RANK[severity] >= 1:
                    self._event(severity, "flag", title, key=key)
                    self._notify(key, severity, title, detail)
            elif SEVERITY_RANK[severity] > SEVERITY_RANK[f["severity"]]:
                self._event(severity, "flag", "Escalated: " + title, key=key)
                self._notify(key, severity, title, detail)
            f.update({"severity": severity, "category": category, "title": title,
                      "detail": detail, "pid": pid, "action": action, "seen": time.time()})
        elif f is not None:
            del self.flags[key]
            if SEVERITY_RANK[f["severity"]] >= 1:
                self._event("good", "resolved", "Resolved: " + f["title"], key=key)

    def _notify(self, key, severity, title, detail):
        if not SETTINGS.data.get("notify") or SEVERITY_RANK[severity] < 2 or key in SETTINGS.ignored():
            return
        if time.time() - self.notified.get(key, 0) < 1800 or not self.warm:
            return
        self.notified[key] = time.time()
        # Pulse.app picks these up and posts them as its own notifications (clicking one opens
        # Pulse). There is deliberately no AppleScript fallback: `display notification` is
        # attributed to Script Editor, which is what opens when it's clicked.
        self.notify_queue.append({"key": key, "severity": severity, "title": title[:120], "body": detail[:240]})

    def _analyze(self, s, now):
        hist = list(self.samples)
        # --- sustained total CPU
        win = [x for x in hist if x["t"] >= now - 60 and "cpu" in x]
        recent = [x["cpu"]["total"] for x in win]
        hi = len(recent) >= 5 and win[-1]["t"] - win[0]["t"] >= 45 and min(recent) > 85
        self._set_flag(hi, "cpu:sustained", "warning", "CPU",
                       "CPU has been pegged above 85% for a minute",
                       "Average %.0f%% over the last minute. Check the top processes below." %
                       (sum(recent) / max(1, len(recent))))

        # --- load average
        load = s.get("load", 0)
        self._set_flag(load > NCPU * 4, "load", "warning" if load < NCPU * 20 else "serious", "CPU",
                       "Run queue is extremely long",
                       "Load average %.0f on %d cores - far more work is waiting than the CPU can run, "
                       "so everything feels slow." % (load, NCPU))

        # --- memory
        m = s.get("mem")
        if m:
            pr = m["pressure"]
            self._set_flag(pr >= 2, "mem:pressure", "critical" if pr >= 4 else "serious", "Memory",
                           "Memory pressure is %s" % ("critical" if pr >= 4 else "high"),
                           "macOS is compressing %s and swapping to disk. Quit memory-heavy apps." %
                           fmt_bytes(m["comp"]))
            swap_pct = 100.0 * m["swap"] / m["swap_total"] if m["swap_total"] else 0
            self._set_flag(m["swap"] > 8 * 2 ** 30 or swap_pct > 85, "mem:swap",
                           "serious" if m["swap"] > 16 * 2 ** 30 else "warning", "Memory",
                           "Heavy swap usage: %s" % fmt_bytes(m["swap"]),
                           "Swap is %.0f%% of its current size. Swapping wears the SSD and slows the Mac. "
                           "A restart clears it." % swap_pct)

        # --- temperature
        t = s.get("temp") or {}
        cmax = t.get("cpu_max")
        if cmax is not None:
            sev = "critical" if cmax >= 100 else "serious" if cmax >= 92 else "warning"
            self._set_flag(cmax >= 85, "temp:cpu", sev, "Temperature",
                           "Chip is running hot: %.0f°C" % cmax,
                           "Apple Silicon throttles around 100°C. Sustained heat usually means a runaway process.")
        if t.get("battery") is not None:
            self._set_flag(t["battery"] >= 40, "temp:battery", "serious" if t["battery"] >= 45 else "warning",
                           "Temperature", "Battery is warm: %.0f°C" % t["battery"],
                           "Keeping the battery above 35°C accelerates wear.")
        self._set_flag(self.thermal_limit < 100, "temp:throttle", "serious", "Temperature",
                       "CPU is being thermally throttled",
                       "macOS has limited CPU speed to %d%%." % self.thermal_limit)

        # --- disk
        du = self.disk_usage
        if du:
            free_pct = 100 - du["pct"]
            sev = "critical" if free_pct < 5 else "serious" if free_pct < 10 else "warning"
            self._set_flag(free_pct < 15, "disk:free", sev, "Disk",
                           "Startup disk is %.0f%% full" % du["pct"],
                           "Only %s free. macOS needs room for swap and updates - below ~10%% things break." %
                           fmt_bytes(du["free"]))

        # --- battery health
        b = self.battery
        if b.get("health") is not None:
            self._set_flag(b["health"] < 80, "battery:health", "info", "Battery",
                           "Battery health is %.0f%%" % b["health"],
                           "%s charge cycles. Below 80%% Apple recommends service." % (b.get("cycles") or "?"))

        # --- spikes (vs. 5 minute baseline)
        self._spike(hist, "cpu", lambda x: x.get("cpu", {}).get("total"), 30, "CPU",
                    lambda v, b: "CPU spiked to %.0f%% (normal ~%.0f%%)" % (v, b))
        self._spike(hist, "net_rx", lambda x: x.get("net", {}).get("rx"), 5 * 2 ** 20, "Network",
                    lambda v, b: "Download burst %s/s (normal ~%s/s)" % (fmt_bytes(v), fmt_bytes(b)))
        self._spike(hist, "net_tx", lambda x: x.get("net", {}).get("tx"), 2 * 2 ** 20, "Network",
                    lambda v, b: "Upload burst %s/s (normal ~%s/s)" % (fmt_bytes(v), fmt_bytes(b)))
        self._spike(hist, "disk_w", lambda x: x.get("disk", {}).get("w"), 50 * 2 ** 20, "Disk",
                    lambda v, b: "Disk write burst %s/s (normal ~%s/s)" % (fmt_bytes(v), fmt_bytes(b)))
        for k in [k for k, exp in self.spikes.items() if exp < now]:
            del self.spikes[k]
            self._set_flag(False, "spike:" + k, "info", "", "", "")

        if self.procs and self.procs_fresh:
            self.procs_fresh = False
            self._analyze_procs(now)

    def _spike(self, hist, key, get, floor, cat, text):
        if not hist:
            return
        vals = [get(x) for x in hist[:-1] if x["t"] >= hist[-1]["t"] - 300]
        vals = [v for v in vals if v is not None]
        cur = get(hist[-1])
        if cur is None or len(vals) < 25:
            return
        mean = statistics.fmean(vals)
        sd = statistics.pstdev(vals) or 1e-9
        if cur > floor and cur > mean + 4 * sd and cur > mean * 2:
            first = ("spike:" + key) not in self.flags
            self.spikes[key] = time.time() + 60
            self._set_flag(True, "spike:" + key, "info", cat, text(cur, mean),
                           "Unusual compared with the last 5 minutes (%.1f standard deviations)." % ((cur - mean) / sd))
            if first:
                self._event("info", "spike", text(cur, mean))

    def _analyze_procs(self, now):
        procs = self.procs
        active_proc_keys = set()
        total_mem = self.samples[-1]["mem"]["total"] if self.samples and "mem" in self.samples[-1] else 0

        def proc_flag(p, kind, severity, title, detail):
            key = "proc:%s:%s" % (kind, p["path"])
            active_proc_keys.add(key)
            self._set_flag(True, key, severity, "Process", title, detail, pid=p["pid"],
                           action="kill" if p["uid"] == MY_UID else None)

        by_path = defaultdict(list)
        for p in procs:
            by_path[p["path"]].append(p)
            h = self.proc_hist.get(p["pid"])
            if h and len(h) >= 4:
                span = h[-1][0] - h[0][0]
                # runaway CPU: average > 80% across the whole window of >= 2 minutes
                win = [x for x in h if x[0] >= now - 600]
                if win and win[-1][0] - win[0][0] >= 120:
                    avg = sum(x[1] for x in win) / len(win)
                    if avg > 80:
                        mins = (win[-1][0] - win[0][0]) / 60
                        proc_flag(p, "cpu", "serious" if mins >= 9 and avg > 95 else "warning",
                                  "%s is using %.0f%% CPU nonstop" % (p["app"], avg),
                                  "Pid %d has averaged %.0f%% CPU for %.0f minutes." % (p["pid"], avg, mins))
                # memory growth: steadily climbing over >= 5 minutes
                if span >= 300:
                    first, last = h[0][2], h[-1][2]
                    ups = sum(1 for a, b in zip(h, list(h)[1:]) if b[2] > a[2])
                    if last - first > 1 * 2 ** 30 and ups > 0.6 * (len(h) - 1):
                        proc_flag(p, "leak", "warning", "%s memory keeps growing" % p["app"],
                                  "Grew %s in %.0f minutes (now %s) without dropping - possible leak." %
                                  (fmt_bytes(last - first), span / 60, fmt_bytes(last)))
            # big memory
            if total_mem and p["rss"] > max(4 * 2 ** 30, 0.15 * total_mem):
                proc_flag(p, "mem", "warning", "%s is using %s of memory" % (p["app"], fmt_bytes(p["rss"])),
                          "Pid %d - %.0f%% of your RAM." % (p["pid"], 100.0 * p["rss"] / total_mem))
            # signature / location
            sig = p.get("sig")
            if not p["system"] and sig:
                risky = is_risky_path(p["path"])
                if sig.get("signed") is False:
                    proc_flag(p, "unsigned", "serious" if risky else "warning",
                              "Unsigned program running: %s" % p["name"],
                              "%s has no code signature%s. Make sure you recognise it." %
                              (p["path"], " and runs from a temporary/download folder" if risky else ""))
                elif risky and (sig.get("adhoc") or not sig.get("team")):
                    proc_flag(p, "risky", "serious", "Unverified program in %s" % os.path.dirname(p["path"]),
                              "%s is not signed by an identified developer and runs from a location "
                              "malware often uses." % p["path"])

        # stuck in uninterruptible wait (U state) across two consecutive samples
        stuck_now = {p["pid"] for p in procs if p["state"].startswith("U") and p["age"] > 60}
        stuck = [p for p in procs if p["pid"] in stuck_now and p["pid"] in self._prev_stuck]
        self._prev_stuck = stuck_now
        names = sorted({p["app"] for p in stuck})
        self._set_flag(len(stuck) >= 5, "proc:stuck", "warning" if len(stuck) >= 25 else "info", "Process",
                       "%d processes stuck waiting on the kernel" % len(stuck),
                       "Usually waiting on a slow/full disk or memory swapping: %s%s" %
                       (", ".join(names[:12]), "…" if len(names) > 12 else ""))

        # zombies
        zombies = [p for p in procs if p["state"].startswith("Z")]
        self._set_flag(len(zombies) >= 10, "proc:zombies", "info", "Process",
                       "%d zombie processes" % len(zombies),
                       "Exited processes whose parent never reaped them. Restarting the parent app cleans them up.")

        # duplicate swarms
        for path, lst in by_path.items():
            if len(lst) >= 25 and not lst[0]["system"] and not is_sim(path) \
                    and ".app/Contents/" not in path:   # browsers/IDEs legitimately run many helpers
                key = "proc:swarm:%s" % path
                active_proc_keys.add(key)
                self._set_flag(True, key, "warning", "Process",
                               "%d copies of %s are running" % (len(lst), lst[0]["name"]),
                               "Together using %.0f%% CPU and %s." %
                               (sum(p["cpu"] for p in lst), fmt_bytes(sum(p["rss"] for p in lst))),
                               pid=lst[0]["pid"])

        # iOS simulators left running
        sim = [p for p in procs if is_sim(p["path"])]
        sim_ui = any(p["path"].endswith("/Simulator.app/Contents/MacOS/Simulator") for p in procs)
        runtimes = len(set(re.findall(r"SimulatorRuntime[^/]*", " ".join(p["path"] for p in sim))))
        sim_cpu = sum(p["cpu"] for p in sim)
        sim_mem = sum(p["rss"] for p in sim)
        self._set_flag(len(sim) > 40, "sim", "warning" if sim_ui else "serious", "Process",
                       "iOS Simulator%s: %d background processes" % ("" if sim_ui else " left running", len(sim)),
                       "%d simulator runtime(s) using %.0f%% CPU%s. %s" %
                       (runtimes or 1, sim_cpu,
                        " and ~%s" % fmt_bytes(sim_mem) if total_mem and sim_mem < total_mem else "",
                        "Shut down devices you aren't using (Simulator > Device > Shut Down, or "
                        "`xcrun simctl shutdown all`)." ),
                       action="simctl")

        # process count
        self._set_flag(self.proc_count > 1500, "proc:count", "warning", "Process",
                       "%d processes running" % self.proc_count,
                       "A typical Mac runs 500-900. Something is spawning a lot of processes.")

        # listening on all interfaces by non-Apple, non-identified programs
        pid_map = {p["pid"]: p for p in procs}
        for port in self.ports:
            p = pid_map.get(port["pid"])
            if not p or not port["public"] or p["system"]:
                continue
            sig = p.get("sig") or {}
            if sig.get("apple"):
                continue
            key = "port:%s:%s" % (p["path"], port["port"])
            active_proc_keys.add(key)
            self._set_flag(True, key, "info", "Network",
                           "%s accepts connections from other devices on port %s" % (p["app"], port["port"]),
                           "Listening on all interfaces, so anyone on your network can reach it. "
                           "Fine for dev servers you started; otherwise investigate.", pid=p["pid"])

        # startup items
        for it in self.startup:
            key = "startup:%s" % it["file"]
            bad = it["risky"] or (it["exists"] is False and not it["disabled"])
            if bad:
                active_proc_keys.add(key)
                self._set_flag(True, key, "serious" if it["risky"] else "info", "Startup",
                               ("Startup item runs from a risky folder: %s" if it["risky"] else
                                "Broken startup item: %s") % it["label"],
                               "%s -> %s" % (it["file"], it["program"]))

        # clear process-scoped flags that are no longer true
        for key in [k for k in self.flags if k.startswith(("proc:", "port:", "startup:"))
                    and k not in ("proc:zombies", "proc:count", "proc:stuck")]:
            if key not in active_proc_keys:
                self._set_flag(False, key, "info", "", "", "")

    # ---------------- API views
    def history(self):
        with self.lock:
            return {"meta": self.meta, "samples": list(self.samples)}

    def live(self, since, visible=True):
        if visible:
            self.last_client = time.time()
        with self.lock:
            samples = [s for s in self.samples if s["t"] > since]
            ignored = SETTINGS.ignored()
            flags = sorted(self.flags.values(), key=lambda f: (-SEVERITY_RANK[f["severity"]], f["since"]))
            flags = [dict(f, ignored=f["key"] in ignored) for f in flags]
            flagged_pids = {f["pid"] for f in flags if f.get("pid")}
            procs = sorted(self.procs, key=lambda p: -(p["cpu"] * 4 + p["rss"] / 2 ** 28))
            top = procs[:250] + [p for p in procs[250:] if p["pid"] in flagged_pids]
            return {
                "meta": self.meta, "samples": samples, "flags": flags,
                "events": list(self.events)[:120],
                "procs": [{k: v for k, v in p.items()} for p in top],
                "apps": self.apps, "ports": self.ports, "startup": self.startup,
                "battery": self.battery, "disk_usage": self.disk_usage,
                "thermal_limit": self.thermal_limit, "proc_count": self.proc_count,
                "notify": SETTINGS.data.get("notify", True), "warm": self.warm,
                "fan": FANS.status([p["pid"] for p in self.procs if p["app"] == "Macs Fan Control"]),
                "overhead": self.overhead, "mode": "live" if self.active() else "background",
                "uptime": time.time() - self.meta["boot"] if self.meta.get("boot") else None,
            }


MON = Monitor()
SCANNER = storage.Scanner(DATA_DIR, HERE)
CLAUDE_CANDIDATES = [os.path.expanduser("~/.local/bin/claude"), "/opt/homebrew/bin/claude", "/usr/local/bin/claude"]


def ask_claude():
    disk = MON._disk_usage()
    report = os.path.join(DATA_DIR, "storage-report.md")
    with open(report, "w") as f:
        f.write(storage.claude_report(SCANNER, disk))
    prompt = (
        "I'm running low on disk space on my Mac (%s free of %s). My monitoring dashboard, Pulse, wrote a storage "
        "report to \"%s\". Read it, verify the biggest items yourself (du -sh, ls), and propose a cleanup plan "
        "grouped into: (1) safe to delete - regenerable caches and build data; (2) probably not needed - old "
        "installers, node_modules in inactive projects, unused simulators/emulators, stale downloads; (3) needs my "
        "decision - personal files, backups, archives. Show the size of each item and the total for each group. "
        "Do not delete anything until I approve a group. Move personal files to the Trash rather than deleting "
        "them permanently, and never touch Documents, Desktop, Pictures, Mail, Keychains or iCloud folders unless "
        "I ask about that specific item." % (fmt_bytes(disk["free"]), fmt_bytes(disk["total"]), report))
    pfile = os.path.join(DATA_DIR, "claude-prompt.txt")
    with open(pfile, "w") as f:
        f.write(prompt)
    cli = next((c for c in CLAUDE_CANDIDATES if os.access(c, os.X_OK)), None)
    if cli:
        cmd = 'cd ~ && %s "$(cat %s)"' % (shlex_quote(cli), shlex_quote(pfile))
        script = ('tell application "Terminal"\n activate\n do script "%s"\nend tell'
                  % cmd.replace("\\", "\\\\").replace('"', '\\"'))
        subprocess.Popen(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": True, "how": "terminal", "report": report}
    subprocess.run(["pbcopy"], input=prompt, text=True)
    subprocess.Popen(["open", "-a", "Claude"])
    return {"ok": True, "how": "clipboard", "report": report}


def shlex_quote(s):
    import shlex
    return shlex.quote(s)


# --------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":")).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _local_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._local_ok():
            return self._send(403, {"error": "forbidden"})
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/api/history":
            return self._send(200, MON.history())
        if u.path == "/api/storage/state":
            st = SCANNER.state()
            st["disk"] = MON._disk_usage()
            st["suggestions"] = SCANNER.suggestions()
            st["claude"] = any(os.access(c, os.X_OK) for c in CLAUDE_CANDIDATES)
            return self._send(200, st)
        if u.path == "/api/storage/node":
            path = parse_qs(u.query).get("path", ["/"])[0]
            node = SCANNER.node(path)
            return self._send(200 if node else 404, node or {"error": "Not scanned yet"})
        if u.path == "/api/storage/large":
            return self._send(200, SCANNER.large_files())
        if u.path == "/api/notifications":
            items = []
            while MON.notify_queue:
                items.append(MON.notify_queue.popleft())
            return self._send(200, items)
        if u.path == "/api/live":
            q = parse_qs(u.query)
            since = float(q.get("since", ["0"])[0] or 0)
            return self._send(200, MON.live(since, q.get("bg", ["0"])[0] != "1"))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        # Only same-origin requests from the dashboard itself.
        if not self._local_ok() or self.headers.get("X-Pulse") != "1":
            return self._send(403, {"error": "forbidden"})
        origin = self.headers.get("Origin")
        if origin and not re.match(r"^http://(127\.0\.0\.1|localhost):%d$" % PORT, origin):
            return self._send(403, {"error": "bad origin"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad json"})
        u = urlparse(self.path)
        if u.path == "/api/ignore":
            SETTINGS.set_ignored(str(data.get("key")), bool(data.get("ignore", True)))
            return self._send(200, {"ok": True})
        if u.path == "/api/notify-test":
            MON.notify_queue.append({"key": "test", "severity": "info", "title": "Pulse notifications work",
                                     "body": "Click this to open Pulse's flags."})
            return self._send(200, {"ok": True})
        if u.path == "/api/notify":
            SETTINGS.set_notify(bool(data.get("on")))
            return self._send(200, {"ok": True})
        if u.path == "/api/kill":
            try:
                pid = int(data.get("pid"))
            except (TypeError, ValueError):
                return self._send(400, {"error": "bad pid"})
            proc = next((p for p in MON.procs if p["pid"] == pid), None)
            if not proc:
                return self._send(404, {"error": "process not found"})
            if proc["uid"] != MY_UID:
                return self._send(403, {"error": "That process belongs to %s; Pulse only quits your own processes."
                                         % proc["user"]})
            if pid in (os.getpid(), 1) or proc["system"] and proc["name"] in ("WindowServer", "loginwindow", "launchd"):
                return self._send(403, {"error": "Refusing to quit a critical system process."})
            sig = signal.SIGKILL if data.get("force") else signal.SIGTERM
            try:
                os.kill(pid, sig)
            except OSError as e:
                return self._send(500, {"error": str(e)})
            MON._event("info", "action", "You quit %s (pid %d)%s" % (proc["app"], pid, " [forced]" if data.get("force") else ""))
            return self._send(200, {"ok": True})
        if u.path == "/api/storage/scan":
            return self._send(200, {"ok": True, "started": SCANNER.start()})
        if u.path == "/api/storage/delete":
            mode = data.get("mode") if data.get("mode") in ("trash", "permanent", "contents") else "trash"
            before = MON._disk_usage().get("free")
            res = storage.delete_path(str(data.get("path") or ""), mode)
            if res.get("ok"):
                gone = res.get("freed") or res.get("moved") or 0      # allocated size (for the tree view)
                SCANNER.forget(data["path"], gone)
                res["size"] = gone
                if mode != "trash":
                    # Report what actually came back: clones share blocks, so it can be far less.
                    res["freed"] = storage.settle_freed(before)
                verb = {"trash": "Moved to Trash", "permanent": "Deleted", "contents": "Emptied"}[mode]
                MON._event("info", "action", "%s %s (%s%s)" % (
                    verb, res["path"], fmt_bytes(gone),
                    "" if mode == "trash" else ", freed %s" % fmt_bytes(res["freed"])))
            return self._send(200 if res.get("ok") else 400, res)
        if u.path == "/api/storage/action":
            name = str(data.get("name"))
            target = None
            if name.startswith("sim_device:"):
                dev = storage.sim_devices().get(name.split(":", 1)[1].upper())
                target = dev["path"] if dev else None
            size = SCANNER.size_of(target) if target else None
            frees = SCANNER.priv_of(target) if target else None
            res = storage.run_action(name)
            if res.get("ok") and res.get("forget"):
                SCANNER.forget(res["forget"], size or 0)
                res["size"], res["expected"] = size, frees
                # APFS releases space asynchronously: measure what actually came back.
                res["freed"] = max(res["freed"], storage.settle_freed(res.get("free_before")))
            if res.get("ok"):
                MON._event("info", "action", "%s - freed %s%s" % (
                    res["label"], fmt_bytes(res["freed"]),
                    " of %s (rest shared with clones)" % fmt_bytes(res["size"]) if res.get("size") and res["freed"] < res["size"] / 2 else ""))
            return self._send(200 if res.get("ok") else 400, res)
        if u.path == "/api/storage/reveal":
            path = str(data.get("path") or "")
            if path.startswith("/") and os.path.lexists(path):
                subprocess.Popen(["open", "-R", path])
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "Not found"})
        if u.path == "/api/open-fda":
            subprocess.Popen(["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"])
            if SCANNER.scanner_app:
                # Show the scanner in Finder so it can be dragged into the Full Disk Access list.
                subprocess.Popen(["open", "-R", SCANNER.scanner_app])
            return self._send(200, {"ok": True})
        if u.path == "/api/storage/deep-scan":
            res = SCANNER.deep_scan()
            if res.get("ok"):
                MON._event("info", "action", "System folders measured (admin, read-only)")
            return self._send(200 if res["ok"] else 400, res)
        if u.path == "/api/storage/claude":
            return self._send(200, ask_claude())
        if u.path == "/api/fan/mode":
            return self._send(200, FANS.set_mode(str(data.get("mode")), data.get("pct")))
        if u.path == "/api/fan/install":
            res = fanctl.install_helper(os.path.join(HERE, "pulse-fand"), DATA_DIR)
            if res.get("ok"):
                MON._event("info", "action", "Fan control enabled")
            return self._send(200 if res["ok"] else 400, res)
        if u.path == "/api/fan/uninstall":
            FANS.set_mode("auto")
            res = fanctl.uninstall_helper()
            return self._send(200 if res["ok"] else 400, res)
        if u.path == "/api/simctl":
            out = run_both(["xcrun", "simctl", "shutdown", "all"], timeout=60)
            MON._event("info", "action", "Shut down all iOS simulators")
            return self._send(200, {"ok": True, "output": out[-500:]})
        self._send(404, {"error": "not found"})


def main():
    try:
        os.nice(10)   # always yield to your real work
    except OSError:
        pass
    if not os.path.exists(PROBE):
        print("Compiling sensor probe...")
        subprocess.run(["clang", "-O2", "-w", "-o", PROBE, os.path.join(HERE, "probe.c"),
                        "-framework", "IOKit", "-framework", "CoreFoundation"], check=True)
    # Always hand the fans back to macOS when Pulse stops (the helper's watchdog also does this).
    import atexit
    import sys
    atexit.register(lambda: FANS.controlling() and FANS.release())
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.signal(signal.SIGHUP, lambda *a: sys.exit(0))
    if not os.path.exists(os.path.join(HERE, "pulse-fand")):
        subprocess.run(["clang", "-O2", "-w", "-o", os.path.join(HERE, "pulse-fand"), os.path.join(HERE, "fand.c"),
                        "-framework", "IOKit", "-framework", "CoreFoundation"])
    threading.Thread(target=MON.loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("Pulse running at http://127.0.0.1:%d  (Ctrl+C to stop)" % PORT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
