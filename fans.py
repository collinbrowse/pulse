"""Fan control for Pulse. Reading fans needs no privileges (the probe does it); setting
speeds goes through the small root helper `pulse-fand` over a Unix socket."""
import os
import socket
import subprocess
import time

SOCK = "/var/run/pulse-fand.sock"
HELPER_DEST = "/Library/PrivilegedHelperTools/com.pulse.fand"
PLIST_DEST = "/Library/LaunchDaemons/com.pulse.fand.plist"
LABEL = "com.pulse.fand"

MODES = {
    "auto": "macOS decides (default)",
    "balanced": "Quieter than High Performance, still cooler than macOS",
    "performance": "Spins up early and fast to avoid any thermal slowdown",
    "max": "Full throttle - maximum RPM",
    "custom": "Fixed speed you choose",
}


def _lerp(t, t0, t1, f0, f1):
    if t <= t0:
        return f0
    if t >= t1:
        return f1
    return f0 + (f1 - f0) * (t - t0) / (t1 - t0)


class FanController:
    def __init__(self, settings):
        self.settings = settings
        self.level = None          # current commanded fraction 0..1
        self.last_send = 0
        self.last_sent_level = None
        self.peak_until = 0
        self.error = None
        self.applied_auto = False

    # ---- settings
    @property
    def mode(self):
        return self.settings.data.get("fan_mode", "auto")

    @property
    def pct(self):
        return int(self.settings.data.get("fan_pct", 60))

    def set_mode(self, mode, pct=None):
        if mode not in MODES:
            return {"ok": False, "error": "Unknown mode"}
        if mode != "auto" and not self.installed():
            return {"ok": False, "error": "Fan control isn't enabled yet."}
        with self.settings.lock:
            self.settings.data["fan_mode"] = mode
            if pct is not None:
                self.settings.data["fan_pct"] = max(0, min(100, int(pct)))
            self.settings.save()
        self.last_send = 0
        self.applied_auto = False
        if mode == "auto":
            self.release()
        return {"ok": True}

    def controlling(self):
        return self.mode != "auto" and self.installed()

    # ---- helper comms
    def installed(self):
        return os.path.exists(SOCK)

    def send(self, cmd):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(SOCK)
            s.sendall((cmd + "\n").encode())
            data = s.recv(2048).decode()
            s.close()
            reply = data.strip()
            self.error = ("Fan helper refused: it only accepts the user who installed it" if reply == "denied"
                          else "Helper rejected the command" if reply == "error" else None)
            return data
        except OSError as e:
            self.error = "Fan helper not reachable (%s)" % e.strerror
            return None

    def release(self):
        if self.installed():
            self.send("auto")
        self.level = None
        self.applied_auto = True

    # ---- control loop (called every sample)
    def update(self, sample, now):
        fans = sample.get("fans") or []
        if not fans or not self.installed():
            return
        mode = self.mode
        if mode == "auto":
            if not self.applied_auto and any(f[4] for f in fans):
                pass   # someone else (e.g. Macs Fan Control) may be in charge; leave it alone
            return
        t = sample.get("temp") or {}
        temp = max([v for v in (t.get("cpu_max"), t.get("gpu")) if v is not None] or [0])
        cpu = (sample.get("cpu") or {}).get("total", 0)
        gpu = sample.get("gpu") or 0

        if mode == "max":
            target = 1.0
        elif mode == "custom":
            target = self.pct / 100.0
        elif mode == "balanced":
            target = _lerp(temp, 55, 85, 0.0, 1.0)
        else:  # performance: pre-emptive - react to load before heat builds up
            target = max(_lerp(temp, 40, 70, 0.30, 1.0),
                         _lerp(max(cpu, gpu), 30, 80, 0.30, 1.0))
            if temp >= 75 or cpu >= 85:
                self.peak_until = now + 30     # hold high briefly after a burst
            if now < self.peak_until:
                target = max(target, 0.85)

        # Ramp: up immediately (performance/max) or quickly; down gently to avoid pulsing.
        if self.level is None:
            self.level = target
        elif target > self.level:
            step = 1.0 if mode in ("performance", "max", "custom") else 0.15
            self.level = min(target, self.level + step)
        else:
            self.level = max(target, self.level - (0.03 if mode == "performance" else 0.05))

        changed = self.last_sent_level is None or abs(self.level - self.last_sent_level) > 0.02
        if changed or now - self.last_send > 10:        # also the helper's keep-alive
            rpms = ["%.0f" % (f[1] + self.level * (f[2] - f[1])) for f in fans]
            if self.send("set " + " ".join(rpms)) is not None:
                self.last_send = now
                self.last_sent_level = self.level

    def status(self, conflict_pids):
        return {"mode": self.mode, "pct": self.pct, "installed": self.installed(),
                "level": round(self.level * 100) if self.level is not None and self.mode != "auto" else None,
                "error": self.error, "modes": MODES, "conflict": conflict_pids}


def install_helper(src_binary, data_dir):
    """Install the root helper. macOS shows its own password dialog to the user."""
    plist = os.path.join(data_dir, LABEL + ".plist")
    with open(plist, "w") as f:
        f.write("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>--allow-uid</string><string>%d</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
""" % (LABEL, HELPER_DEST, os.getuid()))

    def q(p):
        return "'" + p.replace("'", "'\\''") + "'"
    sh = " && ".join([
        "mkdir -p /Library/PrivilegedHelperTools",
        "(launchctl bootout system/%s 2>/dev/null; true)" % LABEL,
        "cp %s %s" % (q(src_binary), HELPER_DEST),
        "chown root:wheel %s" % HELPER_DEST, "chmod 755 %s" % HELPER_DEST,
        "cp %s %s" % (q(plist), PLIST_DEST),
        "chown root:wheel %s" % PLIST_DEST, "chmod 644 %s" % PLIST_DEST,
        "launchctl bootstrap system %s" % PLIST_DEST,
    ])
    return _admin(sh, "Pulse needs your permission to install a small helper that controls the fans.")


def uninstall_helper():
    sh = "(launchctl bootout system/%s 2>/dev/null; true) && rm -f %s %s %s" % (LABEL, HELPER_DEST, PLIST_DEST, SOCK)
    return _admin(sh, "Pulse needs your permission to remove its fan helper.")


def _admin(sh, prompt):
    script = 'do shell script "%s" with administrator privileges with prompt "%s"' % (
        sh.replace("\\", "\\\\").replace('"', '\\"'), prompt)
    p = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if p.returncode != 0:
        msg = (p.stderr or "").strip()
        return {"ok": False, "error": "Cancelled" if "-128" in msg else (msg or "Failed")}
    for _ in range(20):
        if os.path.exists(SOCK) or "rm -f" in sh:
            break
        time.sleep(0.25)
    return {"ok": True}
