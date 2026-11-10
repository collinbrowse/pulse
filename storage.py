"""Storage analysis for Pulse: disk scanner, cleanup suggestions and safe deletion."""
import calendar
import glob
import plistlib
import heapq
import json
import re
import os
import shutil
import stat
import subprocess
import threading
import time

HOME = os.path.realpath(os.path.expanduser("~"))
DATA_ROOT = "/System/Volumes/Data" if os.path.isdir("/System/Volumes/Data/Users") else "/"
MIN_KEEP = 20 * 2 ** 20        # remember folder contents for folders >= 20 MB
TOP_CHILDREN = 200
BIG_FILE = 250 * 2 ** 20


def display(path):
    """Map the data-volume path back to the normal path (/System/Volumes/Data/Users -> /Users)."""
    if DATA_ROOT != "/" and path.startswith(DATA_ROOT):
        rest = path[len(DATA_ROOT):]
        return rest or "/"
    return path


def real(path):
    if DATA_ROOT != "/" and path == "/":
        return DATA_ROOT
    if DATA_ROOT != "/" and path.startswith("/") and not path.startswith("/System/"):
        return DATA_ROOT + path          # /Users, /Applications, /Library, /private ... live on the data volume
    return path


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


# ------------------------------------------------------------------ known space hogs
H = lambda *p: os.path.join(HOME, *p)  # noqa: E731

# safety: safe = regenerates automatically; review = look before deleting; careful = may lose data
KNOWN = [
    {"id": "derived", "path": H("Library/Developer/Xcode/DerivedData"), "name": "Xcode build data (DerivedData)",
     "safety": "safe", "how": "contents", "why": "Intermediate build products. Xcode rebuilds them on the next build."},
    {"id": "devsupport", "path": H("Library/Developer/Xcode/iOS DeviceSupport"), "name": "iOS device support files",
     "safety": "safe", "how": "contents", "why": "Debug symbols for every iOS version you've connected. Re-downloaded when you plug a device in."},
    {"id": "watchsupport", "path": H("Library/Developer/Xcode/watchOS DeviceSupport"), "name": "watchOS device support files",
     "safety": "safe", "how": "contents", "why": "Debug symbols for watchOS versions. Re-downloaded when needed."},
    {"id": "simcaches", "path": H("Library/Developer/CoreSimulator/Caches"), "name": "Simulator caches",
     "safety": "safe", "how": "contents", "why": "Dyld and asset caches for simulators. Rebuilt automatically."},
    {"id": "simdevices", "path": H("Library/Developer/CoreSimulator/Devices"), "name": "iOS Simulator devices",
     "safety": "review", "how": "action:sim_unavailable",
     "why": "Each simulator stores its apps and data here. Pulse removes only simulators for iOS versions you no longer have installed (xcrun simctl delete unavailable)."},
    {"id": "archives", "path": H("Library/Developer/Xcode/Archives"), "name": "Xcode archives",
     "safety": "careful", "how": "review", "why": "Builds you archived for release. Needed to symbolicate crash reports for those versions - keep anything you've shipped."},
    {"id": "xcpg", "path": H("Library/Developer/XCPGDevices"), "name": "Xcode Playground devices",
     "safety": "safe", "how": "contents", "why": "Simulators created for Swift Playgrounds. Recreated when needed."},
    {"id": "xctestdev", "path": H("Library/Developer/XCTestDevices"), "name": "XCTest clone devices",
     "safety": "safe", "how": "contents", "why": "Cloned simulators from parallel UI testing. Recreated on the next test run."},
    {"id": "caches", "path": H("Library/Caches"), "name": "App caches",
     "safety": "safe", "how": "contents", "why": "Temporary data apps keep to load faster. Apps recreate what they need (quit apps first for best results)."},
    {"id": "logs", "path": H("Library/Logs"), "name": "Logs",
     "safety": "safe", "how": "contents", "why": "Diagnostic logs. Only useful when debugging a specific problem."},
    {"id": "brew", "path": H("Library/Caches/Homebrew"), "name": "Homebrew download cache",
     "safety": "safe", "how": "action:brew_cleanup", "why": "Old package downloads. `brew cleanup -s` removes them."},
    {"id": "npm", "path": H(".npm"), "name": "npm cache",
     "safety": "safe", "how": "contents", "why": "Downloaded npm packages. Re-downloaded on the next install."},
    {"id": "yarn", "path": H("Library/Caches/Yarn"), "name": "Yarn cache",
     "safety": "safe", "how": "contents", "why": "Downloaded Yarn packages. Re-downloaded on the next install."},
    {"id": "pnpm", "path": H("Library/pnpm/store"), "name": "pnpm store",
     "safety": "safe", "how": "contents", "why": "Shared pnpm package store. Projects re-link on next install."},
    {"id": "pip", "path": H("Library/Caches/pip"), "name": "pip cache",
     "safety": "safe", "how": "contents", "why": "Downloaded Python wheels."},
    {"id": "gradle", "path": H(".gradle/caches"), "name": "Gradle caches",
     "safety": "safe", "how": "contents", "why": "Android/Gradle build caches and dependencies. Re-downloaded on next build."},
    {"id": "cocoapods", "path": H("Library/Caches/CocoaPods"), "name": "CocoaPods cache",
     "safety": "safe", "how": "contents", "why": "Downloaded pod sources."},
    {"id": "cargo", "path": H(".cargo/registry"), "name": "Rust crate cache",
     "safety": "safe", "how": "contents", "why": "Downloaded crates. Re-fetched by cargo."},
    {"id": "gomod", "path": H("go/pkg/mod"), "name": "Go module cache",
     "safety": "safe", "how": "action:go_clean", "why": "Downloaded Go modules (`go clean -modcache`)."},
    {"id": "avd", "path": H(".android/avd"), "name": "Android emulators",
     "safety": "review", "how": "review", "why": "Each Android Virtual Device keeps a full disk image. Delete emulators you don't use from Android Studio's Device Manager."},
    {"id": "androidsdk", "path": H("Library/Android/sdk/system-images"), "name": "Android system images",
     "safety": "review", "how": "review", "why": "OS images for Android emulators. Remove old API levels in Android Studio's SDK Manager."},
    {"id": "docker", "path": H("Library/Containers/com.docker.docker"), "name": "Docker data",
     "safety": "review", "how": "review", "why": "Docker's virtual disk. Run `docker system prune -a` to drop unused images, or shrink the disk in Docker settings."},
    {"id": "backups", "path": H("Library/Application Support/MobileSync/Backup"), "name": "iPhone/iPad backups",
     "safety": "careful", "how": "review", "why": "Local device backups. Delete old ones in Finder > your device > Manage Backups."},
    {"id": "downloads", "path": H("Downloads"), "name": "Downloads folder",
     "safety": "review", "how": "review", "why": "Installers, archives and files you downloaded. Usually lots of forgotten things."},
    {"id": "trash", "path": H(".Trash"), "name": "Trash",
     "safety": "safe", "how": "action:empty_trash", "why": "Files you've already deleted. Space isn't freed until the Trash is emptied."},
    {"id": "msgattach", "path": H("Library/Messages/Attachments"), "name": "Messages attachments",
     "safety": "careful", "how": "review", "why": "Photos and files from iMessage. Manage in Messages > Settings > Keep messages, or System Settings > Storage."},
    {"id": "mail", "path": H("Library/Mail"), "name": "Mail data",
     "safety": "careful", "how": "review", "why": "Your local mailboxes and attachments. Manage from inside Mail."},
    {"id": "swap", "path": "/private/var/vm", "name": "Swap & sleep image",
     "safety": "careful", "how": "info", "why": "macOS virtual memory. It can't be deleted - it shrinks after a restart and when memory pressure drops."},
]

PROTECTED = {HOME, H("Library"), H("Documents"), H("Desktop"), H("Downloads"), H("Pictures"), H("Movies"),
             H("Music"), H("Applications"), H("Library/Application Support"), H("Library/Containers"),
             H("Library/Group Containers"), H("Library/Preferences"), H(".Trash")}
PROTECTED_PREFIXES = (H("Library/Keychains"), H(".ssh"), H(".gnupg"), H("Library/Mobile Documents"),
                      H("Library/CloudStorage"), H("Library/Preferences"))


def is_project_node_modules(path):
    """A node_modules that belongs to one of your projects (not a global install, tool cache or app bundle)."""
    proj = os.path.dirname(path)
    if not proj.startswith(HOME + "/") or ".app/" in path:
        return False
    if any(part.startswith(".") for part in proj[len(HOME) + 1:].split("/")):
        return False            # ~/.nvm, ~/.npm, ~/.cache, ... are tool-managed
    if "/Library/" in proj + "/":
        return False
    return os.path.exists(os.path.join(proj, "package.json"))


def check_deletable(path):
    """Return (ok, reason). Only things inside your home folder, and never core folders."""
    if not path or not path.startswith("/"):
        return False, "Invalid path"
    path = os.path.normpath(path)
    parent = os.path.realpath(os.path.dirname(path))
    full = os.path.join(parent, os.path.basename(path))
    if not (full + "/").startswith(HOME + "/") or full == HOME:
        return False, "Pulse only deletes things inside your home folder."
    if full in PROTECTED or full.startswith(PROTECTED_PREFIXES):
        return False, "That's a core folder (or holds keys/iCloud data); Pulse won't delete it."
    if not os.path.lexists(full):
        return False, "It no longer exists."
    return True, full


# ------------------------------------------------------------------ scanner
PROTECTED_HINTS = [  # (path, what macOS calls it) - used to tell whether the scanner can see protected data
    (H("Desktop"), "Desktop"), (H("Downloads"), "Downloads"), (H("Documents"), "Documents"),
    (H("Library/Mail"), "Mail"), (H("Library/Messages"), "Messages"), (H("Library/Safari"), "Safari"),
    (H("Library/CloudStorage"), "Cloud storage (iCloud/Dropbox/Drive)"), (H(".Trash"), "Trash"),
    (H("Library/Containers"), "Other apps' data"),
]


class Scanner:
    """Reads results produced by the separate, read-only `pulse-scanner` program.

    The scanner is the only Pulse component meant to hold Full Disk Access. This server
    process (which can delete things) deliberately does not need it, so macOS keeps it out
    of protected locations unless you approve a specific folder."""

    def __init__(self, data_dir, here):
        self.data_dir = data_dir
        self.cache_file = os.path.join(data_dir, "storage_scan.json")
        self.progress_file = os.path.join(data_dir, "scan_progress.json")
        self.system_file = os.path.join(data_dir, "system_scan.json")
        self.loaded_smtime = 0
        self.system_finished = None
        # Inside Pulse.app the scanner is its own tiny app so macOS can grant it (only it)
        # Full Disk Access. When running from source, the bare binary is used.
        app = os.path.join(here, "..", "Library", "Pulse Scanner.app")
        self.scanner_app = os.path.realpath(app) if os.path.isdir(app) else None
        self.scanner_bin = os.path.join(here, "pulse-scanner")
        self.lock = threading.Lock()
        self.dirs, self.big_files, self.node_modules, self.denied_paths = {}, [], [], []
        self.loaded_mtime = 0
        self.finished = self.started = None
        self.files = self.denied = 0
        self._load()

    # ---- results
    def _load(self):
        """Load your scan, and merge in the optional admin system scan (folders outside /Users)."""
        try:
            mt = os.path.getmtime(self.cache_file)
        except OSError:
            return
        try:
            smt = os.path.getmtime(self.system_file)
        except OSError:
            smt = 0
        if (mt, smt) == (self.loaded_mtime, self.loaded_smtime):
            return
        try:
            with open(self.cache_file) as f:
                d = json.load(f)
        except Exception:
            return
        sysd = None
        if smt:
            try:
                with open(self.system_file) as f:
                    sysd = json.load(f)
            except Exception:
                sysd = None
        dirs = d["dirs"]
        big = [tuple(x) for x in d.get("big_files", [])]
        denied = d.get("denied_paths", [])
        if sysd:
            users_key = DATA_ROOT.rstrip("/") + "/Users"
            for k, v in sysd["dirs"].items():
                if k != DATA_ROOT and not k.startswith(users_key):
                    dirs[k] = v                       # system scan saw more here
            sroot, uroot = sysd["dirs"].get(DATA_ROOT), dirs.get(DATA_ROOT)
            if sroot and uroot:
                users = next((c for c in uroot["children"] if c[0] == "Users"), None)
                kids = [c for c in sroot["children"] if c[0] != "Users"] + ([users] if users else [])
                kids.sort(key=lambda c: -c[1])
                dirs[DATA_ROOT] = dict(sroot, children=kids, size=sroot["size"] + (users[1] if users else 0),
                                       files=sroot["files"] + (users[3] if users else 0))
            seen = {b[1] for b in big}
            big += [tuple(x) for x in sysd.get("big_files", []) if x[1] not in seen]
            # system scan resolves "denied" outside /Users; keep the rest
            denied = [p for p in denied if p.startswith("/Users/")] + sysd.get("denied_paths", [])
        with self.lock:
            self.dirs = dirs
            self.big_files = big
            self.node_modules = d.get("node_modules", [])
            self.denied_paths = denied
            self.finished, self.started = d.get("finished"), d.get("started")
            self.files, self.denied = d.get("files", 0), d.get("denied", 0)
            self.system_finished = sysd.get("finished") if sysd else None
            self.loaded_mtime, self.loaded_smtime = mt, smt

    def system_progress(self):
        try:
            with open(os.path.join(self.data_dir, "system_progress.json")) as f:
                return json.load(f)
        except Exception:
            return None

    def deep_scan(self):
        """One-off, read-only scan of root-only folders. macOS asks for an admin password.
        Runs a root-owned copy of the scanner so the binary can't be swapped by another app."""
        src = os.path.join(self.scanner_app, "Contents", "MacOS", "pulse-scanner") if self.scanner_app else self.scanner_bin
        dest = "/Library/PrivilegedHelperTools/com.pulse.scanner"

        def q(p):
            return "'" + p.replace("'", "'\\''") + "'"
        sh = ("mkdir -p /Library/PrivilegedHelperTools && "
              "(cmp -s %s %s || (cp %s %s && chown root:wheel %s && chmod 755 %s)) && "
              "%s --system --as-uid %d --out %s" % (q(src), dest, q(src), dest, dest, dest, dest, os.getuid(),
                                                    q(self.data_dir)))
        script = 'do shell script "%s" with administrator privileges with prompt "%s"' % (
            sh.replace("\\", "\\\\").replace('"', '\\"'),
            "Pulse wants to measure (read-only) system folders that need administrator access.")
        p = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        if p.returncode != 0:
            err = (p.stderr or "").strip()
            return {"ok": False, "error": "Cancelled" if "-128" in err else (err[-300:] or "Failed")}
        self._load()
        return {"ok": True}

    def _save(self):
        try:
            tmp = self.cache_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"dirs": self.dirs, "big_files": self.big_files, "node_modules": self.node_modules,
                           "denied_paths": self.denied_paths, "finished": self.finished, "started": self.started,
                           "files": self.files, "denied": self.denied}, f, separators=(",", ":"))
            os.replace(tmp, self.cache_file)
            self.loaded_mtime = os.path.getmtime(self.cache_file)
        except Exception:
            pass

    def _progress(self):
        try:
            with open(self.progress_file) as f:
                p = json.load(f)
        except Exception:
            return None
        if p.get("status") == "scanning":
            try:
                os.kill(p["pid"], 0)
            except (OSError, KeyError):
                p["status"] = "interrupted"
        return p

    @property
    def status(self):
        p = self._progress()
        if p and p["status"] == "scanning":
            return "scanning"
        self._load()
        return "done" if self.finished else "idle"

    # ---- running the scanner
    def _launch(self, args, wait):
        if self.scanner_app:
            cmd = ["open", "-n", "-g"] + (["-W"] if wait else []) + ["-a", self.scanner_app, "--args"] + args
        else:
            cmd = [self.scanner_bin] + args
        if wait:
            subprocess.run(cmd, capture_output=True, timeout=120)
        else:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start(self):
        if self.status == "scanning":
            return False
        try:
            os.remove(self.progress_file)
        except OSError:
            pass
        self._launch(["--out", self.data_dir], wait=False)
        return True

    def quick_scan(self, path):
        """Ask the scanner for one small folder that the full scan didn't keep in detail."""
        out = os.path.join(self.data_dir, "quick_scan.json")
        try:
            os.remove(out)
        except OSError:
            pass
        try:
            self._launch(["--out", self.data_dir, "--quick", display(real(path))], wait=True)
            with open(out) as f:
                d = json.load(f)
        except Exception:
            return None
        with self.lock:
            self.dirs.update(d.get("dirs", {}))
        return self.dirs.get(real(path))

    def size_of(self, path):
        rp = real(path)
        node = self.dirs.get(rp)
        if node:
            return node["size"]
        parent = self.dirs.get(os.path.dirname(rp))
        if parent:
            for c in parent["children"]:
                if c[0] == os.path.basename(rp):
                    return c[1]
        return None

    def priv_of(self, path):
        """Bytes deleting `path` would actually free (not shared with APFS clones), if measured."""
        rp = real(path)
        node = self.dirs.get(rp)
        if node and "priv" in node:
            return node["priv"]
        parent = self.dirs.get(os.path.dirname(rp))
        if parent:
            for c in parent["children"]:
                if c[0] == os.path.basename(rp) and len(c) > 4:
                    return c[4]
        return None

    # ---- views
    def node(self, path):
        rp = real(path)
        n = self.dirs.get(rp)
        if n is None and self.status != "scanning":
            n = self.quick_scan(path)
        if n is None:
            return None
        kids = []
        for c in n["children"]:
            name, size, isdir, files = c[:4]
            priv = c[4] if len(c) > 4 else None
            cp = os.path.join(display(rp), name)
            ok, _ = check_deletable(cp)
            kid = {"name": name, "path": cp, "size": size, "dir": isdir, "files": files, "priv": priv,
                   "deletable": ok, "known": next((k["id"] for k in KNOWN if k["path"] == cp), None)}
            if isdir and UUID_RE.match(name) and any(display(rp) == f for f, _, _ in SIM_SETS):
                dev = sim_devices().get(name)
                if dev:
                    kid.update(label=dev["label"], detail=" · ".join(sim_detail(dev)), simdev=dev["udid"],
                               last_used=dev["last_used"], booted=dev["booted"])
            elif isdir and name == "Devices" and display(rp) == H("Library/Developer/CoreSimulator"):
                kid["label"] = "Devices (iOS Simulators)"
            kids.append(kid)
        return {"path": display(rp), "size": n["size"], "priv": n.get("priv"), "files": n["files"], "children": kids,
                "other": n["other"], "other_count": n["other_count"], "done": n["done"]}

    def suggestions(self):
        self._load()
        out = []
        for k in KNOWN:
            size = self.size_of(k["path"])
            if not size or size < 100 * 2 ** 20:
                continue
            out.append(dict(k, size=size, frees=self.priv_of(k["path"])))
        # stale node_modules (project untouched for 30+ days)
        now = time.time()
        stale = [n for n in self.node_modules if now - n["mtime"] > 30 * 86400
                 and is_project_node_modules(n["path"])]
        if stale:
            out.append({"id": "node_modules", "name": "node_modules in inactive projects", "safety": "safe",
                        "how": "list", "size": sum(n["size"] for n in stale), "path": None,
                        "why": "%d JavaScript projects untouched for 30+ days. `npm install` restores them." % len(stale),
                        "items": [dict(n, deletable=check_deletable(n["path"])[0])
                                  for n in sorted(stale, key=lambda n: -n["size"])[:60]]})
        old_installers = [{"path": p, "size": s, "mtime": m, "deletable": check_deletable(p)[0]} for s, p, m in self.big_files
                          if p.lower().endswith((".dmg", ".pkg", ".iso", ".xip", ".ipsw"))]
        if old_installers:
            out.append({"id": "installers", "name": "Installers & disk images", "safety": "review", "how": "list",
                        "size": sum(i["size"] for i in old_installers), "path": None,
                        "why": "Large .dmg/.pkg/.iso/.xip/.ipsw files. Once an app is installed the installer isn't needed.",
                        "items": sorted(old_installers, key=lambda n: -n["size"])})
        devs = [d for d in sim_devices(self).values() if d["set"] is None]
        for d in devs:
            d["size"] = self.size_of(d["path"]) or 0
            d["frees"] = self.priv_of(d["path"])
        for sg in out:
            if sg["id"] == "simdevices" and devs:
                sg["items"] = [{"path": d["label"], "simdev": d["udid"], "size": d["size"], "frees": d["frees"],
                                "mtime": d["last_used"],
                                "detail": " · ".join(sim_detail(d)), "deletable": not d["booted"],
                                "folder": d["path"]}
                               for d in sorted(devs, key=lambda d: -d["size"])]
                sg["no_bulk"] = True
                sg["why"] = ("Each simulator keeps its own apps and data. Most of that is usually shared (APFS "
                             "clones) with other simulators and Xcode builds, so deleting one frees only its "
                             "'frees' amount; shared space comes back once every copy is gone.")
        rts = sim_runtimes()
        if rts:
            out.append({"id": "simruntimes", "name": "Simulator runtimes", "safety": "review", "how": "list",
                        "size": sum(r["size"] for r in rts), "path": None,
                        "why": "Installed iOS simulator system images (stored as separate disk images). Remove versions "
                               "you no longer test on; Xcode can re-download any of them.",
                        "items": rts})
        rank = {"safe": 0, "review": 1, "careful": 2}
        out.sort(key=lambda s: (rank[s["safety"]], -s["size"]))
        return out

    def state(self):
        self._load()
        p = self._progress() or {}
        scanning = p.get("status") == "scanning"
        root = self.dirs.get(DATA_ROOT)
        denied = set(self.denied_paths)
        hidden = [label for path, label in PROTECTED_HINTS if display(path) in denied or path in denied]
        return {"status": "scanning" if scanning else ("done" if self.finished else "idle"),
                "files": p.get("files", self.files) if scanning else self.files,
                "bytes": p.get("bytes", 0), "current": p.get("current", ""),
                "started": self.started, "finished": self.finished, "denied": self.denied,
                "root": "/", "home": HOME, "scanned_total": root["size"] if root else None,
                "hidden_locations": hidden, "scanner_app": self.scanner_app,
                "system_scan": {"finished": self.system_finished,
                                "running": (self.system_progress() or {}).get("status") == "scanning"},
                "denied_sample": self.denied_paths[:60]}

    def large_files(self):
        return [{"path": p, "size": s, "mtime": m, "deletable": check_deletable(p)[0]}
                for s, p, m in sorted(self.big_files, reverse=True)]

    def forget(self, path, freed):
        """Update cached sizes after a deletion so the UI reflects it without a rescan."""
        rp = real(path)
        for key in list(self.dirs):
            if key == rp or key.startswith(rp + "/"):
                del self.dirs[key]
        p = rp
        while True:
            parent = os.path.dirname(p)
            node = self.dirs.get(parent)
            if node:
                node["size"] = max(0, node["size"] - freed)
                for c in node["children"]:
                    if c[0] == os.path.basename(p):
                        c[1] = max(0, c[1] - freed)
                if p == rp:
                    node["children"] = [c for c in node["children"] if c[0] != os.path.basename(p)]
                node["children"].sort(key=lambda c: -c[1])
            if parent == p or parent in ("/", ""):
                break
            p = parent
        self.big_files = [b for b in self.big_files if not (b[1] == path or b[1].startswith(path + "/"))]
        heapq.heapify(self.big_files)
        self.node_modules = [n for n in self.node_modules if not n["path"].startswith(path)]
        self._save()


# ------------------------------------------------------------------ deletion
def dir_size(path):
    total = 0
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_blocks * 512
            except OSError:
                pass
    return total


def move_to_trash(path):
    trash = os.path.join(HOME, ".Trash")
    base = os.path.basename(path)
    dest = os.path.join(trash, base)
    i = 1
    while os.path.lexists(dest):
        stem, ext = os.path.splitext(base)
        dest = os.path.join(trash, "%s %s%s" % (stem, time.strftime("%H.%M.%S"), ext if i == 1 else " %d%s" % (i, ext)))
        i += 1
    shutil.move(path, dest)


def remove(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, ignore_errors=True)
    else:
        os.remove(path)


def delete_path(path, mode):
    """mode: 'trash' | 'permanent' | 'contents' (permanently empty a folder, keep the folder)."""
    ok, full = check_deletable(path)
    if not ok:
        # Known cache folders are protected as a whole but their contents may be cleared.
        if not (mode == "contents" and any(k["path"] == path for k in KNOWN)):
            return {"ok": False, "error": full}
        full = os.path.realpath(path)
        if not (full + "/").startswith(HOME + "/"):
            return {"ok": False, "error": "Pulse only deletes things inside your home folder."}
    size = dir_size(full) if os.path.isdir(full) and not os.path.islink(full) else os.lstat(full).st_blocks * 512
    errors = []
    try:
        if mode == "trash":
            move_to_trash(full)
        elif mode == "contents":
            for e in os.scandir(full):
                try:
                    remove(e.path)
                except OSError as ex:
                    errors.append(str(ex))
        else:
            remove(full)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    after = dir_size(full) if mode == "contents" and os.path.isdir(full) else 0
    freed = max(0, size - after)
    return {"ok": True, "freed": freed if mode != "trash" else 0, "moved": size if mode == "trash" else 0,
            "errors": errors[:5], "path": display(full)}


ACTIONS = {
    "sim_unavailable": (["xcrun", "simctl", "delete", "unavailable"], "Deleted simulators for uninstalled iOS versions"),
    "brew_cleanup": (["/opt/homebrew/bin/brew" if os.path.exists("/opt/homebrew/bin/brew") else "brew", "cleanup", "-s", "--prune=all"],
                     "Cleaned Homebrew cache"),
    "go_clean": (["go", "clean", "-modcache"], "Cleared Go module cache"),
    "empty_trash": (["osascript", "-e", 'tell application "Finder" to empty trash'], "Emptied the Trash"),
}


SIM_SETS = [  # (folder, label, simctl --set argument or None for the default set)
    (H("Library/Developer/CoreSimulator/Devices"), None, None),
    (H("Library/Developer/XCTestDevices"), "Test clone", H("Library/Developer/XCTestDevices")),
    (H("Library/Developer/XCPGDevices"), "Playground", H("Library/Developer/XCPGDevices")),
]
UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_sim_cache = {"t": 0, "v": {}}


_type_names = {}


def _pretty_type(ident):
    """Device type display name from Xcode (e.g. 'iPad Air 11-inch (M4)')."""
    if not _type_names:
        code, out = run(["xcrun", "simctl", "list", "devicetypes", "-j"], timeout=20)
        try:
            for t in json.loads(out[out.index("{"):])["devicetypes"]:
                _type_names[t["identifier"]] = t["name"]
        except Exception:
            _type_names["_"] = ""
    return _type_names.get(ident) or (ident or "").rsplit(".", 1)[-1].replace("-", " ") or "Simulator"


def _pretty_runtime(ident):
    tail = (ident or "").rsplit(".", 1)[-1]          # iOS-27-0
    m = re.match(r"([A-Za-z]+)-(\d+)-(\d+)", tail)
    return "%s %s.%s" % m.groups() if m else tail


def sim_devices(scanner=None):
    """udid -> human description of every simulator, from each device's own device.plist."""
    if time.time() - _sim_cache["t"] < 60:
        return _sim_cache["v"]
    out = {}
    for folder, set_label, set_arg in SIM_SETS:
        for plist in glob.glob(os.path.join(folder, "*", "device.plist")):
            udid = os.path.basename(os.path.dirname(plist))
            if not UUID_RE.match(udid):
                continue
            try:
                with open(plist, "rb") as f:
                    d = plistlib.load(f)
            except Exception:
                continue
            path = os.path.dirname(plist)
            apps = sorted({os.path.basename(a)[:-4] for a in
                           glob.glob(os.path.join(path, "data/Containers/Bundle/Application/*/*.app"))})
            dtype, runtime = _pretty_type(d.get("deviceType")), _pretty_runtime(d.get("runtime"))
            name = d.get("name") or dtype
            used = d.get("lastUsedAt")
            used_ts = calendar.timegm(used.utctimetuple()) if hasattr(used, "utctimetuple") else 0
            booted = d.get("state") == 3
            label = name if name == dtype else "%s (%s)" % (name, dtype)
            label += " · " + runtime
            out[udid] = {
                "udid": udid, "path": path, "name": name, "type": dtype, "runtime": runtime,
                "label": label, "booted": booted, "last_used": used_ts, "apps": apps,
                "set": set_label, "set_arg": set_arg,
                "size": scanner.size_of(path) if scanner else None,
            }
    _sim_cache.update(t=time.time(), v=out)
    return out


def sim_detail(dev):
    bits = ["Running now" if dev["booted"] else "Not running"]
    if dev["set"]:
        bits.append(dev["set"])
    bits.append(("apps: " + ", ".join(dev["apps"][:6]) + (" +%d" % (len(dev["apps"]) - 6) if len(dev["apps"]) > 6 else ""))
                if dev["apps"] else "no apps installed")
    return bits


_rt_cache = {"t": 0, "v": []}


def sim_runtimes():
    """Installed simulator runtimes via simctl (cached for 10 minutes)."""
    if time.time() - _rt_cache["t"] < 600:
        return _rt_cache["v"]
    code, out = run(["xcrun", "simctl", "runtime", "list", "-j"], timeout=30)
    res = []
    try:
        data = json.loads(out[out.index("{"):]) if code == 0 else {}
        for rid, r in data.items():
            used = r.get("lastUsedAt")
            ts = calendar.timegm(time.strptime(used[:19], "%Y-%m-%dT%H:%M:%S")) if used else 0
            res.append({"runtime": rid, "size": r.get("sizeBytes", 0), "mtime": ts,
                        "path": "%s %s (%s)%s" % (r.get("platformIdentifier", "iOS").split(".")[-1].replace("simulator", " Simulator"),
                                                 r.get("version", "?"), r.get("build", "?"),
                                                 "" if used else " - never used"),
                        "deletable": bool(r.get("deletable", True))})
    except Exception:
        pass
    res.sort(key=lambda r: r["mtime"])
    _rt_cache.update(t=time.time(), v=res)
    return res


def settle_freed(before, wait=3.0):
    """Free-space gain since `before`, after giving APFS a moment to release blocks."""
    if before is None:
        return 0
    time.sleep(wait)
    vol = "/System/Volumes/Data" if os.path.exists("/System/Volumes/Data") else "/"
    return max(0, shutil.disk_usage(vol).free - before)


def run_action(name):
    forget_path = None
    m = re.match(r"^sim_device:([0-9A-Fa-f-]{36})$", name or "")
    if m:
        udid = m.group(1).upper()
        dev = sim_devices().get(udid)
        if not dev:                      # created since the last look: refresh once
            _sim_cache["t"] = 0
            dev = sim_devices().get(udid)
        if not dev:
            return {"ok": False, "error": "That simulator no longer exists"}
        if dev["booted"]:
            return {"ok": False, "error": "%s is running - shut it down first" % dev["name"]}
        cmd = ["xcrun", "simctl"] + (["--set", dev["set_arg"]] if dev["set_arg"] else []) + ["delete", dev["udid"]]
        label = "Deleted simulator %s" % dev["label"]
        forget_path = dev["path"]
        _sim_cache["t"] = 0
        m = None
    else:
        m = re.match(r"^sim_runtime:([0-9A-Fa-f-]{36})$", name or "")
    if m:
        cmd, label = ["xcrun", "simctl", "runtime", "delete", m.group(1)], "Deleted simulator runtime"
        _rt_cache["t"] = 0
    elif name.startswith("sim_device:"):
        pass
    elif name not in ACTIONS:
        return {"ok": False, "error": "Unknown action"}
    else:
        cmd, label = ACTIONS[name]
    before = shutil.disk_usage("/System/Volumes/Data" if os.path.exists("/System/Volumes/Data") else "/").free
    code, out = run(cmd, timeout=600)
    after = shutil.disk_usage("/System/Volumes/Data" if os.path.exists("/System/Volumes/Data") else "/").free
    return {"ok": code == 0, "label": label, "output": out[-800:], "freed": max(0, after - before),
            "free_before": before,
            "forget": forget_path if code == 0 else None,
            "error": None if code == 0 else (out[-300:] or "Command failed")}


def claude_report(scanner, disk):
    """Markdown report Claude can read to plan a cleanup."""
    gb = lambda n: "%.2f GB" % (n / 2 ** 30)  # noqa: E731
    lines = ["# Pulse storage report", "",
             "Generated %s. Startup disk: %s used of %s, %s free." %
             (time.strftime("%Y-%m-%d %H:%M"), gb(disk["used"]), gb(disk["total"]), gb(disk["free"])), "",
             "## Cleanup candidates (Pulse's classification)", ""]
    for s in scanner.suggestions():
        lines.append("- **%s** - %s - safety: %s - %s%s" % (s["name"], gb(s["size"]), s["safety"], s["why"],
                                                          (" Path: `%s`" % s["path"]) if s.get("path") else ""))
        for it in s.get("items", [])[:25]:
            lines.append("  - `%s` (%s)" % (it["path"], gb(it["size"])))
    lines += ["", "## Largest folders in the home folder (>= 1 GB, up to 4 levels deep)", ""]

    def walk(path, depth):
        node = scanner.dirs.get(real(path))
        if not node or depth > 4:
            return
        for name, size, isdir, _ in node["children"]:
            if size < 2 ** 30:
                break
            p = os.path.join(path, name)
            lines.append("%s- `%s` %s%s" % ("  " * depth, p, gb(size), "" if isdir else " (file)"))
            if isdir:
                walk(p, depth + 1)
    walk(HOME, 0)
    lines += ["", "## Largest folders outside home (>= 2 GB)", ""]
    root = scanner.dirs.get(real("/"))
    if root:
        for name, size, isdir, _ in root["children"]:
            if size >= 2 * 2 ** 30 and "/" + name != "/Users":
                lines.append("- `/%s` %s" % (name, gb(size)))
    lines += ["", "## Largest files", ""]
    for f in scanner.large_files()[:60]:
        lines.append("- `%s` %s, modified %s" % (f["path"], gb(f["size"]), time.strftime("%Y-%m-%d", time.localtime(f["mtime"]))))
    return "\n".join(lines) + "\n"
