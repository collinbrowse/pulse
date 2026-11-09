# Pulse

A lightweight performance, storage and fan monitor for Apple Silicon Macs. It uses only built-in macOS tools and APIs: no `pip install`, no Homebrew, no kernel extensions.

- **Performance:** CPU (overall and per core), memory breakdown, swap and memory pressure, chip/GPU/battery/SSD temperatures, GPU load, network, disk I/O, power draw, and a process list with code-signing info.
- **Automatic flags:**
  - Runaway or leaking processes, sustained CPU load, memory pressure, heavy swap, full disk, heat and throttling.
  - Unusual spikes compared with the last five minutes.
  - Unsigned or unverified programs running from risky locations, swarms of duplicate processes, iOS Simulators left running, broken startup items, and programs reachable from your network.
  - Serious flags also arrive as macOS notifications.
- **Storage:**
  - A step-by-step folder explorer and a list of the largest files.
  - Cleanup suggestions rated *safe* / *review* / *careful*, covering Xcode build data and device support, simulators and their iOS versions, package caches, inactive `node_modules`, old installers, Android emulators and more.
  - Deleting moves files to the Trash or removes them permanently, after you confirm.
  - An "Ask Claude" button hands a storage report to [Claude Code](https://claude.com/claude-code) to plan a cleanup with you.
- **Fans:** live RPM, plus Auto, Balanced, High Performance (spins up early, before heat builds), Full throttle and Custom modes.

## Install

```bash
./build_app.sh
```

This builds `Pulse.app` and copies it to `/Applications` (or `~/Applications`). It needs the Xcode Command Line Tools for `clang`, `swiftc` and `python3`.

To run from source without building the app:

```bash
./start.sh
```

This serves the dashboard at http://127.0.0.1:8765.

## Lightweight by design

- A single long-running native probe (`probe.c`) reads CPU, memory, temperature, network, disk, GPU, fan and process data directly from the kernel and IOKit, so nothing is spawned per sample.
- It samples every 2 seconds while the dashboard is visible and every 10 seconds otherwise; the process list, ports and battery are checked less often. Everything runs at `nice 10`.
- Measured on an M1 Max: about 0.3% of one core in the background and 1–3% with the window open.
- Disk scans run only when you ask, using the C scanner (`fts`), at about 30k files per second.

## Security model

Pulse is split so that no single part has more access than it needs:

| Component | Runs as | Can | Cannot |
|---|---|---|---|
| `Pulse.app` + `server.py` | you | show the dashboard, quit **your** processes, delete files **inside your home folder** after you confirm | delete outside your home folder, or core folders (Library, Documents, Keychains, iCloud, …); it has no Full Disk Access, so macOS also blocks it from protected folders unless you approve one |
| `Pulse Scanner.app` (`scanner.c`) | you; optionally given **Full Disk Access** | list folders and read file sizes | modify, move or delete anything (it has no such code); record names inside personal-data folders (Mail, Messages, Safari, Containers, cloud storage, Photos libraries, …), where only totals are kept; write anywhere except `~/Library/Application Support/Pulse` |
| `pulse-fand` (`fand.c`, optional) | root (LaunchDaemon, installed via the macOS admin prompt) | set fan speeds within the hardware's own min–max range | accept commands from anyone except the user who installed it (checked with `getpeereid`); keep fans in manual mode if Pulse stops, since it returns them to Auto after 30 seconds without contact |

The dashboard server listens only on `127.0.0.1`. It rejects requests with a foreign `Host` header (which blocks DNS rebinding) and requires a custom header on every action (which blocks cross-site requests).

### Removing the fan helper

The **Fans** card has an uninstall option. To remove it manually:

```bash
sudo launchctl bootout system/com.pulse.fand
```

```bash
sudo rm -f /Library/PrivilegedHelperTools/com.pulse.fand /Library/LaunchDaemons/com.pulse.fand.plist
```

## Notes

- Temperatures come from Apple Silicon's HID sensors (a private but widely used API). Fan control uses SMC keys `F*Md`/`F*Tg`.
- Settings and scan results are stored in `~/Library/Application Support/Pulse`. Logs go to `~/Library/Logs/Pulse.log`.
- Built for Apple Silicon. Some readings may be missing on Intel Macs.
