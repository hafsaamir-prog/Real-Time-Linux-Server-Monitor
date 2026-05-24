# ServerPulse — Real-Time Linux Server Health Monitor

A terminal dashboard that continuously monitors your Linux system in real-time.

```
╔══════════════ ServerPulse — Real-Time Linux Monitor ════════════════╗
║ Host: myserver  OS: Ubuntu 22.04 LTS  Kernel: 5.15.0  Up: 03:12:45 ║
║ CPU  [#################............]  56.2%  ▁▂▄▅▆▇▇▆              ║
║ Mem  [###########.................]  38.1%                           ║
║ Disk [####################........]  66.7%  /  220.3/400.0 GB       ║
║ Net  eth0  ↓ 1.2 MB/s  ↑ 0.3 MB/s                                   ║
╠══════════════════════ Alerts ═══════════════════════════════════════╣
║ [OK] All systems nominal                                             ║
╠══════════════ Processes (top 10 by CPU) ════════════════════════════╣
║  PID     USER         CPU%        MEM        TIME      COMMAND       ║
║  1234    postgres     12.3%    512 MB    00:04:33  /usr/bin/psql ... ║
╚═════════════════════════════════════════════════════════════════════╝
```

## Features

- **CPU monitor** with real-time sparkline history graph
- **Memory monitor** using MemAvailable for accurate readings
- **Disk monitor** — tracks any filesystem (e.g. `/`, `/home`, `/data`)
- **Network monitor** — live bandwidth per interface from `/proc/net/dev`
- **Colour-coded alerts** — green / yellow / red based on configurable thresholds
- **Event logging** — CRITICAL alerts are timestamped to `./logs/events_YYYY-MM-DD.log`
- **Hourly summaries** — average + peak metrics saved to `./logs/summary_*.txt`
- **Process table** — top N processes sorted by CPU usage

## Customising Thresholds

Edit the defaults in `include/alert_manager.h`:

```cpp
Threshold cpu_thresh_    {0.70f, 0.90f};  // warn at 70%, critical at 90%
Threshold memory_thresh_ {0.75f, 0.90f};
Threshold disk_thresh_   {0.80f, 0.95f};
```

## Quit

Press **q** to exit cleanly.
