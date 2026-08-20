# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec - System Performance Monitor
======================================
Collects system metrics during load testing:
  - API process: CPU%, memory (RSS/VMS), open file descriptors
  - PostgreSQL container: CPU%, memory, active connections
  - Redis container: CPU%, memory, connected clients, ops/sec, hit rate
  - System: overall CPU%, available memory

Run in a SEPARATE terminal while load test or timing.py is running:
  python tests/load/monitor.py

Press Ctrl+C to stop. Final summary printed on exit.

Requirements:
  pip install psutil --break-system-packages
  the compose stack running (the postgres and redis containers are resolved
  by service name; set WRAPSEC_PG_CONTAINER / WRAPSEC_REDIS_CONTAINER to
  override)
"""

from __future__ import annotations

import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    print("Installing psutil...")
    subprocess.run([sys.executable, "-m", "pip", "install", "psutil", "--break-system-packages"])
    import psutil

SAMPLE_INTERVAL = 2      # seconds between samples

# Compose derives container names from the project, so they are not fixed and
# must be resolved at runtime. Override either variable to point at a container
# directly (a stack started by other means, or a remote name).
COMPOSE_FILE    = "infrastructure/docker/docker-compose.yml"
DOCKER_POSTGRES = os.getenv("WRAPSEC_PG_CONTAINER",    "")
DOCKER_REDIS    = os.getenv("WRAPSEC_REDIS_CONTAINER", "")


def _resolve_container(service: str) -> str:
    """
    Return the running container id for a compose service, or "" if the stack
    is not up. Callers degrade to skipping that metric rather than failing.
    """
    try:
        out = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "ps", "-q", service],
            capture_output = True, text = True, timeout = 10,
        )
        return out.stdout.strip().splitlines()[0] if out.stdout.strip() else ""
    except Exception:
        return ""


DOCKER_POSTGRES = DOCKER_POSTGRES or _resolve_container("postgres")
DOCKER_REDIS    = DOCKER_REDIS    or _resolve_container("redis")

# ── Helpers ───────────────────────────────────────────────────────────────────

def find_api_process() -> psutil.Process | None:
    """Find the uvicorn API process."""
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            if "uvicorn" in cmdline and "api.main" in cmdline:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def docker_stats(container: str) -> dict:
    """Get CPU% and memory from docker stats."""
    try:
        result = subprocess.run(
            ["docker", "stats", container, "--no-stream", "--format",
             "{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {}
        parts = result.stdout.strip().split(",")
        if len(parts) < 3:
            return {}
        cpu_str = parts[0].replace("%", "").strip()
        mem_str = parts[1].strip()  # e.g. "45.2MiB / 7.77GiB"
        mem_pct = parts[2].replace("%", "").strip()
        return {
            "cpu_pct": float(cpu_str) if cpu_str else 0.0,
            "mem_str": mem_str,
            "mem_pct": float(mem_pct) if mem_pct else 0.0,
        }
    except Exception:
        return {}


def redis_info() -> dict:
    """Get Redis metrics via redis-cli."""
    try:
        result = subprocess.run(
            ["docker", "exec", DOCKER_REDIS, "redis-cli", "INFO", "all"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {}
        info = {}
        for line in result.stdout.splitlines():
            if ":" in line and not line.startswith("#"):
                key, _, val = line.partition(":")
                info[key.strip()] = val.strip()
        return {
            "connected_clients":   int(info.get("connected_clients", 0)),
            "used_memory_human":   info.get("used_memory_human", "?"),
            "used_memory_peak_human": info.get("used_memory_peak_human", "?"),
            "keyspace_hits":       int(info.get("keyspace_hits", 0)),
            "keyspace_misses":     int(info.get("keyspace_misses", 0)),
            "instantaneous_ops_per_sec": int(info.get("instantaneous_ops_per_sec", 0)),
            "rejected_connections": int(info.get("rejected_connections", 0)),
            "blocked_clients":     int(info.get("blocked_clients", 0)),
            "evicted_keys":        int(info.get("evicted_keys", 0)),
            "total_commands_processed": int(info.get("total_commands_processed", 0)),
        }
    except Exception:
        return {}


def pg_connections() -> int:
    """Get active PostgreSQL connection count."""
    try:
        result = subprocess.run(
            ["docker", "exec", DOCKER_POSTGRES, "psql", "-U", "wrapsec", "-d", "wrapsec",
             "-t", "-c", "SELECT count(*) FROM pg_stat_activity WHERE datname='wrapsec';"],
            capture_output=True, text=True, timeout=5,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception:
        return 0


def pg_long_queries() -> int:
    """Count queries running longer than 1 second."""
    try:
        result = subprocess.run(
            ["docker", "exec", DOCKER_POSTGRES, "psql", "-U", "wrapsec", "-d", "wrapsec",
             "-t", "-c",
             ("SELECT count(*) FROM pg_stat_activity "
             "WHERE state='active' AND query_start < NOW() - INTERVAL '1 second';")],
            capture_output=True, text=True, timeout=5,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception:
        return 0


# ── Main monitor loop ─────────────────────────────────────────────────────────

def main():
    print("\nWrapSec System Monitor")
    print(f"Sampling every {SAMPLE_INTERVAL}s - press Ctrl+C to stop\n")

    # History for summary
    api_cpu:     list[float] = []
    api_mem_mb:  list[float] = []
    sys_cpu:     list[float] = []
    pg_conns:    list[int]   = []
    redis_ops:   list[int]   = []
    redis_mem:   list[str]   = []

    sample_count = 0

    print(f"{'Time':<10} {'API CPU%':>8} {'API MEM':>10} {'SYS CPU%':>9} "
          f"{'PG conns':>9} {'Redis ops/s':>12} {'Redis mem':>10} {'Redis clients':>14}")
    print("-" * 95)

    try:
        while True:
            now = datetime.now(timezone.utc).strftime("%H:%M:%S")

            # API process
            api_proc = find_api_process()
            if api_proc:
                try:
                    with api_proc.oneshot():
                        a_cpu = api_proc.cpu_percent(interval=None)
                        a_mem = api_proc.memory_info().rss / 1024 / 1024  # MB
                        api_proc.num_fds() if hasattr(api_proc, 'num_fds') else 0
                    api_cpu.append(a_cpu)
                    api_mem_mb.append(a_mem)
                    api_str = f"{a_cpu:>7.1f}% {a_mem:>8.1f}MB"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    api_str = "   N/A"
            else:
                api_str = "   not found"

            # System CPU
            s_cpu = psutil.cpu_percent(interval=None)
            psutil.virtual_memory()
            sys_cpu.append(s_cpu)
            sys_str = f"{s_cpu:>8.1f}%"

            # PostgreSQL
            pg_conn = pg_connections()
            pg_conns.append(pg_conn)

            # Redis
            r_info = redis_info()
            r_ops   = r_info.get("instantaneous_ops_per_sec", 0)
            r_mem   = r_info.get("used_memory_human", "?")
            r_cli   = r_info.get("connected_clients", 0)
            r_evict = r_info.get("evicted_keys", 0)
            r_reject = r_info.get("rejected_connections", 0)
            redis_ops.append(r_ops)
            redis_mem.append(r_mem)

            # Compute hit rate
            hits   = r_info.get("keyspace_hits", 0)
            misses = r_info.get("keyspace_misses", 0)
            total  = hits + misses
            f"{hits/total*100:.0f}%" if total > 0 else "N/A"

            print(
                f"{now:<10} {api_str:<20} {sys_str:<10} "
                f"{pg_conn:>9} {r_ops:>12} {r_mem:>10} {r_cli:>14}",
                end=""
            )

            # Warnings
            warnings = []
            if a_cpu > 80 if api_proc else False:
                warnings.append("⚠ API CPU HIGH")
            if a_mem > 500 if api_proc else False:
                warnings.append("⚠ API MEM HIGH")
            if pg_conn > 20:
                warnings.append("⚠ PG CONNS HIGH")
            if r_evict > 0:
                warnings.append("⚠ REDIS EVICTING")
            if r_reject > 0:
                warnings.append("⚠ REDIS REJECTING")

            if warnings:
                print(f"  {'  '.join(warnings)}", end="")
            print()

            sample_count += 1
            time.sleep(SAMPLE_INTERVAL)

    except KeyboardInterrupt:
        pass

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Monitor Summary ({sample_count} samples over ~{sample_count * SAMPLE_INTERVAL}s)")
    print(f"{'='*60}")

    if api_cpu:
        print("\n  API Process:")
        print(f"    CPU%:   avg={statistics.mean(api_cpu):.1f}%  "
              f"max={max(api_cpu):.1f}%  "
              f"p95={sorted(api_cpu)[int(len(api_cpu)*0.95)]:.1f}%")
        print(f"    Memory: avg={statistics.mean(api_mem_mb):.1f}MB  "
              f"max={max(api_mem_mb):.1f}MB  "
              f"min={min(api_mem_mb):.1f}MB")
        mem_growth = max(api_mem_mb) - min(api_mem_mb)
        if mem_growth > 50:
            print(f"    ⚠ Memory grew {mem_growth:.0f}MB - possible leak")
        else:
            print(f"     Memory stable (grew {mem_growth:.0f}MB)")

    if sys_cpu:
        print("\n  System CPU:")
        print(f"    avg={statistics.mean(sys_cpu):.1f}%  "
              f"max={max(sys_cpu):.1f}%  "
              f"p95={sorted(sys_cpu)[int(len(sys_cpu)*0.95)]:.1f}%")

    if pg_conns:
        print("\n  PostgreSQL connections:")
        print(f"    avg={statistics.mean(pg_conns):.1f}  "
              f"max={max(pg_conns)}  "
              f"min={min(pg_conns)}")
        if max(pg_conns) > 20:
            print(f"    ⚠ Peak connections {max(pg_conns)} - check pool size")
        else:
            print("     Connections healthy")

    if redis_ops:
        print("\n  Redis:")
        print(f"    ops/s: avg={statistics.mean(redis_ops):.0f}  "
              f"max={max(redis_ops)}  "
              f"peak_mem={redis_mem[-1] if redis_mem else '?'}")

    print("\n  Pass criteria:")
    api_cpu_ok  = max(api_cpu)  < 80  if api_cpu  else True
    api_mem_ok  = max(api_mem_mb) < 500 if api_mem_mb else True
    pg_conn_ok  = max(pg_conns) < 25  if pg_conns else True
    mem_stable  = (max(api_mem_mb) - min(api_mem_mb)) < 50 if api_mem_mb else True

    print(f"    API CPU  < 80%:    {' PASS' if api_cpu_ok  else ' FAIL'} (max={max(api_cpu):.1f}%  if api_cpu else 'N/A')")
    print(f"    API MEM  < 500MB:  {' PASS' if api_mem_ok  else ' FAIL'} (max={max(api_mem_mb):.1f}MB if api_mem_mb else 'N/A')")
    print(f"    PG conns < 25:     {' PASS' if pg_conn_ok  else ' FAIL'} (max={max(pg_conns) if pg_conns else 'N/A'})")
    print(f"    Memory stable:     {' PASS' if mem_stable  else ' FAIL'}")
    print()


if __name__ == "__main__":
    # First sample needs a baseline CPU reading - call cpu_percent once to initialise
    psutil.cpu_percent(interval=None)
    proc = find_api_process()
    if proc:
        proc.cpu_percent(interval=None)
        print(f" API process found (PID {proc.pid})")
    else:
        print("⚠ API process not found - start the API first")
        print("  Looking for: uvicorn api.main:app")

    time.sleep(0.5)  # let cpu_percent initialise
    main()
