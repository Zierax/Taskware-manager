#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  TASKWARE MANAGER                                           ║
║  Malware-Centric Process Monitor (Linux Only)                    ║
║  100% Offline — Live Malware Analysis & Threat Hunting           ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python3 run_taskware.py
    sudo python3 run_taskware.py    # Full access (memory dumps, strace)

Requirements:
    pip install -r taskware_requirements.txt

Platform:
    Linux only. Requires strace for ML-based syscall analysis.
    Install: sudo apt install strace
"""

import sys
import os

# Enforce Linux
if sys.platform == "win32":
    print("[!] Taskware Manager is designed for Linux only.")
    print("[!] Please run this application on a Linux system.")
    sys.exit(1)

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from taskware.gui.app import run_app

if __name__ == "__main__":
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║  TASKWARE MANAGER v1.0.0                                 ║
    ║  Malware-Centric Process Monitor                         ║
    ║  Platform: Linux                                         ║
       Root: {'YES ✅' if is_root else 'NO ⚠️  (limited access)'}                                     ║
    ║  Loading...                                              ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    if not is_root:
        print("    ⚠️  Running without root. Some features will be limited:")
        print("       - Memory dumps (requires /proc/pid/mem access)")
        print("       - Strace-based ML analysis")
        print("       - Full process listing")
        print("    Tip: Run with 'sudo python3 run_taskware.py' for full access\n")

    run_app()
