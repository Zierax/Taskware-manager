# Troubleshooting

This document outlines common issues encountered when running Taskware Manager and how to resolve them.

### 1. Feature "X" is disabled / grayed out in the GUI
**Cause**: The application was launched without root privileges. Many features (Memory Dumping, YARA memory scanning, ML strace attachment) require kernel-level access.
**Solution**: Restart the application using sudo:
```bash
sudo python3 run_taskware.py
```

### 2. Error: "strace command not found"
**Cause**: The ML Syscall analysis engine requires the `strace` utility to be installed on the system.
**Solution**: Install strace via your package manager:
```bash
sudo apt install strace
```

### 3. YARA compilation errors
**Cause**: One or more `.yar` files in the `taskware/yara_rules/` directory contain syntax errors, preventing the `yara-python` module from running.
**Solution**: Check the console output when launching the application. It will specify which rule file failed to compile. Remove or fix the offending YARA rule, then restart the application.

### 4. High CPU Usage
**Cause**: Polling `/proc/` rapidly for hundreds of processes, especially with YARA memory scanning active, can be resource-intensive.
**Solution**: Increase the polling interval in `taskware/config.py` (if configurable) or limit memory scanning exclusively to processes flagged by heuristics, rather than all processes.

### 5. Cannot Dump Memory
**Cause 1**: Not running as root. (See issue #1)
**Cause 2**: Kernel lockdown mechanisms (e.g., YAMA `ptrace_scope`) are preventing memory access even for root.
**Solution**: Temporarily adjust the `ptrace_scope` if necessary (not recommended for production).
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```
