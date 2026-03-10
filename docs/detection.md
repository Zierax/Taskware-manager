# Detection Engine & YARA

The Taskware Manager Detection Engine combines static and behavioral analysis to evaluate the threat level of running processes.

## The Suspicion Scorer
All detection mechanisms feed into a centralized `SuspicionScorer`. This component calculates a weighted percentage (0-100%) indicating the likelihood that a process is malicious.

### Weights (Approximation)
*   Direct YARA Match: +70-100%
*   Heuristic Flag (e.g., execution from `/dev/shm`): +20-40% per flag
*   High ML Prediction (Syscall Anomalies): +40-60%

## Heuristic Analysis
The `Heuristics` engine statically analyzes process metadata without dynamic interception. It looks for:

*   **Suspicious Origins**: Processes running from `/tmp`, `/dev/shm`, `/var/tmp`, or hidden directories (`.m2`, `.config` masquerades).
*   **Obfuscated Commands**: Detection of base64 encoding (`echo ... | base64 -d`), hex encoding, or extreme use of shell variables.
*   **Unusual Process Trees**: Expected binaries (e.g., `svchost` or `bash`) running without their standard parent processes, or a web server spawning an interactive shell (Reverse shell indicator).
*   **Persistence Mechanisms**: Auto-restarting cron jobs spawned from user space, unusual modifications to `.bashrc`, etc.

## YARA Integration
Taskware incorporates `yara-python` to perform deep scanning.

### Rule Location
Rules are stored in `taskware/yara_rules/`. You can add standard `.yar` files to this directory. The engine compiles these upon startup.

### Scanning Capabilities
1.  **File System Scan**: Scans the executable file on disk.
2.  **Memory Scan (Root Required)**: Accesses `/proc/{pid}/mem` to scan the live memory space of a process. This is critical for detecting memory-resident malware (fileless malware) or unpacked payloads.

To update the rules, simply drop new valid YARA files into the `yara_rules` folder and restart the manager.
