# Architecture Overview

Taskware Manager is designed as a modular, offline-first process monitoring tool. It combines several analysis components into a unified graphical interface, providing analysts with a comprehensive view of system activity.

## System Components

The architecture is divided into the following main components:

### 1. GUI Layer (`taskware/gui/`)
Built using PyQt6, the GUI provides real-time updates and an interactive dashboard. It allows users to filter processes, view detailed analytics, and execute actions (e.g., terminate processes, dump memory).

### 2. Core Monitoring (`taskware/core/`)
Handles the low-level data collection:
*   **Process Tracking**: Wraps around `psutil` to securely extract running process details, child-parent trees, and command-line arguments.
*   **Memory Management**: Facilitates secure reading of `/proc/<pid>/mem` for dumping and string extraction.

### 3. Detection Engine (`taskware/detection/`)
The brain of the system, comprising three sub-engines:
*   **YARA Scanner**: Compares memory and disk images against predefined malware signatures.
*   **Heuristics Engine**: Evaluates process behavior (e.g., suspicious paths like `/tmp/`, encoded command-line arguments, unusual child processes).
*   **Machine Learning (ML)**: Uses `strace` to intercept syscalls and scores their likelihood of being malicious based on a trained model.

### 4. Data Storage (`taskware/database/`)
A lightweight, local SQLite database stores historical process executions, generated alerts, and known threat hashes, enabling historical analysis and trend matching without internet connectivity.

## Data Flow

1.  **Polling**: The GUI loop periodically requests process updates from the Core Monitor.
2.  **Analysis**: For each updated/new process, the Core Monitor feeds the details into the Detection Engine.
3.  **Triage**: The Heuristics and YARA scanners run immediately. If flagged as suspicious (or explicitly requested), the ML engine begins a short `strace` session.
4.  **Reporting**: A combined "Suspicioun Score" is generated and returned to the GUI for display.
5.  **Logging**: High-suspicion events or manually triggered alerts are logged in the SQLite Database.
