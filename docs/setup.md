# Taskware Manager Setup & Installation

This document details the process for setting up Taskware Manager on your Linux system.

## 1. System Requirements

*   **Operating System**: Linux (Ubuntu/Debian recommended)
*   **Privileges**: Root access (sudo) is required for most advanced features (memory dumping, strace).
*   **Python**: Python 3.8+

## 2. System Dependencies

Before installing Python packages, ensure the necessary system utilities are present:

```bash
sudo apt update
sudo apt install strace python3 python3-pip python3-venv libmagic1
```
*(Note: `libmagic1` is required by the `python-magic` package for file type detection).*

## 3. Python Environment Setup

It is highly recommended to use a virtual environment to manage dependencies:

```bash
# Navigate to the directory
cd /path/to/MALWARE_MONITOR

# Create a virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```

## 4. Install Requirements

Install the necessary python modules using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

## 5. Running the Application

### Standard Privileges
For simple process monitoring without access to kernel-level details or memory dumping:
```bash
python3 run_taskware.py
```

### Root Privileges
For full capabilities (strongly recommended for threat hunting):
```bash
sudo python3 run_taskware.py
```
*(If using a virtual environment, you may need to specify the path to the python binary: `sudo ./venv/bin/python3 run_taskware.py`)*

## 6. Model Training (Optional)
If you wish to retrain the ML model for syscall analysis, refer to the [Machine Learning Module](ml_analysis.md) documentation.
