# Machine Learning Syscall Analysis

The Machine Learning (ML) module in Taskware Manager provides advanced behavioral analysis by monitoring raw system calls (syscalls) made by a process. This allows for the detection of malicious activity that might bypass traditional signature-based scanners.

## Operational Workflow

1.  **Strace Hooking**: Upon trigger (heuristic-based or manual), the engine utilizes the `strace` utility to attach to the target process.
2.  **Syscall Extraction**: It captures a sequential stream of system calls (e.g., `openat`, `socket`, `connect`, `execve`, `mmap`) within a specific sampling window.
3.  **Feature Vectorization**: The raw sequence is transformed into numerical feature vectors, often using frequency analysis (TF-IDF or bag-of-words approaches) of syscall types.
4.  **ML Inference**: Feature vectors are processed by a pre-trained classifier that outputs a probability score, identifying patterns consistent with malicious behavior (e.g., ransomware encryption patterns or anomalous network callbacks).

## Model Architecture

*   **Algorithm**: Utilizes ensemble methods such as **Random Forest** or **Gradient Boosting (XGBoost/LightGBM)** for robust classification of non-linear behavioral traits.
*   **Training Data**: Models are trained on extensive datasets comprising syscall traces from both benign system processes and diverse malware families (Trojans, Ransomware, Rootkits).

## Deployment and Storage

*   **Location**: Pre-trained models reside in the `./model/` directory of the application root.
*   **Format**: Models are stored as `.joblib` or `.pkl` files, accompanied by necessary preprocessing metadata (e.g., `StandardScaler` parameters).

## Retraining Pipeline

To update or replace the default model:

1.  **Data Collection**: Gather syscall sequences from representative benign and malicious samples.
2.  **Preprocessing**: Apply the same feature extraction logic used in the core engine.
3.  **Training**: Train a scikit-learn compatible classifier.
4.  **Export**: Serialize the model using `joblib` into the `./model/` directory. Ensure the input vector dimensions match the expectations in `taskware/core/ml_engine.py`.

---

**Reference Model**: [Malware-LinuxTypes-Detector-ML](https://github.com/Zierax/Malware-LinuxTypes-Detector-ML)

