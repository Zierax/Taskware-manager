"""
Prediction utility for system call sequence analysis (Python 3).
Optimized for malware type prediction from syscall sequences in sample.csv format.

This module provides functions for loading a trained model, predicting malware types from system call sequences,
and reading input data from CSV or text files.

You can import and use the main prediction function `run_prediction` in your own scripts, e.g. in run.py:

    from predict import run_prediction

    results = run_prediction(
        text="execve brk mmap openat fstat",
        proba=True,
        limit=10,
        top_n=3,
        output=None
    )
    print(results)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Union
import csv

import warnings
import joblib
import pandas as pd
import numpy as np

# Suppress all scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=FutureWarning, module="sklearn")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
warnings.filterwarnings("ignore", message=".*X does not have valid feature names.*")

# Import HandcraftedFeatures to register class for joblib model loading
from model_features import HandcraftedFeatures

# Backward-compat alias: some serialized pipelines may reference 'features.HandcraftedFeatures'.
# Ensure that import path resolves by aliasing our package module into sys.modules.
try:
    from . import model_features as _features_mod  # type: ignore
    sys.modules.setdefault('features', _features_mod)
except Exception:
    pass

MODEL_PATH = Path(__file__).parent / "artifacts" / "model.joblib"

def load_model() -> Tuple[Any, List[str]]:
    """Load the trained model pipeline and class labels."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Please train first.")
    pipeline = joblib.load(MODEL_PATH)
    classes = pipeline.classes_ if hasattr(pipeline, 'classes_') else []
    return pipeline, classes

def predict_texts(texts: List[str], proba: bool = False) -> Tuple[np.ndarray, Optional[np.ndarray]]:

    if not texts:
        return np.array([]), None if not proba else (np.array([]), None)
    pipeline, _ = load_model()
    if hasattr(pipeline, "predict_proba"):
        if proba:
            probs = pipeline.predict_proba(texts)
            preds = pipeline.predict(texts)
            return preds, probs
        else:
            preds = pipeline.predict(texts)
            return preds, None
    return pipeline.predict(texts), None

def read_texts_from_csv(path: Path) -> List[str]:
    """
    Read system call sequences from CSV file.
    Tries to auto-detect the column containing the syscalls.
    If only one column, uses that column.
    If multiple columns, tries to find a column with 'text', 'sequence', 'api', 'calls', or 'syscalls' in the header.
    If no header, uses the first column.
    """
    try:
        # Try reading with header first
        try:
            df = pd.read_csv(path, header=0, encoding="utf-8")
            if df.empty:
                return []
            # Try to find a likely column
            lower_cols = [str(c).lower() for c in df.columns]
            candidates = ["text", "sequence", "api", "calls", "syscalls"]
            col_idx = None
            for cand in candidates:
                if cand in lower_cols:
                    col_idx = lower_cols.index(cand)
                    break
            if col_idx is not None:
                col = df.columns[col_idx]
                return df[col].astype(str).tolist()
            # If only one column, use it
            if len(df.columns) == 1:
                return df.iloc[:, 0].astype(str).tolist()
            # Otherwise, fallback to first column
            return df.iloc[:, 0].astype(str).tolist()
        except Exception:
            # If header read fails, try no header
            df = pd.read_csv(path, header=None, encoding="utf-8")
            if df.empty:
                return []
            # If only one column, use it
            if df.shape[1] == 1:
                return df.iloc[:, 0].astype(str).tolist()
            # If more than one column, treat each row as a sequence by joining all columns
            else:
                return [' '.join([str(x) for x in row if pd.notnull(x)]).strip() for row in df.values if any([str(x).strip() for x in row if pd.notnull(x)])]
    except Exception as exc:
        if "field larger than field limit" in str(exc).lower():
            csv.field_size_limit(10 ** 9)
            return read_texts_from_csv(path)
        raise

def read_texts_from_file(path: Path) -> List[str]:
    """Read system call sequences from newline-delimited file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip()]

def format_proba(probs: np.ndarray, classes: List[str], top_n: int = 3) -> str:
    """Format probability output for top N predictions."""
    if probs is None or len(probs) == 0:
        return ""
    top_indices = np.argsort(probs)[-top_n:][::-1]
    return ", ".join(f"{classes[i]}:{probs[i]:.2f}" for i in top_indices)

def run_prediction(
    text: Optional[str] = None,
    csv_path: Optional[Union[str, Path]] = None,
    file_path: Optional[Union[str, Path]] = None,
    proba: bool = False,
    limit: Optional[int] = None,
    top_n: int = 3,
    output: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """
    Main prediction function for importable use.

    Args:
        text: Single system call sequence as a string.
        csv_path: Path to CSV file containing syscall sequences.
        file_path: Path to text file with one sequence per line.
        proba: Whether to include probability scores.
        limit: Limit number of results returned (None = all).
        top_n: Number of top predictions to show in probability output.
        output: Optional path to save results as CSV.

    Returns:
        List of result dicts, each with keys: Sample_ID, Predicted_Malware_Type, Text, (optional) Probability, Top_Predictions.
    """
    if text is not None:
        texts = [text]
    elif csv_path is not None:
        texts = read_texts_from_csv(Path(csv_path))
    elif file_path is not None:
        texts = read_texts_from_file(Path(file_path))
    else:
        raise ValueError("One of text, csv_path, or file_path must be provided.")

    if not texts:
        return []

    preds, probs = predict_texts(texts, proba=proba)
    _, classes = load_model()

    results = []
    for i, (sample_text, pred) in enumerate(zip(texts, preds)):
        result = {
            "Sample_ID": i + 1,
            "Predicted_Malware_Type": pred,
            "Text": (sample_text[:80] + "...") if len(sample_text) > 80 else sample_text
        }
        if proba and probs is not None:
            result["Probability"] = float(np.max(probs[i]))
            result["Top_Predictions"] = format_proba(probs[i], classes, top_n)
        results.append(result)

    if limit is not None:
        results = results[:limit]

    if output is not None:
        pd.DataFrame(results).to_csv(output, index=False)

    return results