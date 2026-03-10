
from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


class HandcraftedFeatures(BaseEstimator, TransformerMixin):
    """
    Extracts simple statistical and pattern-based features from text.
    """
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for text in X:
            tokens = str(text).split()
            num_tokens = len(tokens)
            unique_ratio = (len(set(tokens)) / num_tokens) if num_tokens else 0.0
            avg_len = (sum(len(t) for t in tokens) / num_tokens) if num_tokens else 0.0
            upper_ratio = (sum(t.isupper() for t in tokens) / num_tokens) if num_tokens else 0.0
            digit_ratio = (sum(any(ch.isdigit() for ch in t) for t in tokens) / num_tokens) if num_tokens else 0.0
            features.append([
                num_tokens,
                unique_ratio,
                avg_len,
                upper_ratio,
                digit_ratio,
            ])
        return np.asarray(features, dtype=float)

