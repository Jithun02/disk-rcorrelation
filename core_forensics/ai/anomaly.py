from __future__ import annotations

from typing import Any

import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover
    IsolationForest = None


def ai_detect(correlated_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not correlated_data or IsolationForest is None:
        return []

    df = pd.DataFrame(correlated_data).copy()

    df["process"] = df["process"].astype(str)
    df["name_len"] = df["process"].str.len()
    df["found_on_disk"] = df["found_on_disk"].astype(int)
    df["path_suspicious"] = df["path_suspicious"].astype(int)

    feature_columns = [
        "name_len",
        "pid",
        "ppid",
        "found_on_disk",
        "path_suspicious",
        "dll_count",
        "connection_count",
    ]

    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    model = IsolationForest(contamination=0.1, random_state=42)
    df["anomaly_flag"] = model.fit_predict(df[feature_columns])
    df["anomaly_score"] = model.decision_function(df[feature_columns])

    anomalous = df[df["anomaly_flag"] == -1].copy()
    anomalous.sort_values(by="anomaly_score", ascending=True, inplace=True)

    return [
        {
            "process": row["process"],
            "pid": int(row["pid"]),
            "score": float(row["anomaly_score"]),
            "reason": "IsolationForest marked this process as statistically unusual.",
        }
        for _, row in anomalous.iterrows()
    ]
