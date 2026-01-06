from sklearn.ensemble import IsolationForest
import numpy as np

def calculate_ai_risk(df):
    X = [[hash(ip) % 1000, hash(ev) % 1000] for ip, ev in zip(df["ip"], df["event"])]

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X)

    scores = model.decision_function(X)
    denom = scores.max() - scores.min()

    if denom == 0:
        return [0.5] * len(scores)

    return list(1 - (scores - scores.min()) / denom)
