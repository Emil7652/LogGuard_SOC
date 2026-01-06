import numpy as np

def calculate_ai_risk(df):
    risk = (
        df["attempts"] * 0.04 +
        (df["bytes"] > 100000) * 0.4
    )
    return np.clip(risk, 0, 1)
