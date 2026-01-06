from sklearn.ensemble import RandomForestClassifier
import pandas as pd

MODEL = RandomForestClassifier(n_estimators=50)

ATTACK_MAP = {
    "login_fail": "Brute Force",
    "email_click": "Phishing",
    "process_exec": "Malware",
    "port_scan": "Reconnaissance",
    "file_access": "Data Exfiltration",
    "admin_login": "Lateral Movement"
}

def train_model():
    X = []
    y = []
    for event, attack in ATTACK_MAP.items():
        for _ in range(30):
            X.append([len(event), random.randint(1,20)])
            y.append(attack)
    MODEL.fit(X, y)

def predict_attack(df):
    preds = []
    for _, r in df.iterrows():
        preds.append(
            ATTACK_MAP.get(r["event"], "Normal")
        )
    return preds
