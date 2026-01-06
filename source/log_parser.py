import pandas as pd

def parse_logs(path):
    df = pd.read_csv(path)

    mapping = {
        "timestamp": ["time", "date", "timestamp"],
        "user": ["user", "username", "account"],
        "ip": ["ip", "src_ip", "source_ip"],
        "event": ["event", "action", "message"]
    }

    normalized = {}

    for std, variants in mapping.items():
        for v in variants:
            if v in df.columns:
                normalized[std] = df[v]
                break
        else:
            normalized[std] = "unknown"

    out = pd.DataFrame(normalized)
    out["attempts"] = 1
    out["bytes"] = df.get("bytes", 0)

    return out
