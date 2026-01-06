import pandas as pd

def parse_logs(path):
    df = pd.read_csv(path)

    def col(name_list):
        for n in name_list:
            if n in df.columns:
                return df[n]
        return ["unknown"] * len(df)

    result = pd.DataFrame({
        "time": col(["time", "timestamp", "date"]),
        "user": col(["user", "username", "account"]),
        "ip": col(["ip", "src_ip", "source"]),
        "event": col(["event", "action", "message"])
    })

    result["technique"] = "Unknown"
    return result
