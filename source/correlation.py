def correlate_events(df):
    kill_chain = {
        "T1566": "Initial Access",
        "T1110": "Credential Access",
        "T1068": "Privilege Escalation",
        "T1021": "Lateral Movement",
        "T1053": "Persistence",
        "T1041": "Exfiltration"
    }

    df["kill_chain"] = df["technique"].map(kill_chain).fillna("Unknown")
    return df
