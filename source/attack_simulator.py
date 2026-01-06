import pandas as pd
import random
from datetime import datetime, timedelta

ATTACKS = [
    ("Brute Force", "login_fail"),
    ("Phishing", "email_click"),
    ("Malware", "process_exec"),
    ("Reconnaissance", "port_scan"),
    ("Data Exfiltration", "file_access"),
    ("Lateral Movement", "admin_login")
]

def generate_attacks():
    data = []
    base = datetime.now()

    for _ in range(random.randint(40, 80)):
        attack, event = random.choice(ATTACKS)
        data.append({
            "timestamp": base + timedelta(seconds=random.randint(1, 300)),
            "user": random.choice(["admin", "user1", "guest"]),
            "ip": f"192.168.1.{random.randint(1,255)}",
            "event": event,
            "true_attack": attack,
            "attempts": random.randint(1, 20),
            "bytes": random.randint(100, 500000)
        })

    return pd.DataFrame(data)
