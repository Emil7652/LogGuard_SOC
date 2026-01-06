import pandas as pd
import random
from datetime import datetime, timedelta
from attack_memory import remember

ATTACKS = [
    ("Phishing", "T1566"),
    ("Brute Force", "T1110"),
    ("Privilege Escalation", "T1068"),
    ("Lateral Movement", "T1021"),
    ("Persistence", "T1053"),
    ("Data Exfiltration", "T1041")
]

def generate_attacks():
    events = []
    base = datetime.now()

    for i in range(random.randint(40, 80)):
        attack, tech = random.choice(ATTACKS)
        ip = f"10.0.0.{random.randint(1,50)}"

        events.append({
            "time": base + timedelta(minutes=i),
            "user": f"user{random.randint(1,5)}",
            "ip": ip,
            "event": attack,
            "technique": tech
        })

        remember(ip, True)

    return pd.DataFrame(events)
