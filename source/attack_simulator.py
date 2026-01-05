import random
import csv
from datetime import datetime, timedelta

ATTACK_TYPES = {
    "Brute Force (T1110)": {
        "key": "BRUTE_FORCE",
        "failures": 6
    },
    "Port Scan (T1046)": {
        "key": "PORT_SCAN",
        "failures": 10
    },
    "Privilege Escalation (T1068)": {
        "key": "PRIV_ESC",
        "failures": 3
    },
    "Lateral Movement (T1021)": {
        "key": "LATERAL_MOVE",
        "failures": 4
    }
}

IPS = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.9"]
USERS = ["admin", "root", "guest", "user1", "user2"]

def simulate_attack(attack_label, output_file="sample_logs.csv"):
    if attack_label not in ATTACK_TYPES:
        raise ValueError("Unknown attack type")

    attack = ATTACK_TYPES[attack_label]
    now = datetime.now()
    rows = []

    ip = random.choice(IPS)
    user = random.choice(USERS)

    for i in range(attack["failures"]):
        rows.append([
            (now + timedelta(seconds=i)).isoformat(),
            ip,
            user,
            "FAIL"
        ])

    rows.append([
        (now + timedelta(seconds=attack["failures"] + 2)).isoformat(),
        ip,
        user,
        "OK"
    ])

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["time", "ip", "user", "status"])
        writer.writerows(rows)

    return attack_label
