import csv
from collections import defaultdict
from datetime import datetime
from mitre import MITRE_ATTACK

# ================== ВЕСА ==================

ATTACK_WEIGHTS = {
    "Recon": 10,
    "Spraying": 20,
    "Brute Force": 30,
    "DoS": 40
}

KILL_CHAIN_WEIGHTS = {
    "Reconnaissance": 10,
    "Credential Access": 25,
    "Impact": 40
}

# ================== ЗАГРУЗКА ==================

def load_logs(path):
    logs = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            row["time"] = datetime.fromisoformat(row["time"])
            logs.append(row)
    return logs

# ================== ДЕТЕКТ АТАК ==================

def detect_attacks(logs):
    attacks = defaultdict(list)
    users = defaultdict(set)
    times = defaultdict(list)
    user_activity = defaultdict(list)

    for log in logs:
        ip = log["ip"]
        user = log["user"]

        users[ip].add(user)
        times[ip].append(log["time"])
        user_activity[user].append(log)

        if log["status"] == "FAIL":
            attacks[ip].append("Brute Force")
        else:
            attacks[ip].append("Recon")

    for ip, u in users.items():
        if len(u) >= 3:
            attacks[ip].append("Spraying")

    return attacks, users, times, user_activity

# ================== KILL CHAIN ==================

def kill_chain_stages(events):
    return list({MITRE_ATTACK[e]["kill_chain"] for e in events})

# ================== ВРЕМЕННЫЕ АНОМАЛИИ ==================

def detect_time_anomaly(times):
    times.sort()
    bursts = 0
    for i in range(1, len(times)):
        if (times[i] - times[i-1]).seconds < 5:
            bursts += 1
    return bursts >= 3

# ================== AI РИСК ==================

def calculate_ai_risk(events, times):
    score = 0

    for e in set(events):
        score += ATTACK_WEIGHTS[e]

    stages = kill_chain_stages(events)
    for s in stages:
        score += KILL_CHAIN_WEIGHTS[s]

    score += min(len(events) * 2, 20)

    if len(stages) >= 2:
        score += 15
    if len(stages) >= 3:
        score += 25

    if detect_time_anomaly(times):
        score += 20

    return min(score, 100)

def threat_level(score):
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"

# ================== UEBA ==================

def ueba_analysis(user_activity):
    ueba = {}

    for user, logs in user_activity.items():
        fail = sum(1 for l in logs if l["status"] == "FAIL")
        ips = len(set(l["ip"] for l in logs))

        risk = min(fail * 10 + ips * 15, 100)
        ueba[user] = {
            "risk": risk,
            "anomaly": risk > 60
        }

    return ueba

# ================== ATTACK GRAPH ==================

def build_attack_graph(attacks):
    graph = defaultdict(set)

    for ip, events in attacks.items():
        stages = kill_chain_stages(events)
        stages.sort()
        for i in range(len(stages) - 1):
            graph[stages[i]].add(stages[i+1])

    return graph

# ================== HEATMAP ==================

def build_heatmap(attacks):
    heatmap = defaultdict(lambda: defaultdict(int))

    for ip, events in attacks.items():
        for e in events:
            stage = MITRE_ATTACK[e]["kill_chain"]
            heatmap[stage][ip] += 1

    return heatmap

# ================== ОСНОВНОЙ АНАЛИЗ ==================

def analyze(logs):
    attacks, users, times, user_activity = detect_attacks(logs)

    report = []
    ueba = ueba_analysis(user_activity)
    graph = build_attack_graph(attacks)
    heatmap = build_heatmap(attacks)

    for ip, events in attacks.items():
        score = calculate_ai_risk(events, times[ip])
        report.append({
            "ip": ip,
            "events": list(set(events)),
            "kill_chain": kill_chain_stages(events),
            "risk": score,
            "level": threat_level(score)
        })

    return {
        "ip_report": report,
        "ueba": ueba,
        "attack_graph": graph,
        "heatmap": heatmap
    }
