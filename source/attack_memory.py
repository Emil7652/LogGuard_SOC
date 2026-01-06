memory = {}

def remember(ip, success):
    memory.setdefault(ip, []).append(success)

def reputation(ip):
    if ip not in memory:
        return 0.5
    return sum(memory[ip]) / len(memory[ip])
