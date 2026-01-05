import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx

from attack_simulator import simulate_attack, ATTACK_TYPES

# =============================
# THEME (DARK SOC)
# =============================
BG = "#0f172a"
FG = "#e5e7eb"
CARD = "#111827"
RED = "#ef4444"
ORANGE = "#f59e0b"
GREEN = "#22c55e"

# =============================
# AI RISK ENGINE
# =============================
def calculate_risk(events):
    score = sum(12 for e in events if e["status"] == "FAIL")
    return min(score, 100)

# =============================
# LOG PARSER
# =============================
def load_logs(path):
    events = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            r["time"] = datetime.fromisoformat(r["time"])
            events.append(r)
    return events

# =============================
# DASHBOARD METRICS
# =============================
def metrics(events):
    return {
        "events": len(events),
        "attacks": sum(1 for e in events if e["status"] == "FAIL"),
        "ips": len({e["ip"] for e in events}),
        "users": len({e["user"] for e in events})
    }

# =============================
# VISUALS
# =============================
def show_activity(events):
    data = defaultdict(int)
    for e in events:
        data[e["status"]] += 1
    plt.bar(data.keys(), data.values())
    plt.title("Activity")
    plt.show()

def show_graph(events):
    G = nx.DiGraph()
    for e in events:
        G.add_edge(e["ip"], e["user"])
    nx.draw(G, with_labels=True, node_color="lightcoral")
    plt.title("Attack Graph")
    plt.show()

def show_timeline(events):
    t = [e["time"] for e in events]
    plt.plot(t, range(len(t)), marker="o")
    plt.title("Kill Chain Timeline")
    plt.show()

# =============================
# GUI
# =============================
class LogGuardSOC(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LogGuard SOC Dashboard")
        self.geometry("900x620")
        self.configure(bg=BG)

        tk.Label(self, text="LogGuard SOC", fg=FG, bg=BG,
                 font=("Arial", 24, "bold")).pack()
        tk.Label(self, text="Blue Team Dashboard • MITRE ATT&CK",
                 fg="#9ca3af", bg=BG).pack()

        # DASHBOARD
        dash = tk.Frame(self, bg=BG)
        dash.pack(pady=15)

        self.cards = {}
        for name in ["Events", "Attacks", "IPs", "Users"]:
            self.cards[name] = self.card(dash, name)

        # RISK
        self.risk = tk.Label(self, text="RISK: 0",
                             font=("Arial", 20, "bold"),
                             bg=BG, fg=GREEN)
        self.risk.pack(pady=10)

        # ATTACK SIM
        tk.Label(self, text="Attack Simulator", bg=BG, fg=FG).pack()
        self.attack = ttk.Combobox(self,
                                   values=list(ATTACK_TYPES.keys()),
                                   width=45,
                                   state="readonly")
        self.attack.current(0)
        self.attack.pack()

        tk.Button(self, text="🚨 Simulate Attack",
                  bg=RED, fg="white",
                  font=("Arial", 12, "bold"),
                  command=self.simulate).pack(pady=10)

        # CONTROLS
        for text, cmd in [
            ("📂 Load Logs", self.load),
            ("📊 Activity", lambda: show_activity(self.events)),
            ("🌐 Attack Graph", lambda: show_graph(self.events)),
            ("⏱ Timeline", lambda: show_timeline(self.events))
        ]:
            tk.Button(self, text=text, width=25, command=cmd).pack(pady=3)

        self.events = []

    def card(self, parent, title):
        f = tk.Frame(parent, bg=CARD, padx=20, pady=15)
        f.pack(side="left", padx=8)
        tk.Label(f, text=title, fg="#9ca3af", bg=CARD).pack()
        val = tk.Label(f, text="0", fg=FG, bg=CARD,
                       font=("Arial", 20, "bold"))
        val.pack()
        return val

    def update(self):
        m = metrics(self.events)
        self.cards["Events"].config(text=m["events"])
        self.cards["Attacks"].config(text=m["attacks"])
        self.cards["IPs"].config(text=m["ips"])
        self.cards["Users"].config(text=m["users"])

        r = calculate_risk(self.events)
        color = GREEN if r < 30 else ORANGE if r < 70 else RED
        self.risk.config(text=f"RISK: {r}", fg=color)

    def simulate(self):
        simulate_attack(self.attack.get())
        self.events = load_logs("sample_logs.csv")
        self.update()
        messagebox.showinfo("Attack", "Attack simulated")

    def load(self):
        p = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if p:
            self.events = load_logs(p)
            self.update()

# =============================
if __name__ == "__main__":
    LogGuardSOC().mainloop()
