import customtkinter as ctk
from tkinter import filedialog, messagebox
import pandas as pd
import random
from datetime import datetime, timedelta
import matplotlib.pyplot as plt


# ================== НАСТРОЙКИ ==================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

HIGH_RISK_EVENTS = ["login_fail", "port_scan", "email_click"]


# ================== ПРИЛОЖЕНИЕ ==================
class LogGuardSOC(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LogGuard SOC AI")
        self.geometry("1300x750")
        self.minsize(1200, 700)

        self.logs = None

        self.build_ui()

    # ================== UI ==================
    def build_ui(self):
        # ---------- SIDEBAR ----------
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        ctk.CTkLabel(
            self.sidebar,
            text="🛡 LogGuard",
            font=("Segoe UI", 22, "bold")
        ).pack(pady=(30, 20))

        ctk.CTkButton(
            self.sidebar, text="📂 Загрузить логи",
            command=self.load_logs
        ).pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(
            self.sidebar, text="🎯 Симулятор атак",
            command=self.simulate_attacks
        ).pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(
            self.sidebar, text="🤖 AI + UEBA анализ",
            command=self.analyze
        ).pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(
            self.sidebar, text="📈 Таймлайн",
            command=self.timeline
        ).pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(
            self.sidebar, text="🧬 MITRE ATT&CK",
            command=self.mitre
        ).pack(pady=10, padx=20, fill="x")

        # ---------- MAIN ----------
        self.main = ctk.CTkFrame(self)
        self.main.pack(fill="both", expand=True, padx=20, pady=20)

        self.cards = ctk.CTkFrame(self.main, fg_color="transparent")
        self.cards.pack(fill="x", pady=(0, 20))

        self.card_events = self.card("События", "0")
        self.card_risk = self.card("AI Risk", "0.00")
        self.card_status = self.card("Статус", "Ожидание")

        self.table = ctk.CTkTextbox(
            self.main,
            font=("Consolas", 12)
        )
        self.table.pack(fill="both", expand=True)

    def card(self, title, value):
        card = ctk.CTkFrame(self.cards, corner_radius=20)
        card.pack(side="left", expand=True, fill="both", padx=10)

        ctk.CTkLabel(card, text=title, font=("Segoe UI", 14)).pack(pady=(15, 5))
        label = ctk.CTkLabel(card, text=value, font=("Segoe UI", 36, "bold"))
        label.pack(pady=(0, 15))

        return label

    # ================== ЛОГИ ==================
    def normalize_logs(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df.columns = [c.lower() for c in df.columns]

        if "timestamp" not in df.columns:
            if "time" in df.columns:
                df["timestamp"] = df["time"]
            else:
                start = datetime.now()
                df["timestamp"] = [
                    start + timedelta(seconds=i * 5) for i in range(len(df))
                ]

        if "event" not in df.columns:
            for col in ["action", "event_type", "activity"]:
                if col in df.columns:
                    df["event"] = df[col]
                    break
            else:
                df["event"] = "unknown"

        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["event"] = df["event"].astype(str)

        return df[["timestamp", "event"]]

    def load_logs(self):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not path:
            return

        try:
            raw = pd.read_csv(path)
            self.logs = self.normalize_logs(raw)

            self.update_dashboard("Логи нормализованы", "#38bdf8")
            self.update_table()

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ================== СИМУЛЯТОР ==================
    def simulate_attacks(self):
        events = [
            "login_success", "login_fail", "port_scan",
            "file_access", "process_exec", "email_click"
        ]

        data = []
        start = datetime.now()

        for i in range(40):
            data.append({
                "timestamp": start + timedelta(seconds=i * random.randint(5, 20)),
                "event": random.choice(events)
            })

        self.logs = pd.DataFrame(data)
        self.update_dashboard("Атаки сгенерированы", "#facc15")
        self.update_table()

    # ================== AI + UEBA ==================
    def analyze(self):
        if self.logs is None:
            messagebox.showerror("Ошибка", "Нет логов")
            return

        self.logs["ueba"] = self.logs["event"].apply(
            lambda x: 0.9 if x in HIGH_RISK_EVENTS else 0.2
        )

        self.logs["ai_risk"] = (
            self.logs["ueba"] * 0.7 +
            self.logs["event"].isin(HIGH_RISK_EVENTS).astype(int) * 0.3
        ).round(2)

        avg = round(self.logs["ai_risk"].mean(), 2)

        color = "#22c55e"
        if avg > 0.6:
            color = "#ef4444"
        elif avg > 0.3:
            color = "#facc15"

        self.card_risk.configure(text=str(avg), text_color=color)
        self.update_dashboard("AI + UEBA анализ завершён", color)
        self.update_table()

    # ================== TABLE ==================
    def update_dashboard(self, status, color):
        self.card_events.configure(text=str(len(self.logs)))
        self.card_status.configure(text=status, text_color=color)

    def update_table(self):
        self.table.delete("1.0", "end")

        self.table.tag_config("high", foreground="#ef4444")
        self.table.tag_config("medium", foreground="#facc15")

        for _, row in self.logs.iterrows():
            line = f"{row['timestamp']} | {row['event']}\n"
            risk = row.get("ai_risk", 0)

            if risk > 0.6:
                self.table.insert("end", line, "high")
            elif risk > 0.3:
                self.table.insert("end", line, "medium")
            else:
                self.table.insert("end", line)

    # ================== ВИЗУАЛЫ ==================
    def timeline(self):
        if self.logs is None:
            return

        counts = self.logs.groupby(self.logs["timestamp"].dt.minute).size()
        plt.figure("Timeline")
        counts.plot()
        plt.xlabel("Минута")
        plt.ylabel("События")
        plt.show()

    def mitre(self):
        if self.logs is None:
            return

        mapping = {
            "login_fail": "Credential Access",
            "port_scan": "Discovery",
            "email_click": "Initial Access",
            "process_exec": "Execution",
            "file_access": "Collection"
        }

        tactics = self.logs["event"].map(mapping).fillna("Other")
        counts = tactics.value_counts()

        plt.figure("MITRE ATT&CK")
        counts.plot(kind="bar")
        plt.ylabel("События")
        plt.show()


# ================== RUN ==================
if __name__ == "__main__":
    app = LogGuardSOC()
    app.mainloop()
