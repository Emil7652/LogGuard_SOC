import customtkinter as ctk
from tkinter import filedialog, messagebox
import pandas as pd
import random
import datetime
import matplotlib.pyplot as plt

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# MITRE ATT&CK mapping
MITRE_MAP = {
    "port_scan": "Reconnaissance",
    "login_fail": "Brute Force",
    "process_exec": "Malware",
    "email_click": "Phishing",
    "file_access": "Data Exfiltration"
}


class LogGuardSOC(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("LogGuard SOC")
        self.geometry("1300x750")
        self.logs = None
        self.build_ui()

    # ================= UI =================
    def build_ui(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        ctk.CTkLabel(self.sidebar, text="🛡 LogGuard", font=("Segoe UI", 22, "bold"))\
            .pack(pady=(30, 20))

        ctk.CTkButton(self.sidebar, text="📂 Загрузить логи", command=self.load_logs)\
            .pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(self.sidebar, text="🎯 Симулятор атак", command=self.simulate_attacks)\
            .pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(self.sidebar, text="📈 Таймлайн", command=self.show_timeline)\
            .pack(pady=10, padx=20, fill="x")

        ctk.CTkButton(self.sidebar, text="🧬 MITRE ATT&CK", command=self.show_mitre)\
            .pack(pady=10, padx=20, fill="x")

        self.main = ctk.CTkFrame(self)
        self.main.pack(fill="both", expand=True, padx=20, pady=20)

        self.cards = ctk.CTkFrame(self.main, fg_color="transparent")
        self.cards.pack(fill="x", pady=(0, 20))

        self.card_events = self.card("События", "0")
        self.card_status = self.card("Статус", "Ожидание")

        self.table = ctk.CTkTextbox(self.main, font=("Consolas", 12))
        self.table.pack(fill="both", expand=True)

    def card(self, title, value):
        card = ctk.CTkFrame(self.cards, corner_radius=20)
        card.pack(side="left", expand=True, fill="both", padx=10)

        ctk.CTkLabel(card, text=title, font=("Segoe UI", 14)).pack(pady=(15, 5))
        label = ctk.CTkLabel(card, text=value, font=("Segoe UI", 36, "bold"))
        label.pack(pady=(0, 15))
        return label

    # ================= LOGIC =================
    def normalize_logs(self, df):
        # Нормализация колонок
        if "timestamp" not in df.columns:
            df["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if "event" not in df.columns:
            if "action" in df.columns:
                df["event"] = df["action"]
            else:
                df["event"] = "unknown"
        return df

    def load_logs(self):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            df = pd.read_csv(path)
            df = self.normalize_logs(df)
            self.logs = df
            self.update_table()
            self.card_events.configure(text=str(len(df)))
            # 🔹 Визуальное сообщение о нормализации
            self.card_status.configure(text="Логи нормализованы", text_color="#38bdf8")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def simulate_attacks(self):
        events = list(MITRE_MAP.keys())
        data = []

        for _ in range(60):
            data.append({
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": random.choice(events)
            })

        self.logs = pd.DataFrame(data)
        self.update_table()
        self.card_events.configure(text=str(len(self.logs)))
        self.card_status.configure(text="Атаки сгенерированы", text_color="#facc15")

    def update_table(self):
        self.table.delete("1.0", "end")
        self.table.insert("end", self.logs.head(100).to_string(index=False))

    # ================= VISUALS =================
    def show_timeline(self):
        if self.logs is None:
            return

        df = self.logs.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        timeline = df.groupby(df["timestamp"].dt.minute).size()

        plt.figure("Timeline")
        timeline.plot(kind="bar")
        plt.title("Timeline событий")
        plt.xlabel("Минута")
        plt.ylabel("Количество событий")
        plt.tight_layout()
        plt.show()

    def show_mitre(self):
        if self.logs is None:
            return

        df = self.logs.copy()
        df["mitre"] = df["event"].map(MITRE_MAP).fillna("Unknown")
        counts = df["mitre"].value_counts()

        plt.figure("MITRE ATT&CK")
        counts.plot(kind="bar")
        plt.title("MITRE ATT&CK TTP")
        plt.xlabel("Тактика")
        plt.ylabel("Количество событий")
        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    app = LogGuardSOC()
    app.mainloop()
