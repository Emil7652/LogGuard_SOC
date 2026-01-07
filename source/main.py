import customtkinter as ctk
from tkinter import filedialog, messagebox
import pandas as pd

from log_parser import parse_logs
from attack_simulator import generate_attacks
from ai_risk import calculate_ai_risk
from ueba import calculate_ueba
from correlation import correlate_events
from ai_attack_classifier import predict_attack
from visuals import show_timeline, show_mitre


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class LogGuardSOC(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("LogGuard SOC AI")
        self.geometry("1300x750")
        self.minsize(1200, 700)

        self.logs = None

        self.build_ui()

    def build_ui(self):
        # ========== SIDEBAR ==========
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        ctk.CTkLabel(
            self.sidebar,
            text="🛡 LogGuard",
            font=("Segoe UI", 22, "bold")
        ).pack(pady=(30, 20))

        self.btn_load = ctk.CTkButton(
            self.sidebar, text="📂 Загрузить логи",
            command=self.load_logs
        )
        self.btn_load.pack(pady=10, padx=20, fill="x")

        self.btn_sim = ctk.CTkButton(
            self.sidebar, text="🎯 Симулятор атак",
            command=self.simulate_attacks
        )
        self.btn_sim.pack(pady=10, padx=20, fill="x")

        self.btn_analyze = ctk.CTkButton(
            self.sidebar, text="🤖 AI + UEBA анализ",
            command=self.analyze
        )
        self.btn_analyze.pack(pady=10, padx=20, fill="x")

        self.btn_timeline = ctk.CTkButton(
            self.sidebar, text="📈 Таймлайн",
            command=self.timeline
        )
        self.btn_timeline.pack(pady=10, padx=20, fill="x")

        self.btn_mitre = ctk.CTkButton(
            self.sidebar, text="🧬 MITRE ATT&CK",
            command=self.mitre
        )
        self.btn_mitre.pack(pady=10, padx=20, fill="x")

        # ========== MAIN AREA ==========
        self.main = ctk.CTkFrame(self)
        self.main.pack(fill="both", expand=True, padx=20, pady=20)

        self.cards = ctk.CTkFrame(self.main, fg_color="transparent")
        self.cards.pack(fill="x", pady=(0, 20))

        self.card_events = self.card("События", "0")
        self.card_risk = self.card("AI Risk", "0.00")
        self.card_status = self.card("Статус", "Ожидание")

        # ========== TABLE ==========
        self.table_frame = ctk.CTkFrame(self.main)
        self.table_frame.pack(fill="both", expand=True)

        self.table = ctk.CTkTextbox(
            self.table_frame,
            font=("Consolas", 12)
        )
        self.table.pack(fill="both", expand=True, padx=10, pady=10)

    def card(self, title, value):
        card = ctk.CTkFrame(self.cards, corner_radius=20)
        card.pack(side="left", expand=True, fill="both", padx=10)

        ctk.CTkLabel(
            card,
            text=title,
            font=("Segoe UI", 14)
        ).pack(pady=(15, 5))

        label = ctk.CTkLabel(
            card,
            text=value,
            font=("Segoe UI", 36, "bold")
        )
        label.pack(pady=(0, 15))

        return label

    # ========== LOGIC ==========
    def load_logs(self):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not path:
            return
        self.logs = parse_logs(path)
        self.update_dashboard("Логи загружены", "#38bdf8")

    def simulate_attacks(self):
        self.logs = generate_attacks()
        self.update_dashboard("Атаки сгенерированы", "#facc15")

    def analyze(self):
        if self.logs is None:
            messagebox.showerror("Ошибка", "Нет данных для анализа")
            return

        self.logs["ueba"] = calculate_ueba(self.logs)
        self.logs["ai_risk"] = calculate_ai_risk(self.logs)
        self.logs["predicted_attack"] = predict_attack(self.logs)
        self.logs = correlate_events(self.logs)

        avg_risk = round(self.logs["ai_risk"].mean(), 2)

        color = "#22c55e"
        if avg_risk > 0.6:
            color = "#ef4444"
        elif avg_risk > 0.3:
            color = "#facc15"

        self.card_risk.configure(text=str(avg_risk), text_color=color)
        self.update_table()

        self.update_dashboard("Анализ завершён", "#22c55e")

    def update_dashboard(self, status, color):
        self.card_events.configure(text=str(len(self.logs)))
        self.card_status.configure(text=status, text_color=color)

    def update_table(self):
        self.table.delete("1.0", "end")
        self.table.insert("end", self.logs.head(50).to_string(index=False))

    def timeline(self):
        if self.logs is not None:
            show_timeline(self.logs)

    def mitre(self):
        if self.logs is not None:
            show_mitre(self.logs)


if __name__ == "__main__":
    app = LogGuardSOC()
    app.mainloop()
