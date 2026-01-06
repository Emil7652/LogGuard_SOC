import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# Импорты твоих модулей
from log_parser import parse_logs
from attack_simulator import generate_attacks
from ai_risk import calculate_ai_risk
from ueba import calculate_ueba
from correlation import correlate_events
from ai_attack_classifier import predict_attack
from visuals import show_timeline, show_mitre


class LogGuardSOC(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("LogGuard SOC AI")
        self.geometry("1100x700")
        self.configure(bg="#0f172a")

        self.logs = None

        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TButton", font=("Segoe UI", 11), padding=10)
        style.configure("Card.TFrame", background="#020617")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"),
                        background="#0f172a", foreground="white")
        style.configure("CardTitle.TLabel", font=("Segoe UI", 12, "bold"),
                        background="#020617", foreground="#e5e7eb")
        style.configure("Value.TLabel", font=("Segoe UI", 26, "bold"),
                        background="#020617", foreground="#22c55e")

        self._build_ui()

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=20, pady=15)
        ttk.Label(header, text="🛡 LogGuard SOC AI", style="Title.TLabel").pack(side="left")

        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=20, pady=10)

        sidebar = ttk.Frame(main, width=220)
        sidebar.pack(side="left", fill="y", padx=(0, 20))

        ttk.Button(sidebar, text="📂 Загрузить логи", command=self.load_logs).pack(fill="x", pady=8)
        ttk.Button(sidebar, text="🎯 Симуляция атак", command=self.simulate_attacks).pack(fill="x", pady=8)
        ttk.Button(sidebar, text="🤖 AI + UEBA анализ", command=self.analyze).pack(fill="x", pady=8)
        ttk.Button(sidebar, text="📈 Таймлайн", command=self.timeline).pack(fill="x", pady=8)
        ttk.Button(sidebar, text="🧬 MITRE ATT&CK", command=self.mitre).pack(fill="x", pady=8)

        dashboard = ttk.Frame(main)
        dashboard.pack(fill="both", expand=True)

        self.card_events = self._card(dashboard, "События", "0")
        self.card_risk = self._card(dashboard, "AI Risk", "0.00")
        self.card_status = self._card(dashboard, "Статус", "Ожидание")

    def _card(self, parent, title, value):
        frame = ttk.Frame(parent, style="Card.TFrame", padding=20)
        frame.pack(side="left", expand=True, fill="both", padx=10)

        ttk.Label(frame, text=title, style="CardTitle.TLabel").pack(anchor="w")
        label = ttk.Label(frame, text=value, style="Value.TLabel")
        label.pack(anchor="w", pady=10)
        return label

    def load_logs(self):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if path:
            self.logs = parse_logs(path)
            self.card_events.config(text=str(len(self.logs)))
            self.card_status.config(text="Логи загружены", foreground="#38bdf8")

    def simulate_attacks(self):
        self.logs = generate_attacks()
        self.card_events.config(text=str(len(self.logs)))
        self.card_status.config(text="Атаки сгенерированы", foreground="#facc15")

    def analyze(self):
        if self.logs is None:
            messagebox.showerror("Ошибка", "Нет логов для анализа")
            return
        try:
            # AI + UEBA анализ
            self.logs["ueba_score"] = calculate_ueba(self.logs)
            self.logs["ai_risk"] = calculate_ai_risk(self.logs)
            self.logs["predicted_attack"] = predict_attack(self.logs)
            self.logs = correlate_events(self.logs)

            avg_risk = round(self.logs["ai_risk"].mean(), 2)
            self.card_risk.config(text=str(avg_risk))

            # Цветовая индикация риска
            if avg_risk < 0.3:
                color = "#22c55e"
            elif avg_risk < 0.6:
                color = "#facc15"
            else:
                color = "#ef4444"
            self.card_risk.config(foreground=color)
            self.card_status.config(text="Анализ завершён", foreground="#22c55e")
        except Exception as e:
            import traceback
            messagebox.showerror("Ошибка анализа", f"Произошла ошибка:\n{traceback.format_exc()}")

    def timeline(self):
        if self.logs is not None:
            show_timeline(self.logs)

    def mitre(self):
        if self.logs is not None:
            show_mitre(self.logs)


if __name__ == "__main__":
    LogGuardSOC().mainloop()
