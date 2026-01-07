import customtkinter as ctk
from tkinter import filedialog, messagebox
import pandas as pd

from attack_simulator import generate_attacks
from mitre_attack import show_mitre_window
from timeline import show_timeline

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LogGuardApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("LogGuard SOC")
        self.geometry("1100x650")

        # События (лог + симулятор)
        self.events = []

        # GUI
        self.create_sidebar()
        self.create_main_area()

    # -------- SIDEBAR --------
    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)

        ctk.CTkLabel(
            self.sidebar,
            text="LogGuard",
            font=("Segoe UI", 20, "bold")
        ).pack(pady=20)

        # Кнопки
        ctk.CTkButton(self.sidebar, text="Load Logs", command=self.load_logs).pack(pady=8)
        ctk.CTkButton(self.sidebar, text="Attack Simulator", command=self.run_attack_simulator).pack(pady=8)
        ctk.CTkButton(self.sidebar, text="MITRE ATT&CK", command=self.open_mitre).pack(pady=8)
        ctk.CTkButton(self.sidebar, text="Attack Timeline", command=self.open_timeline).pack(pady=8)

    # -------- MAIN AREA --------
    def create_main_area(self):
        self.main = ctk.CTkFrame(self)
        self.main.pack(expand=True, fill="both", padx=10, pady=10)

        self.status_label = ctk.CTkLabel(self.main, text="Ready", font=("Segoe UI", 16))
        self.status_label.pack(pady=40)

    # -------- LOAD LOGS (исправлено) --------
    def load_logs(self):
    path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
    if not path:
        return

    try:
        parsed = parse_logs(path)

        # 🔧 ГАРАНТИЯ DataFrame
        if isinstance(parsed, list):
            self.logs = pd.DataFrame(parsed)
        else:
            self.logs = parsed

        if self.logs.empty:
            messagebox.showwarning("Внимание", "Логи загружены, но они пустые")
            return

        # Обновляем интерфейс
        self.update_table()
        self.update_dashboard("Логи загружены", "#38bdf8")

    except Exception as e:
        messagebox.showerror("Ошибка загрузки логов", str(e))

            # Обновление статуса
            self.status_label.configure(text=f"Loaded {len(self.events)} log events")

            messagebox.showinfo("Logs loaded", f"Successfully loaded {len(self.events)} events")

        except Exception as e:
            messagebox.showerror("Error loading logs", str(e))

    # -------- ATTACK SIMULATOR --------
    def run_attack_simulator(self):
        self.events = generate_attacks()
        self.status_label.configure(text=f"Generated {len(self.events)} attack events")

    # -------- MITRE ATT&CK --------
    def open_mitre(self):
        show_mitre_window(self, self.events)

    # -------- TIMELINE --------
    def open_timeline(self):
        show_timeline(self, self.events)


if __name__ == "__main__":
    app = LogGuardApp()
    app.mainloop()

