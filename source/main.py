import customtkinter as ctk
from tkinter import filedialog, messagebox
import pandas as pd
from mitre_attack import show_mitre_window
from timeline import show_timeline

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LogGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LogGuard SOC")
        self.geometry("1200x700")
        self.logs = None
        self.events = []

        self.create_sidebar()
        self.create_main_area()

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220)
        self.sidebar.pack(side="left", fill="y")

        title = ctk.CTkLabel(
            self.sidebar,
            text="LogGuard",
            font=("Segoe UI", 22, "bold")
        )
        title.pack(pady=20)

        self.load_btn = ctk.CTkButton(
            self.sidebar,
            text="Load Logs",
            command=self.load_logs
        )
        self.load_btn.pack(pady=8)

        self.mitre_btn = ctk.CTkButton(
            self.sidebar,
            text="MITRE ATT&CK",
            command=self.open_mitre
        )
        self.mitre_btn.pack(pady=8)

        self.timeline_btn = ctk.CTkButton(
            self.sidebar,
            text="Attack Timeline",
            command=self.open_timeline
        )
        self.timeline_btn.pack(pady=8)

    def create_main_area(self):
        self.main = ctk.CTkFrame(self)
        self.main.pack(expand=True, fill="both")

        self.label = ctk.CTkLabel(
            self.main,
            text="LogGuard SOC Dashboard",
            font=("Segoe UI", 26, "bold")
        )
        self.label.pack(pady=40)

        self.info = ctk.CTkLabel(
            self.main,
            text="Load logs or generate attacks to begin analysis",
            font=("Segoe UI", 14)
        )
        self.info.pack()

    def load_logs(self):
    file_path = filedialog.askopenfilename(
        title="Select log file",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )

    if not file_path:
        return

    try:
        df = pd.read_csv(file_path)

        events = []

        for _, row in df.iterrows():
            event = {
                "timestamp": str(
                    row["timestamp"] if "timestamp" in df.columns else "unknown"
                ),
                "event": str(
                    row["event"] if "event" in df.columns else "unknown"
                ),
                "severity": str(
                    row["severity"] if "severity" in df.columns else "Medium"
                ),
                "mitre": str(
                    row["mitre"] if "mitre" in df.columns else "N/A"
                )
            }
            events.append(event)

        self.events = events

        if hasattr(self, "status_label"):
            self.status_label.configure(
                text=f"Loaded {len(self.events)} log events"
            )

        messagebox.showinfo(
            "Logs loaded",
            f"Successfully loaded {len(self.events)} events"
        )

    except Exception as e:
        messagebox.showerror(
            "Error loading logs",
            str(e)
        )

    def normalize_logs(self, df):
        # Приводим лог к единому формату: timestamp, event, severity
        df = df.copy()
        if "timestamp" not in df.columns:
            df["timestamp"] = pd.Timestamp.now()
        if "event" not in df.columns:
            df["event"] = "Unknown"
        if "severity" not in df.columns:
            df["severity"] = "Medium"
        return df[["timestamp", "event", "severity"]]

    def convert_logs_to_events(self, df):
        return df.to_dict(orient="records")

    def open_mitre(self):
        show_mitre_window(self)

    def open_timeline(self):
        show_timeline(self, self.events)


if __name__ == "__main__":
    app = LogGuardApp()
    app.mainloop()

