import customtkinter as ctk


def show_mitre_window(parent):
    win = ctk.CTkToplevel(parent)
    win.title("MITRE ATT&CK")
    win.geometry("900x600")
    win.grab_set()

    title = ctk.CTkLabel(
        win,
        text="MITRE ATT&CK – Detected Techniques",
        font=("Segoe UI", 20, "bold")
    )
    title.pack(pady=15)

    box = ctk.CTkTextbox(win, width=850, height=450)
    box.pack(padx=20, pady=10)

    box.insert(
        "end",
        "T1110 – Brute Force\n"
        "T1078 – Valid Accounts\n"
        "T1046 – Network Service Scanning\n"
        "T1059 – Command and Scripting Interpreter\n"
        "T1021 – Remote Services\n"
    )

    box.configure(state="disabled")
