import customtkinter as ctk


def show_timeline(parent, events):
    win = ctk.CTkToplevel(parent)
    win.title("Attack Timeline")
    win.geometry("900x500")
    win.grab_set()

    title = ctk.CTkLabel(
        win,
        text="Security Events Timeline",
        font=("Segoe UI", 20, "bold")
    )
    title.pack(pady=15)

    box = ctk.CTkTextbox(win, width=850, height=400)
    box.pack(padx=20, pady=10)

    if not events:
        box.insert("end", "No events available\n")
    else:
        for e in events:
            box.insert(
                "end",
                f"{e['timestamp']} | {e['event']} | Severity: {e['severity']}\n"
            )

    box.configure(state="disabled")
