import matplotlib.pyplot as plt

def show_timeline(df):
    plt.figure(figsize=(10,4))
    plt.plot(df.index, df["ai_risk"], marker="o")
    plt.title("Timeline атак")
    plt.xlabel("Событие")
    plt.ylabel("AI Risk")
    plt.show()

def show_mitre(df):
    df["technique"].value_counts().plot(kind="bar", figsize=(8,5))
    plt.title("MITRE ATT&CK")
    plt.show()
