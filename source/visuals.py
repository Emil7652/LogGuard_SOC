import matplotlib.pyplot as plt

def show_timeline(df):
    plt.style.use("dark_background")
    plt.plot(df.index, df["ai_risk"], color="#22c55e")
    plt.title("Attack Timeline")
    plt.show()

def show_mitre(df):
    plt.style.use("dark_background")
    df["predicted_attack"].value_counts().plot(kind="bar")
    plt.title("MITRE ATT&CK")
    plt.show()
