def calculate_ueba(df):
    freq = df["user"].value_counts()
    return [min(freq[u] / 10, 1.0) for u in df["user"]]
