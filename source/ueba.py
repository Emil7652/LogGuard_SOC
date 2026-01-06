def calculate_ueba(df):
    scores = []
    for _, r in df.iterrows():
        score = 0.1
        if r["user"] == "admin":
            score += 0.3
        if r["attempts"] > 10:
            score += 0.4
        scores.append(min(score, 1))
    return scores
