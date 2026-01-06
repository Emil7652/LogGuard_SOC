def correlate_events(df):
    df["correlated"] = df["attempts"] > 5
    return df
