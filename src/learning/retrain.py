import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


def retrain_safe_model():

    df = pd.read_csv("datasets/safe_unsafe_dataset.csv")

    if len(df) < 50:
        return

    X = df["text"]
    y = df["label"]

    vectorizer = TfidfVectorizer()
    X_vec = vectorizer.fit_transform(X)

    model = LogisticRegression()
    model.fit(X_vec, y)

    joblib.dump(model, "models/safe_unsafe_model.pkl")
    joblib.dump(vectorizer, "models/vectorizer.pkl")


def retrain_ai_model():

    df = pd.read_csv("datasets/ai_human_dataset.csv")

    if len(df) < 50:
        return

    X = df["text"]
    y = df["label"]

    vectorizer = TfidfVectorizer()
    X_vec = vectorizer.fit_transform(X)

    model = LogisticRegression()
    model.fit(X_vec, y)

    joblib.dump(model, "models/ai_model.pkl")
    joblib.dump(vectorizer, "models/ai_vectorizer.pkl")