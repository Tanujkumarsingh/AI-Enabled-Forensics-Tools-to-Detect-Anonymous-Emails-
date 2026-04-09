import csv
import os
import pandas as pd
from src.learning.retrain import retrain_ai_model, retrain_safe_model

AI_DATASET = "datasets/ai_human_dataset.csv"
SAFE_DATASET = "datasets/safe_unsafe_dataset.csv"
UNSAFE_DATASET = "datasets/unsafe_dataset.csv"


def save_ai_human(text, label):

    os.makedirs("datasets", exist_ok=True)

    file_exists = os.path.isfile(AI_DATASET)

    with open(AI_DATASET, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["text", "label"])

        writer.writerow([text, label])


def save_safe_unsafe(text, label):

    file_exists = os.path.isfile(SAFE_DATASET)

    with open(SAFE_DATASET, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["text", "label"])

        writer.writerow([text, label])


def save_unsafe_only(data):

    file_exists = os.path.isfile(UNSAFE_DATASET)

    with open(UNSAFE_DATASET, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(data)


def check_and_retrain():

    try:
        df1 = pd.read_csv(AI_DATASET)
        df2 = pd.read_csv(SAFE_DATASET)

        if len(df1) % 50 == 0:
            retrain_ai_model()

        if len(df2) % 50 == 0:
            retrain_safe_model()

    except:
        pass