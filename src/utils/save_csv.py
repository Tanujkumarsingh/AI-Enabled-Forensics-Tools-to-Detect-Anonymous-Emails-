import csv
import os

def save_result(data):

    os.makedirs("output", exist_ok=True)
    file = "output/all_emails.csv"

    file_exists = os.path.isfile(file)

    with open(file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(data)