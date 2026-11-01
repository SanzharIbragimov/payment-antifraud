"""Выгрузить вымышленный поток попыток оплаты в data/sample_attempts.csv (колонка label — разметка аномалий)."""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.synthetic import generate  # noqa: E402

import random  # noqa: E402

full = generate(days=30)
# компактная выборка для репозитория: все аномалии + 1500 случайных честных попыток
rng = random.Random(1)
legit = [r for r in full if r["label"] == "legit"]
rows = sorted([r for r in full if r["label"] != "legit"] + rng.sample(legit, 1500), key=lambda r: r["ts"])
out = Path(__file__).resolve().parent.parent / "data" / "sample_attempts.csv"
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print(f"{len(rows)} строк → {out}")
