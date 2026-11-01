"""Генератор ВЫМЫШЛЕННОГО потока попыток оплаты билетов.

Данные не относятся к Ticketon и не основаны на его статистике. В поток
намеренно заложены аномалии с метками (label):
  legit         — добросовестные покупатели (в т.ч. туристы с иностранными картами)
  friendly      — добросовестные на вид покупки, по которым позже откроют спор «не совершал»
  carding       — оплата украденными картами (кольца мошенников, прокси, «горящие» события)
  card_testing  — перебор карт мелкими суммами ботом (простой и с ротацией устройств/IP)
"""
from __future__ import annotations

import random
import zlib
from datetime import datetime, timedelta

CITIES = ["Astana", "Almaty", "Shymkent", "Karaganda"]
KZ_BINS = ["400100", "400200", "510300", "520400", "440500"]
FOREIGN = [("RU", "Moscow"), ("UZ", "Tashkent"), ("TR", "Istanbul"), ("DE", "Berlin"), ("US", "Dallas")]


def _events(rng: random.Random, start: datetime, days: int) -> list[dict]:
    ev = []
    for i in range(40):
        ev.append({
            "event_id": f"EV{i:03d}",
            "event_city": rng.choice(CITIES),
            "event_start": start + timedelta(days=rng.uniform(2, days + 5), hours=rng.choice([0, 1, 2])),
            "hot_event": i % 7 == 0,
            "price": rng.choice([5000, 8000, 12000, 15000, 25000, 40000, 60000]),
        })
    return ev


def generate(days: int = 30, legit_per_day: int = 900, seed: int = 42,
             start: datetime = datetime(2026, 9, 1)) -> list[dict]:
    rng = random.Random(seed)
    events = _events(rng, start, days)
    rows: list[dict] = []
    n = 0

    def nid(prefix: str) -> str:
        nonlocal n
        n += 1
        return f"{prefix}{n:06d}"

    # --- добросовестные покупатели ---
    customers = []
    for i in range(6000):
        foreign = rng.random() < 0.04
        cc, city = rng.choice(FOREIGN) if foreign else ("KZ", rng.choice(CITIES))
        customers.append({
            "account_id": None if rng.random() < 0.15 else f"A{i:05d}",
            "account_created": start - timedelta(days=rng.uniform(1, 900)) if rng.random() > 0.05 else None,
            "email": f"user{i}@mail.kz",
            "phone_verified": rng.random() < 0.6,
            "cards": [f"tok_L{i}_{k}" for k in range(rng.choice([1, 1, 2]))],
            "bin": rng.choice(KZ_BINS) if cc == "KZ" else rng.choice(["411100", "530000"]),
            "bin_country": cc,
            # турист чаще платит из Казахстана, иногда — из дома
            "ip_country": "KZ" if (cc == "KZ" or rng.random() < 0.6) else cc,
            "ip_city": city if cc == "KZ" else ("Almaty" if rng.random() < 0.6 else city),
            "device": f"dev_L{i}",
            "name": f"Ivan Userov{i}",
        })

    def legit_row(ts: datetime, c: dict, label: str) -> dict:
        e = rng.choice([x for x in events if x["event_start"] > ts] or events)
        tickets = rng.choices([1, 2, 3, 4, 6], [35, 40, 12, 10, 3])[0]
        acc_created = c["account_created"] if c["account_id"] else None
        if c["account_id"] and acc_created is None:
            acc_created = ts - timedelta(hours=rng.uniform(0.2, 20))  # новый честный клиент
        return {
            "attempt_id": nid("T"), "order_id": nid("O"), "ts": ts, "label": label,
            "amount_kzt": e["price"] * tickets, "tickets": tickets, "event_id": e["event_id"],
            "event_city": e["event_city"], "event_start": e["event_start"], "hot_event": e["hot_event"],
            "account_id": c["account_id"], "account_created": acc_created, "email": c["email"],
            "phone_verified": c["phone_verified"], "card_token": rng.choice(c["cards"]), "card_bin": c["bin"],
            "card_last4": f"{rng.randint(0, 9999):04d}", "bin_country": c["bin_country"],
            "cardholder_name": c["name"] if c["account_id"] else None,
            "ip": f"10.{zlib.crc32(c['device'].encode()) % 250}.{rng.randint(0, 3)}.{rng.randint(1, 250)}",
            "ip_country": c["ip_country"], "ip_city": c["ip_city"], "ip_is_proxy": rng.random() < 0.01,
            "device_id": c["device"], "checkout_seconds": max(5.0, rng.lognormvariate(4.2, 0.6)),
            "channel": rng.choice(["web", "ios", "android"]),
        }

    for d in range(days):
        for _ in range(legit_per_day):
            ts = start + timedelta(days=d, seconds=rng.uniform(8 * 3600, 24 * 3600))
            c = rng.choice(customers)
            rows.append(legit_row(ts, c, "friendly" if rng.random() < 0.003 else "legit"))

    # --- кардинг: кольца мошенников ---
    for r in range(8):
        devs = [f"dev_F{r}_{k}" for k in range(rng.randint(1, 3))]
        proxy = rng.random() < 0.6
        cc, city = rng.choice(FOREIGN + [("KZ", "Almaty")] * 2)
        day0 = rng.uniform(0, days - 3)
        for c in range(rng.randint(6, 18)):  # украденные карты
            ts = start + timedelta(days=day0 + c * rng.uniform(0.05, 0.6), hours=rng.uniform(0, 12))
            hot = [x for x in events if x["hot_event"] and x["event_start"] > ts] or events
            e = rng.choice(hot) if rng.random() < 0.7 else rng.choice(events)
            if rng.random() < 0.4:  # ближайшее событие — «сбыть до начала»
                soon = [x for x in events if timedelta(0) < x["event_start"] - ts < timedelta(hours=3)]
                if soon:
                    e = rng.choice(soon)
            tickets = rng.choice([4, 5, 6, 8])
            dev = rng.choice(devs)
            acc = None if rng.random() < 0.4 else f"AF{r}_{c % 3}"
            for retry in range(rng.choice([1, 1, 2, 3])):
                rows.append({
                    "attempt_id": nid("T"), "order_id": nid("O"), "ts": ts + timedelta(minutes=retry * 2),
                    "label": "carding", "amount_kzt": e["price"] * tickets, "tickets": tickets,
                    "event_id": e["event_id"], "event_city": e["event_city"], "event_start": e["event_start"],
                    "hot_event": e["hot_event"], "account_id": acc,
                    "account_created": ts - timedelta(hours=rng.uniform(0.1, 30)) if acc else None,
                    "email": f"fr{r}{c}@" + rng.choice(["mailinator.com", "gmail.com", "yopmail.com", "mail.ru"]),
                    "phone_verified": False, "card_token": f"tok_F{r}_{c}",
                    "card_bin": rng.choice(KZ_BINS + ["411100", "530000", "455600"]),
                    "card_last4": f"{rng.randint(0, 9999):04d}",
                    "bin_country": rng.choice(["KZ", "US", "DE", "KZ"]),
                    "cardholder_name": rng.choice(["John Smith", "Aigerim Sadykova", None]),
                    "ip": f"185.{r}.{rng.randint(0, 255)}.{rng.randint(1, 250)}",
                    "ip_country": "KZ" if not proxy else cc, "ip_city": city, "ip_is_proxy": proxy,
                    "device_id": dev, "checkout_seconds": rng.choice([4.0, 6.0, 15.0, 25.0, 40.0]),
                    "channel": "web",
                })

    # --- card testing: три всплеска ---
    for b, mode in enumerate(["simple", "rotating", "rotating"]):
        t0 = start + timedelta(days=rng.uniform(1, days - 1), hours=rng.choice([2, 3, 4]))
        bin_ = rng.choice(["455600", "400100"])
        for k in range(rng.randint(250, 450)):
            ts = t0 + timedelta(seconds=k * rng.uniform(3, 9))
            dev = f"dev_CT{b}_{k}" if mode == "rotating" else f"dev_CT{b}_{k % 3}"
            ip = f"45.{b}.{rng.randint(0, 255)}.{rng.randint(1, 250)}" if mode == "rotating" else f"45.{b}.0.{k % 4}"
            e = min(events, key=lambda x: x["price"])
            rows.append({
                "attempt_id": nid("T"), "order_id": nid("O"), "ts": ts, "label": "card_testing",
                "amount_kzt": rng.choice([500, 800, 1000]), "tickets": 1, "event_id": e["event_id"],
                "event_city": e["event_city"], "event_start": e["event_start"], "hot_event": False,
                "account_id": None, "account_created": None, "email": f"bot{b}_{k}@yopmail.com",
                "phone_verified": False, "card_token": f"tok_CT{b}_{k}", "card_bin": bin_,
                "card_last4": f"{rng.randint(0, 9999):04d}", "bin_country": "KZ", "cardholder_name": None,
                "ip": ip, "ip_country": rng.choice(["KZ", "NL"]), "ip_city": None, "ip_is_proxy": rng.random() < 0.7,
                "device_id": dev, "checkout_seconds": rng.uniform(1.5, 6.0), "channel": "web",
            })

    rows.sort(key=lambda r: r["ts"])
    return rows
