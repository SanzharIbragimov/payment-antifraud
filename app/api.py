"""HTTP API риск-контура оплаты + демонстрационная панель."""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .chargebacks import process_chargeback
from .engine import RiskEngine
from .models import AuthResult, Chargeback, Decision, OrderFulfilment, PaymentAttempt
from .simulate import ASSUMPTIONS, compare

app = FastAPI(title="Ticketon Payment Antifraud — прототип", version="0.1.0")
engine = RiskEngine()
_sim_cache: list[dict] | None = None
SIM_DAYS = int(os.getenv("SIM_DAYS", "30"))


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/v1/policy")
def policy() -> dict:
    return engine.p


@app.post("/v1/payments/score", response_model=Decision)
def score(a: PaymentAttempt) -> Decision:
    return engine.score(a)


@app.post("/v1/payments/auth-result")
def auth_result(r: AuthResult) -> dict:
    try:
        engine.record_auth(r)
    except KeyError:
        raise HTTPException(404, "attempt not found")
    return {"ok": True, "shield_mode": engine.shield_active(engine.s.attempts[r.attempt_id].ts)}


@app.post("/v1/orders/fulfilment")
def fulfilment(f: OrderFulfilment) -> dict:
    engine.record_fulfilment(f)
    return {"ok": True}


@app.post("/v1/chargebacks")
def chargeback(cb: Chargeback) -> dict:
    return process_chargeback(engine, cb)


@app.get("/v1/decisions/recent")
def recent(limit: int = 20) -> list[dict]:
    return list(engine.s.log)[:limit]


@app.get("/v1/metrics/simulation")
def simulation() -> dict:
    global _sim_cache
    if _sim_cache is None:
        _sim_cache = [{k: v for k, v in r.items() if k != "raw"} for r in compare(days=SIM_DAYS)]
    return {"note": "Вымышленный поток и допущения модели; не данные Ticketon", "assumptions": ASSUMPTIONS,
            "results": _sim_cache}


SCENARIOS = {
    "honest": dict(account_id="A00001", account_created_days=400, email="aliya@mail.kz", phone_verified=True,
                   card_token="tok_demo_honest", card_bin="400100", bin_country="KZ", ip_country="KZ",
                   ip_is_proxy=False, device_id="dev_demo_honest", checkout_seconds=75, tickets=2,
                   amount_kzt=24000, hot_event=False, hours_to_event=72, cardholder_name="Aliya Nurlanova"),
    "tourist": dict(account_id="A00777", account_created_days=30, email="mehmet@gmail.com", phone_verified=False,
                    card_token="tok_demo_tourist", card_bin="530000", bin_country="TR", ip_country="KZ",
                    ip_is_proxy=False, device_id="dev_demo_tourist", checkout_seconds=95, tickets=2,
                    amount_kzt=50000, hot_event=False, hours_to_event=30, cardholder_name="Mehmet Kaya"),
    "carding": dict(account_id=None, account_created_days=None, email="fast1@yopmail.com", phone_verified=False,
                    card_token="tok_demo_stolen", card_bin="411100", bin_country="US", ip_country="NL",
                    ip_is_proxy=True, device_id="dev_demo_fraud", checkout_seconds=4, tickets=8,
                    amount_kzt=480000, hot_event=True, hours_to_event=2, cardholder_name=None),
}


@app.post("/v1/demo/score/{scenario}", response_model=Decision)
def demo_score(scenario: str) -> Decision:
    sc = SCENARIOS.get(scenario)
    if not sc:
        raise HTTPException(404, "unknown scenario")
    now = datetime.now().replace(microsecond=0)
    n = len(engine.s.attempts) + 1
    a = PaymentAttempt(
        attempt_id=f"DEMO{n}", order_id=f"ORD{n}", ts=now, amount_kzt=sc["amount_kzt"], tickets=sc["tickets"],
        event_id="EV-DEMO", event_city="Astana", event_start=now + timedelta(hours=sc["hours_to_event"]),
        hot_event=sc["hot_event"], account_id=sc["account_id"],
        account_created=now - timedelta(days=sc["account_created_days"]) if sc["account_created_days"] else None,
        email=sc["email"], phone_verified=sc["phone_verified"], card_token=sc["card_token"],
        card_bin=sc["card_bin"], card_last4="4242", bin_country=sc["bin_country"],
        cardholder_name=sc["cardholder_name"], ip=f"10.0.0.{n % 250}", ip_country=sc["ip_country"],
        ip_city="Amsterdam" if sc["ip_country"] == "NL" else "Astana", ip_is_proxy=sc["ip_is_proxy"],
        device_id=sc["device_id"], checkout_seconds=sc["checkout_seconds"])
    return engine.score(a)


@app.post("/v1/demo/chargeback/{scenario}")
def demo_chargeback(scenario: str) -> dict:
    """friendly — билет использован, но покупатель заявляет «не совершал»; fraud — краденая карта."""
    if scenario not in ("friendly", "fraud"):
        raise HTTPException(404, "unknown scenario")
    now = datetime.now().replace(microsecond=0)
    n = len(engine.s.attempts) + 1
    friendly = scenario == "friendly"
    paid = now - timedelta(days=200 if friendly else 20)
    for i, back in enumerate([200 + 160, 200 + 130] if friendly else []):  # прошлые оплаты той же картой
        pa = PaymentAttempt(attempt_id=f"HIST{n}_{i}", order_id=f"HORD{n}_{i}", ts=now - timedelta(days=back),
                            amount_kzt=15000, event_id="EV-OLD", event_start=now - timedelta(days=back - 5),
                            account_id="A-CB", email="arman@mail.kz", card_token=f"tok_cb_{scenario}",
                            card_bin="400100", card_last4="1111", ip="10.1.1.1", device_id="dev_cb_friendly")
        engine.score(pa)
        engine.record_auth(AuthResult(attempt_id=pa.attempt_id, approved=True, three_ds="none"))
    a = PaymentAttempt(attempt_id=f"CBT{n}", order_id=f"CBO{n}", ts=paid, amount_kzt=36000, tickets=3,
                       event_id="EV-CB", event_start=paid + timedelta(days=10 if friendly else 40),
                       account_id="A-CB" if friendly else None, email="arman@mail.kz" if friendly else "x@yopmail.com",
                       card_token=f"tok_cb_{scenario}", card_bin="400100", card_last4="1111",
                       ip="10.1.1.1" if friendly else "185.9.9.9",
                       device_id="dev_cb_friendly" if friendly else "dev_cb_fraud")
    engine.score(a)
    engine.record_auth(AuthResult(attempt_id=a.attempt_id, approved=True, three_ds="none"))
    engine.record_fulfilment(OrderFulfilment(order_id=a.order_id, ticket_sent_to=a.email, ticket_downloaded=friendly,
                                             ticket_scanned_at_venue=friendly,
                                             scan_time=a.event_start if friendly else None))
    cb = Chargeback(chargeback_id=f"CB{n}", order_id=a.order_id, reason_code="10.4", amount_kzt=36000,
                    received=paid + timedelta(days=40 if friendly else 15))
    return process_chargeback(engine, cb)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")
