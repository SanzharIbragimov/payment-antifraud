from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.chargebacks import process_chargeback
from app.engine import RiskEngine
from app.models import Action, AuthResult, Chargeback, OrderFulfilment, PaymentAttempt
from app.simulate import compare

T0 = datetime(2026, 9, 10, 18, 0)
_n = 0


def att(**kw) -> PaymentAttempt:
    global _n
    _n += 1
    base = dict(attempt_id=f"T{_n}", order_id=f"O{_n}", ts=T0, amount_kzt=20000, tickets=2, event_id="E1",
                event_start=T0 + timedelta(days=5), account_id="A1", account_created=T0 - timedelta(days=300),
                email="aliya.nur@mail.kz", phone_verified=True, card_token="tok_1", card_bin="400100",
                card_last4="1111", ip="10.0.0.1", device_id="dev1", checkout_seconds=70,
                cardholder_name="Aliya Nur")
    base.update(kw)
    return PaymentAttempt(**base)


def test_honest_customer_passes_without_challenge():
    e = RiskEngine()
    d = e.score(att())
    assert d.action == Action.allow_frictionless
    assert d.level == "low"


def test_carding_profile_is_declined_or_challenged_strictly():
    e = RiskEngine()
    d = e.score(att(account_id=None, account_created=None, email="x@yopmail.com", phone_verified=False,
                    bin_country="US", ip_country="NL", ip_city="Amsterdam", ip_is_proxy=True, tickets=8,
                    amount_kzt=480000, hot_event=True, event_start=T0 + timedelta(hours=2), checkout_seconds=3))
    assert d.action in (Action.decline, Action.challenge_3ds_strict)
    assert d.score >= 80


def test_tourist_gets_3ds_not_decline():
    e = RiskEngine()
    d = e.score(att(account_id="A9", account_created=T0 - timedelta(days=30), bin_country="TR",
                    phone_verified=False, card_token="tok_tr", cardholder_name="Mehmet Kaya", email="mk@gmail.com"))
    assert d.action != Action.decline


def test_card_testing_device_blocked():
    e = RiskEngine()
    actions = [e.score(att(ts=T0 + timedelta(seconds=10 * i), card_token=f"tok_ct{i}", device_id="bot",
                           account_id=None, amount_kzt=500)).action for i in range(5)]
    assert actions[2] == Action.decline
    assert actions[4] == Action.decline  # устройство остаётся заблокированным


def test_card_testing_rotating_devices_bin_pressure():
    e = RiskEngine()
    last = None
    for i in range(16):
        last = e.score(att(ts=T0 + timedelta(seconds=5 * i), card_token=f"tok_r{i}", device_id=f"d{i}",
                           ip=f"45.0.{i}.1", card_bin="455600", account_id=None))
    assert last.action in (Action.challenge_3ds_strict, Action.decline)
    assert "card_testing:bin_under_attack" in last.reasons


def test_shield_mode_on_decline_spike():
    e = RiskEngine()
    for i in range(50):
        a = att(ts=T0 + timedelta(seconds=3 * i), card_token=f"tok_s{i}", device_id=f"ds{i}", ip=f"46.{i}.0.1",
                card_bin=f"4{i:05d}")
        e.score(a)
        e.record_auth(AuthResult(attempt_id=a.attempt_id, approved=i % 2 == 0))
    assert e.shield_active(T0 + timedelta(minutes=3))
    d = e.score(att(ts=T0 + timedelta(minutes=3), card_token="tok_honest2", device_id="dh"))
    assert d.action == Action.challenge_3ds and d.shield_mode


def test_blocklist_declines():
    e = RiskEngine()
    e.add_blocklist(["card:tok_bad"])
    assert e.score(att(card_token="tok_bad")).action == Action.decline


def test_trusted_customer_lowers_score():
    e = RiskEngine()
    first = e.score(att(card_token="tok_t", phone_verified=False, account_id=None, account_created=None))
    for i in range(3):
        a = att(card_token="tok_t", ts=T0 + timedelta(days=i))
        e.score(a)
        e.record_auth(AuthResult(attempt_id=a.attempt_id, approved=True))
        e.record_fulfilment(OrderFulfilment(order_id=a.order_id, ticket_scanned_at_venue=True))
    later = e.score(att(card_token="tok_t", phone_verified=False, account_id=None, account_created=None,
                        ts=T0 + timedelta(days=10)))
    assert later.score < first.score
    assert any(r.startswith("trusted_customer") for r in later.reasons)


def _paid(e, **kw):
    a = att(**kw)
    e.score(a)
    e.record_auth(AuthResult(attempt_id=a.attempt_id, approved=True, three_ds=kw.pop("three_ds", "none")))
    return a


def test_friendly_fraud_is_represented():
    e = RiskEngine()
    a = _paid(e, card_token="tok_f")
    e.record_fulfilment(OrderFulfilment(order_id=a.order_id, ticket_sent_to=a.email, ticket_downloaded=True,
                                        ticket_scanned_at_venue=True))
    r = process_chargeback(e, Chargeback(chargeback_id="CB1", order_id=a.order_id, reason_code="10.4",
                                         amount_kzt=a.amount_kzt, received=T0 + timedelta(days=30)))
    assert r["recommendation"] == "represent"
    assert e.s.graylist.get("acc:A1")  # аккаунт под наблюдением
    assert "card:tok_f" not in e.s.blocklist


def test_real_fraud_accepted_blocklisted_and_ticket_annulled():
    e = RiskEngine()
    a = _paid(e, card_token="tok_stolen", event_start=T0 + timedelta(days=40))
    r = process_chargeback(e, Chargeback(chargeback_id="CB2", order_id=a.order_id, reason_code="4837",
                                         amount_kzt=a.amount_kzt, received=T0 + timedelta(days=10)))
    assert r["recommendation"] == "accept"
    assert "ticket_annulled" in r["risk_actions"]
    assert e.score(att(card_token="tok_stolen", ts=T0 + timedelta(days=11))).action == Action.decline


def test_liability_shift_evidence():
    e = RiskEngine()
    a = att(card_token="tok_3ds")
    e.score(a)
    e.record_auth(AuthResult(attempt_id=a.attempt_id, approved=True, three_ds="challenge_passed", eci="05"))
    r = process_chargeback(e, Chargeback(chargeback_id="CB3", order_id=a.order_id, reason_code="10.4",
                                         amount_kzt=1, received=T0 + timedelta(days=20)))
    assert r["evidence_score"] >= 100 and r["recommendation"] == "represent"


def test_duplicate_processing_refunded():
    e = RiskEngine()
    a = _paid(e, card_token="tok_dup")
    r = process_chargeback(e, Chargeback(chargeback_id="CB4", order_id=a.order_id, reason_code="12.6",
                                         amount_kzt=1, received=T0 + timedelta(days=3)))
    assert r["recommendation"] == "accept_and_refund"


@pytest.fixture(scope="module")
def sim():
    return {r["policy"]: r for r in compare(days=10)}


def test_simulation_risk_based_beats_baselines(sim):
    nb, all3, rb = sim["no_3ds"], sim["3ds_all"], sim["risk_based"]
    assert rb["fraud_share_turnover_pct"] < nb["fraud_share_turnover_pct"] / 3
    assert rb["chargeback_ratio_pct"] < nb["chargeback_ratio_pct"]
    assert nb["legit_conversion_pct"] - rb["legit_conversion_pct"] < 1.0   # без значимого падения конверсии
    assert rb["legit_conversion_pct"] > all3["legit_conversion_pct"]
    assert rb["card_testing_auths_sent"] < nb["card_testing_auths_sent"] * 0.05


def test_api_endpoints():
    from app.api import app
    c = TestClient(app)
    assert c.get("/health").json()["status"] == "ok"
    assert c.get("/").status_code == 200
    d = c.post("/v1/demo/score/carding").json()
    assert d["action"] in ("decline", "challenge_3ds_strict")
    assert c.post("/v1/demo/chargeback/friendly").json()["recommendation"] == "represent"
    assert c.post("/v1/demo/chargeback/fraud").json()["recommendation"] == "accept"
    payload = att().model_dump(mode="json")
    assert c.post("/v1/payments/score", json=payload).json()["action"] == "allow_frictionless"
    assert len(c.get("/v1/decisions/recent").json()) >= 1
