"""Симуляция трёх политик на одном вымышленном потоке:

  no_3ds      — 3-D Secure не запрашивается никогда (текущий вариант «не применяется»)
  3ds_all     — челлендж 3-D Secure для всех (текущий вариант «для всех подряд»)
  risk_based  — предлагаемый риск-контур: скоринг + card testing + процесс чарджбэков

Поведение эмитентов, покупателей и мошенников задано допущениями ASSUMPTIONS —
это модель для сравнения политик между собой, а не прогноз для Ticketon.
"""
from __future__ import annotations

import heapq
import itertools
import random
from datetime import timedelta

from .chargebacks import process_chargeback
from .engine import RiskEngine
from .models import Action, AuthResult, Chargeback, OrderFulfilment, PaymentAttempt
from .synthetic import generate

ASSUMPTIONS = {
    "issuer_approve": {"legit": 0.95, "friendly": 0.95, "carding": 0.75, "card_testing": 0.15},
    "abandon_challenge_legit": 0.08,   # честный покупатель бросает оплату на челлендже 3DS
    "abandon_strict_legit": 0.12,      # то же при строгом режиме (челлендж + доп. подтверждение)
    "pass_challenge_carding": 0.12,    # мошенник проходит челлендж (перехваченный OTP)
    "pass_strict_carding": 0.06,
    "pass_challenge_bot": 0.0,         # бот не проходит челлендж, авторизация не отправляется
    "fraud_cb_prob": 0.85,             # доля одобренного фрода без liability shift, ставшая чарджбэком
    "fraud_alert_prob": 0.6,           # ранние фрод-уведомления эмитента (TC40/SAFE, Ethoca/Verifi)
    "fraud_alert_days": (3, 7),
    "cb_delay_days": (10, 45),
    "cb_fee_kzt": 7500,                # комиссия/штраф эквайера за чарджбэк
    "represent_win_friendly": 0.65,    # выигрыш оспаривания при доказательствах исполнения
    "represent_win_real_fraud": 0.10,
    "scan_prob": {"legit": 0.9, "friendly": 0.95, "carding": 0.5},  # перепроданные краденые билеты тоже сканируют
}
FIELDS = set(PaymentAttempt.model_fields)


def _attempt(row: dict) -> PaymentAttempt:
    return PaymentAttempt(**{k: v for k, v in row.items() if k in FIELDS})


def run_policy(rows: list[dict], policy: str, seed: int = 7) -> dict:
    A = ASSUMPTIONS
    rng = random.Random(seed)
    engine = RiskEngine() if policy == "risk_based" else None
    queue: list = []
    seq = itertools.count()
    m = {k: 0 for k in ["legit_attempts", "legit_approved", "legit_rule_declined", "legit_abandoned",
                        "approved", "approved_amount", "fraud_approved", "fraud_approved_amount",
                        "fraud_reports_or_disputes", "chargebacks", "cb_won", "cb_lost_amount", "cb_fees",
                        "auth_sent", "auth_declined", "ct_attempts", "ct_auth_sent", "ct_rule_blocked",
                        "carding_attempts", "carding_rule_blocked", "lost_revenue_legit", "challenges"]}

    def push(ts, kind, payload):
        heapq.heappush(queue, (ts, next(seq), kind, payload))

    def drain(until):
        while queue and queue[0][0] <= until:
            _, _, kind, payload = heapq.heappop(queue)
            if engine is None:
                continue
            if kind == "alert":
                engine.add_graylist(engine.entity_keys(payload), payload.ts)
            elif kind == "fulfil":
                engine.record_fulfilment(payload)
            elif kind == "cb":
                process_chargeback(engine, payload)

    for row in rows:
        a = _attempt(row)
        label = row["label"]
        drain(a.ts)
        honest = label in ("legit", "friendly")
        if honest:
            m["legit_attempts"] += 1
        if label == "card_testing":
            m["ct_attempts"] += 1
        if label == "carding":
            m["carding_attempts"] += 1

        if policy == "no_3ds":
            action = Action.allow_frictionless
        elif policy == "3ds_all":
            action = Action.challenge_3ds
        else:
            action = engine.score(a).action

        if action == Action.decline:
            if honest:
                m["legit_rule_declined"] += 1
                m["lost_revenue_legit"] += a.amount_kzt
            elif label == "card_testing":
                m["ct_rule_blocked"] += 1
            else:
                m["carding_rule_blocked"] += 1
            continue

        three_ds, eci = "none", None
        if action in (Action.challenge_3ds, Action.challenge_3ds_strict):
            m["challenges"] += 1
            strict = action == Action.challenge_3ds_strict
            if honest:
                passed = rng.random() >= A["abandon_strict_legit" if strict else "abandon_challenge_legit"]
            elif label == "carding":
                passed = rng.random() < A["pass_strict_carding" if strict else "pass_challenge_carding"]
            else:
                passed = rng.random() < A["pass_challenge_bot"]
            if not passed:
                if honest:
                    m["legit_abandoned"] += 1
                    m["lost_revenue_legit"] += a.amount_kzt
                if engine:
                    engine.record_auth(AuthResult(attempt_id=a.attempt_id, approved=False, three_ds="challenge_failed"))
                continue
            three_ds, eci = "challenge_passed", "05"

        # авторизация у эмитента
        m["auth_sent"] += 1
        if label == "card_testing":
            m["ct_auth_sent"] += 1
        approved = rng.random() < A["issuer_approve"][label]
        if engine:
            engine.record_auth(AuthResult(attempt_id=a.attempt_id, approved=approved, three_ds=three_ds, eci=eci))
        if not approved:
            m["auth_declined"] += 1
            if honest:
                m["lost_revenue_legit"] += a.amount_kzt
            continue

        m["approved"] += 1
        m["approved_amount"] += a.amount_kzt
        if honest:
            m["legit_approved"] += 1
        if label in ("carding", "legit", "friendly"):
            if rng.random() < A["scan_prob"][label]:
                push(a.event_start, "fulfil", OrderFulfilment(order_id=a.order_id, ticket_sent_to=a.email,
                                                              ticket_downloaded=True, ticket_scanned_at_venue=True,
                                                              scan_time=a.event_start))
        liability_shift = eci == "05"

        if label in ("carding", "card_testing"):
            m["fraud_approved"] += 1
            m["fraud_approved_amount"] += a.amount_kzt
            m["fraud_reports_or_disputes"] += 1
            if rng.random() < A["fraud_alert_prob"]:
                push(a.ts + timedelta(days=rng.uniform(*A["fraud_alert_days"])), "alert", a)
            if not liability_shift and rng.random() < A["fraud_cb_prob"]:
                cb = Chargeback(chargeback_id=f"CB{a.attempt_id}", order_id=a.order_id, reason_code="10.4",
                                amount_kzt=a.amount_kzt,
                                received=a.ts + timedelta(days=rng.uniform(*A["cb_delay_days"])))
                m["chargebacks"] += 1
                m["cb_fees"] += A["cb_fee_kzt"]
                # настоящий фрод без liability shift признаём: оспаривание почти не выигрывается
                m["cb_lost_amount"] += a.amount_kzt
                push(cb.received, "cb", cb)
        elif label == "friendly":
            m["fraud_reports_or_disputes"] += 1
            cb = Chargeback(chargeback_id=f"CB{a.attempt_id}", order_id=a.order_id, reason_code="10.4",
                            amount_kzt=a.amount_kzt, received=a.ts + timedelta(days=rng.uniform(*A["cb_delay_days"])))
            m["chargebacks"] += 1
            m["cb_fees"] += A["cb_fee_kzt"]
            if liability_shift:
                won = True  # спор «не совершал» при пройденном 3DS — ответственность эмитента
            else:
                won = policy == "risk_based" and rng.random() < A["represent_win_friendly"]
            if won:
                m["cb_won"] += 1
            else:
                m["cb_lost_amount"] += a.amount_kzt
            push(cb.received, "cb", cb)
    drain(rows[-1]["ts"] + timedelta(days=90))
    return _metrics(policy, m)


def _metrics(policy: str, m: dict) -> dict:
    def pct(x, y):
        return round(100 * x / y, 3) if y else 0.0
    return {
        "policy": policy,
        "legit_conversion_pct": pct(m["legit_approved"], m["legit_attempts"]),
        "false_decline_pct": pct(m["legit_rule_declined"], m["legit_attempts"]),
        "legit_abandon_3ds_pct": pct(m["legit_abandoned"], m["legit_attempts"]),
        "challenge_rate_pct": pct(m["challenges"], m["legit_attempts"] + m["ct_attempts"] + m["carding_attempts"]),
        "fraud_share_turnover_pct": pct(m["fraud_approved_amount"], m["approved_amount"]),
        "chargeback_ratio_pct": pct(m["chargebacks"], m["approved"]),
        "fraud_and_dispute_ratio_pct": pct(m["fraud_reports_or_disputes"], m["approved"]),
        "issuer_decline_ratio_pct": pct(m["auth_declined"], m["auth_sent"]),
        "card_testing_auths_sent": m["ct_auth_sent"],
        "card_testing_attempts": m["ct_attempts"],
        "carding_blocked_by_rules": m["carding_rule_blocked"],
        "losses_kzt": m["cb_lost_amount"] + m["cb_fees"],
        "lost_revenue_legit_kzt": m["lost_revenue_legit"],
        "approved_turnover_kzt": m["approved_amount"],
        "raw": m,
    }


def compare(days: int = 30, seed: int = 42) -> list[dict]:
    rows = generate(days=days, seed=seed)
    return [run_policy(rows, p) for p in ("no_3ds", "3ds_all", "risk_based")]


if __name__ == "__main__":
    for r in compare():
        print({k: v for k, v in r.items() if k != "raw"})
