"""Процесс работы с чарджбэками: классификация → доказательная база →
решение (оспорить / принять) → уведомления → обновление списков риска.
"""
from __future__ import annotations

from datetime import timedelta

from .engine import RiskEngine
from .models import Chargeback

# Коды причин МПС → категория. Достаточно для прототипа; полный справочник — в документе.
REASON_CATEGORY = {
    "10.4": "fraud", "10.5": "fraud", "4837": "fraud", "4863": "fraud",          # «не совершал»
    "13.1": "not_received", "4855": "not_received",                                # «услуга не оказана»
    "13.7": "cancelled", "4853": "cancelled",                                      # «отменено / не соответствует»
    "12.6": "processing", "4834": "processing",                                    # дубль списания
}


def classify(reason_code: str) -> str:
    return REASON_CATEGORY.get(reason_code, "other")


def build_evidence(engine: RiskEngine, cb: Chargeback) -> dict:
    s = engine.s
    att_id = s.order_attempt.get(cb.order_id)
    a = s.attempts.get(att_id) if att_id else None
    auth = s.auth.get(att_id) if att_id else None
    f = s.fulfilment.get(cb.order_id)
    category = classify(cb.reason_code)
    items: list[dict] = []
    score = 0

    def add(name: str, points: int, detail: str) -> None:
        nonlocal score
        score += points
        items.append({"evidence": name, "points": points, "detail": detail})

    liability_shift = bool(auth and auth.eci in {"05", "02"} and auth.three_ds in {"frictionless", "challenge_passed"})
    if category == "fraud" and liability_shift:
        add("3ds_liability_shift", 100, f"3-D Secure пройден, ECI {auth.eci}: ответственность на эмитенте")
    elif auth and auth.three_ds == "challenge_passed":
        add("3ds_challenge_passed", 30, "Держатель прошёл челлендж 3-D Secure")
    if f:
        if f.ticket_scanned_at_venue:
            add("ticket_scanned", 45, f"Билет отсканирован на входе {f.scan_time or ''}".strip())
        if f.ticket_downloaded:
            add("ticket_downloaded", 15, "Билет скачан из личного кабинета/приложения")
        if f.ticket_sent_to:
            add("ticket_delivered", 10, f"Билет отправлен на {f.ticket_sent_to}")
        if category in {"not_received", "cancelled"} and f.event_took_place:
            add("event_took_place", 20, "Мероприятие состоялось, условия возврата опубликованы")
    if a:
        prior = [x for x in s.attempts.values()
                 if x.card_token == a.card_token and x.order_id != a.order_id
                 and x.order_id in s.order_attempt and x.ts < a.ts - timedelta(days=120)
                 and x.ts > a.ts - timedelta(days=365)
                 and (x.device_id == a.device_id or x.ip == a.ip or (x.account_id and x.account_id == a.account_id))]
        if len(prior) >= 2:
            add("compelling_evidence_3_0", 40, f"{len(prior)} прошлых неоспоренных оплаты той же картой с тем же устройством/IP/аккаунтом (Visa CE 3.0)")
        add("transaction_context", 5, f"IP {a.ip}, устройство {a.device_id}, канал {a.channel}, время {a.ts:%Y-%m-%d %H:%M}")

    min_score = engine.p["chargebacks"]["represent_min_evidence_score"]
    if category == "processing":
        recommendation = "accept_and_refund"  # дубль — признаём, расследуем причину
    else:
        recommendation = "represent" if score >= min_score else "accept"
    return {"chargeback_id": cb.chargeback_id, "order_id": cb.order_id, "reason_code": cb.reason_code,
            "category": category, "evidence_score": score, "recommendation": recommendation,
            "respond_by": (cb.received + timedelta(days=engine.p["chargebacks"]["response_days"])).date().isoformat(),
            "items": items}


def process_chargeback(engine: RiskEngine, cb: Chargeback) -> dict:
    ev = build_evidence(engine, cb)
    s = engine.s
    att_id = s.order_attempt.get(cb.order_id)
    a = s.attempts.get(att_id) if att_id else None
    f = s.fulfilment.get(cb.order_id)
    risk_actions: list[str] = []
    notifications: list[str] = [f"Финансы/антифрод: чарджбэк {cb.chargeback_id} по заказу {cb.order_id}, "
                                f"код {cb.reason_code}, рекомендация «{ev['recommendation']}», срок {ev['respond_by']}"]
    if a:
        keys = engine.entity_keys(a)
        if ev["category"] == "fraud" and ev["recommendation"] == "accept":
            # Настоящий фрод: всё, что связано с заказом, в серый список; карта — в чёрный
            engine.add_graylist(keys, cb.received)
            engine.add_blocklist([f"card:{a.card_token}"])
            risk_actions += ["blocklist:card"] + [f"graylist:{k.split(':')[0]}" for k in keys]
            if a.event_start > cb.received and not (f and f.ticket_scanned_at_venue):
                risk_actions.append("ticket_annulled")
                notifications.append(f"Контроль входа: билет заказа {cb.order_id} аннулирован")
            s.good_orders_by_card[a.card_token] = 0
        elif ev["category"] == "fraud" and ev["recommendation"] == "represent":
            # «Не совершал», но билет использован / 3DS пройден — признак дружественного фрода
            engine.add_graylist([k for k in keys if not k.startswith("card:")], cb.received)
            risk_actions.append("graylist:account_device_email (friendly_fraud)")
            notifications.append(f"Покупателю: уведомление о споре по заказу {cb.order_id} и доказательствах исполнения")
    notifications.append(f"Эквайеру: {'пакет доказательств' if ev['recommendation'] == 'represent' else 'согласие с чарджбэком'}")
    ev["risk_actions"] = risk_actions
    ev["notifications"] = notifications
    return ev
