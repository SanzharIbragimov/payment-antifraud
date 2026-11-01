"""Модели данных риск-контура оплаты.

Номер карты (PAN) не принимается и не хранится: только токен платёжного
провайдера, BIN (6 цифр) и последние 4 цифры — минимизация зоны PCI DSS.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Action(str, Enum):
    allow_frictionless = "allow_frictionless"
    challenge_3ds = "challenge_3ds"
    challenge_3ds_strict = "challenge_3ds_strict"
    decline = "decline"


class PaymentAttempt(BaseModel):
    attempt_id: str
    order_id: str
    ts: datetime
    amount_kzt: int = Field(ge=0)
    tickets: int = Field(ge=1, default=1)
    event_id: str
    event_city: str = "Astana"
    event_start: datetime
    hot_event: bool = False

    account_id: Optional[str] = None  # None = гостевая покупка
    account_created: Optional[datetime] = None
    email: str
    phone_verified: bool = False

    card_token: str
    card_bin: str = Field(min_length=6, max_length=8)
    card_last4: str = Field(min_length=4, max_length=4)
    bin_country: str = "KZ"
    cardholder_name: Optional[str] = None

    ip: str
    ip_country: str = "KZ"
    ip_city: Optional[str] = None
    ip_is_proxy: bool = False
    device_id: str
    checkout_seconds: float = 60.0
    channel: str = "web"  # web | ios | android


class Decision(BaseModel):
    attempt_id: str
    score: int
    level: str
    action: Action
    reasons: list[str]
    card_testing: bool = False
    shield_mode: bool = False


class AuthResult(BaseModel):
    """Результат авторизации от эквайера/3DS — обратная связь в контур."""
    attempt_id: str
    approved: bool
    three_ds: Optional[str] = None  # frictionless | challenge_passed | challenge_failed | none
    eci: Optional[str] = None       # 05/02 — аутентифицировано (liability shift)
    decline_code: Optional[str] = None


class Chargeback(BaseModel):
    chargeback_id: str
    order_id: str
    reason_code: str            # например Visa 10.4, MC 4837
    amount_kzt: int
    received: datetime


class OrderFulfilment(BaseModel):
    """Факты исполнения заказа — главный аргумент при оспаривании."""
    order_id: str
    ticket_sent_to: Optional[str] = None
    ticket_downloaded: bool = False
    ticket_scanned_at_venue: bool = False
    scan_time: Optional[datetime] = None
    event_took_place: bool = True
