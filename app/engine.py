"""Риск-движок: card testing → жёсткие правила → скоринг → маршрутизация.

Хранилище в памяти (в продакшене — Redis для скользящих окон и списков,
PostgreSQL для истории решений). Время берётся из события (attempt.ts),
поэтому движок детерминирован и пригоден для симуляции на истории.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

import yaml

from .models import Action, AuthResult, Decision, OrderFulfilment, PaymentAttempt

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"
DISPOSABLE_DOMAINS = {"mailinator.com", "tempmail.org", "10minutemail.com", "guerrillamail.com", "yopmail.com"}
ACTION_RANK = {Action.allow_frictionless: 0, Action.challenge_3ds: 1, Action.challenge_3ds_strict: 2, Action.decline: 3}


def load_policy(path: Path | str = POLICY_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


class SlidingWindow:
    """Скользящее окно событий (ts, value) по ключу."""

    def __init__(self) -> None:
        self._data: dict[str, deque] = defaultdict(deque)
        self._keep: dict[str, timedelta] = {}

    def add(self, key: str, ts: datetime, value: object = 1, keep: timedelta = timedelta(days=7)) -> None:
        self._data[key].append((ts, value))
        self._keep[key] = keep

    def _prune(self, key: str, now: datetime, span: timedelta) -> deque:
        q = self._data[key]
        keep = self._keep.get(key, timedelta(days=7))
        while q and q[0][0] < now - keep:
            q.popleft()
        return q

    def count(self, key: str, now: datetime, span: timedelta) -> int:
        return sum(1 for ts, _ in self._prune(key, now, span) if ts >= now - span)

    def distinct(self, key: str, now: datetime, span: timedelta) -> int:
        return len({v for ts, v in self._prune(key, now, span) if ts >= now - span})

    def values(self, key: str, now: datetime, span: timedelta) -> list:
        return [v for ts, v in self._prune(key, now, span) if ts >= now - span]


@dataclass
class Store:
    attempts: dict[str, PaymentAttempt] = field(default_factory=dict)
    decisions: dict[str, Decision] = field(default_factory=dict)
    auth: dict[str, AuthResult] = field(default_factory=dict)
    order_attempt: dict[str, str] = field(default_factory=dict)       # order_id → последняя успешная попытка
    fulfilment: dict[str, OrderFulfilment] = field(default_factory=dict)
    blocklist: set[str] = field(default_factory=set)                   # подтверждённый фрод (карта/устройство/почта/аккаунт)
    graylist: dict[str, datetime] = field(default_factory=dict)        # ключ → истекает
    temp_block: dict[str, datetime] = field(default_factory=dict)      # card testing: устройство/IP → до
    bin_pressure: dict[str, datetime] = field(default_factory=dict)    # BIN под атакой → до
    shield_until: datetime | None = None
    good_orders_by_card: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    seen_card_account: set[tuple[str, str]] = field(default_factory=set)
    w: SlidingWindow = field(default_factory=SlidingWindow)
    log: deque = field(default_factory=lambda: deque(maxlen=500))


class RiskEngine:
    def __init__(self, policy: dict | None = None) -> None:
        self.p = policy or load_policy()
        self.s = Store()

    # ---------- списки риска ----------
    @staticmethod
    def entity_keys(a: PaymentAttempt) -> list[str]:
        keys = [f"card:{a.card_token}", f"dev:{a.device_id}", f"email:{a.email.lower()}"]
        if a.account_id:
            keys.append(f"acc:{a.account_id}")
        return keys

    def add_graylist(self, keys: Iterable[str], now: datetime) -> None:
        ttl = timedelta(days=self.p["chargebacks"]["graylist_ttl_days"])
        for k in keys:
            self.s.graylist[k] = now + ttl

    def add_blocklist(self, keys: Iterable[str]) -> None:
        self.s.blocklist.update(keys)

    def _gray_hit(self, a: PaymentAttempt) -> bool:
        return any(self.s.graylist.get(k, a.ts) > a.ts for k in self.entity_keys(a))

    # ---------- card testing ----------
    def _card_testing(self, a: PaymentAttempt, reasons: list[str]) -> Action | None:
        ct = self.p["card_testing"]
        now, m10 = a.ts, timedelta(minutes=10)
        w = self.s.w
        w.add(f"ct_dev:{a.device_id}", now, a.card_token, keep=m10)
        w.add(f"ct_ip:{a.ip}", now, a.card_token, keep=m10)
        w.add(f"ct_bin:{a.card_bin}", now, a.card_token, keep=m10)

        for key in (f"dev:{a.device_id}", f"ip:{a.ip}"):
            until = self.s.temp_block.get(key)
            if until and until > now:
                reasons.append(f"card_testing_blocked:{key.split(':')[0]}")
                return Action.decline

        ttl = timedelta(minutes=ct["block_ttl_min"])
        if w.distinct(f"ct_dev:{a.device_id}", now, m10) >= ct["device_distinct_cards_10m"]:
            self.s.temp_block[f"dev:{a.device_id}"] = now + ttl
            reasons.append("card_testing:device_many_cards_10m")
            return Action.decline
        if w.distinct(f"ct_ip:{a.ip}", now, m10) >= ct["ip_distinct_cards_10m"]:
            self.s.temp_block[f"ip:{a.ip}"] = now + ttl
            reasons.append("card_testing:ip_many_cards_10m")
            return Action.decline
        if w.distinct(f"ct_bin:{a.card_bin}", now, m10) >= ct["bin_distinct_cards_10m"]:
            self.s.bin_pressure[a.card_bin] = now + ttl
        if self.s.bin_pressure.get(a.card_bin, now) > now:
            reasons.append("card_testing:bin_under_attack")
            return Action.challenge_3ds_strict
        return None

    def _update_shield(self, now: datetime) -> None:
        ct = self.p["card_testing"]
        m5 = timedelta(minutes=5)
        total = self.s.w.count("global_auth", now, m5)
        declined = self.s.w.count("global_decline", now, m5)
        if total >= ct["shield_min_attempts_5m"] and declined / total >= ct["shield_decline_rate_5m"]:
            self.s.shield_until = now + timedelta(minutes=ct["shield_ttl_min"])

    def shield_active(self, now: datetime) -> bool:
        return bool(self.s.shield_until and self.s.shield_until > now)

    # ---------- сигналы ----------
    def signals(self, a: PaymentAttempt) -> list[str]:
        t, w, now = self.p["thresholds"], self.s.w, a.ts
        fired: list[str] = []
        if a.account_id is None:
            fired.append("guest_checkout")
        elif a.account_created and now - a.account_created < timedelta(hours=t["new_account_hours"]):
            fired.append("new_account")
        if a.email.split("@")[-1].lower() in DISPOSABLE_DOMAINS:
            fired.append("email_disposable")
        if a.bin_country != a.ip_country:
            fired.append("bin_country_mismatch")
        if a.ip_is_proxy:
            fired.append("ip_proxy_or_hosting")
        if a.ip_city and a.ip_city != a.event_city and a.ip_country != "KZ":
            fired.append("geo_far_from_event")
        if a.amount_kzt >= t["high_amount_kzt"]:
            fired.append("high_amount")
        if a.tickets >= t["many_tickets"]:
            fired.append("many_tickets")
        if a.hot_event:
            fired.append("hot_event")
        if timedelta(0) <= a.event_start - now < timedelta(hours=t["last_minute_hours"]):
            fired.append("last_minute")
        if a.account_id and (a.card_token, a.account_id) not in self.s.seen_card_account:
            fired.append("card_new_to_account")
        if w.distinct(f"dev_cards:{a.device_id}", now, timedelta(hours=24)) >= t["cards_per_device_24h"]:
            fired.append("cards_per_device_24h")
        if w.count(f"card_attempts:{a.card_token}", now, timedelta(hours=1)) >= t["attempts_per_card_1h"]:
            fired.append("attempts_per_card_1h")
        if w.count(f"dev_declines:{a.device_id}", now, timedelta(hours=1)) >= t["declines_device_1h"]:
            fired.append("declines_device_1h")
        if w.distinct(f"card_accounts:{a.card_token}", now, timedelta(days=7)) >= t["accounts_per_card_7d"]:
            fired.append("accounts_per_card_7d")
        if a.cardholder_name and a.account_id:
            last = a.cardholder_name.split()[-1].lower()[:4]
            if last and last not in a.email.lower():
                fired.append("name_email_mismatch")
        if a.checkout_seconds < t["fast_checkout_sec"]:
            fired.append("fast_checkout")
        if self._gray_hit(a):
            fired.append("risk_list_hit")
        if self.s.good_orders_by_card[a.card_token] >= t["trusted_min_paid_orders"]:
            fired.append("trusted_customer")
        if a.phone_verified:
            fired.append("verified_phone")
        return fired

    def _level(self, score: int) -> tuple[str, Action]:
        for lvl in self.p["levels"]:
            if score <= lvl["max_score"]:
                return lvl["name"], Action(lvl["action"])
        last = self.p["levels"][-1]
        return last["name"], Action(last["action"])

    # ---------- основной вызов ----------
    def score(self, a: PaymentAttempt) -> Decision:
        reasons: list[str] = []
        now = a.ts
        floor = Action.allow_frictionless

        # 0. Жёсткие правила: чёрный список
        if self.p["hard_rules"]["blocklist_decline"] and any(k in self.s.blocklist for k in self.entity_keys(a)):
            return self._finish(a, Decision(attempt_id=a.attempt_id, score=100, level="critical",
                                            action=Action.decline, reasons=["blocklist"]))

        # 1. Card testing — до скоринга, дешёвые проверки скоростей
        ct_action = self._card_testing(a, reasons)
        if ct_action == Action.decline:
            return self._finish(a, Decision(attempt_id=a.attempt_id, score=100, level="critical",
                                            action=Action.decline, reasons=reasons, card_testing=True))
        if ct_action:
            floor = ct_action

        # 2. Скоринг
        fired = self.signals(a)
        weights = self.p["signals"]
        raw = sum(weights[s] for s in fired)
        score = max(0, min(100, raw))
        level, action = self._level(score)
        reasons += [f"{s}({weights[s]:+d})" for s in fired]

        # 3. Минимальные пороги действия
        if a.account_id is None and a.amount_kzt > self.p["hard_rules"]["max_amount_guest_kzt"]:
            floor = max(floor, Action.challenge_3ds_strict, key=ACTION_RANK.get)
            reasons.append("floor:guest_high_amount")
        shield = self.shield_active(now)
        if shield:
            floor = max(floor, Action.challenge_3ds, key=ACTION_RANK.get)
            reasons.append("floor:shield_mode")
        action = max(action, floor, key=ACTION_RANK.get)

        return self._finish(a, Decision(attempt_id=a.attempt_id, score=score, level=level, action=action,
                                        reasons=reasons, card_testing=bool(ct_action), shield_mode=shield))

    def _finish(self, a: PaymentAttempt, d: Decision) -> Decision:
        w, now = self.s.w, a.ts
        self.s.attempts[a.attempt_id] = a
        self.s.decisions[a.attempt_id] = d
        w.add(f"dev_cards:{a.device_id}", now, a.card_token, keep=timedelta(hours=24))
        w.add(f"card_attempts:{a.card_token}", now, keep=timedelta(hours=1))
        if a.account_id:
            w.add(f"card_accounts:{a.card_token}", now, a.account_id)
        self.s.log.appendleft({"ts": now.isoformat(timespec="seconds"), "attempt_id": a.attempt_id,
                               "amount_kzt": a.amount_kzt, "score": d.score, "level": d.level,
                               "action": d.action.value, "reasons": d.reasons[:6]})
        return d

    # ---------- обратная связь ----------
    def record_auth(self, r: AuthResult) -> None:
        a = self.s.attempts.get(r.attempt_id)
        if not a:
            raise KeyError(r.attempt_id)
        self.s.auth[r.attempt_id] = r
        now = a.ts
        m5 = timedelta(minutes=5)
        self.s.w.add("global_auth", now, keep=m5)
        if not r.approved:
            self.s.w.add("global_decline", now, keep=m5)
            self.s.w.add(f"dev_declines:{a.device_id}", now, keep=timedelta(hours=1))
        else:
            self.s.order_attempt[a.order_id] = a.attempt_id
            if a.account_id:
                self.s.seen_card_account.add((a.card_token, a.account_id))
        self._update_shield(now)

    def record_fulfilment(self, f: OrderFulfilment) -> None:
        self.s.fulfilment[f.order_id] = f
        att = self.s.order_attempt.get(f.order_id)
        if att and f.ticket_scanned_at_venue:
            self.s.good_orders_by_card[self.s.attempts[att].card_token] += 1
