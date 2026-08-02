from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence


REVIEW_THRESHOLD = 65
HIGH_RISK_THRESHOLD = 85
RECENT_WINDOW = timedelta(hours=24)
RELATED_WINDOW = timedelta(days=7)
EXACT_IP_REVIEW_WINDOW = timedelta(days=30)
NEW_ACCOUNT_WINDOW = timedelta(days=30)
NEW_SERVER_MEMBER_WINDOW = timedelta(days=30)
NEW_ACCOUNT_SCORE = 5
NEW_SERVER_MEMBER_SCORE = 5
COUNTRY_NETWORK_MATCH_SCORE = 10
VPN_SINGLE_PROVIDER_SCORE = 65
VPN_MULTIPLE_PROVIDER_SCORE = 100


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    level: str
    decision: str
    possible_main_user_id: int | None
    reasons: tuple[str, ...]
    related_user_count: int

    @property
    def requires_review(self) -> bool:
        return self.decision == "review"


@dataclass(frozen=True, slots=True)
class _CandidateAssessment:
    user_id: int
    score: int
    reasons: tuple[str, ...]
    created_at: datetime
    preferred_main: bool


def _value(record: Any, key: str):
    try:
        return record[key]
    except (KeyError, TypeError):
        return getattr(record, key, None)


def _utc_datetime(value: datetime | None) -> datetime:
    if value is None:
        return datetime.fromtimestamp(0, timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _same_nonempty(current: Any, candidate: Any, key: str) -> bool:
    current_value = _value(current, key)
    candidate_value = _value(candidate, key)
    return bool(current_value) and current_value == candidate_value


def _is_within_window(
    value: datetime | None,
    current_time: datetime,
    window: timedelta,
) -> bool:
    if value is None:
        return False
    age = max(timedelta(0), current_time - _utc_datetime(value))
    return age <= window


def assess_verification_risk(
    current: Any,
    candidates: Sequence[Any],
    *,
    now: datetime | None = None,
    account_created_at: datetime | None = None,
    server_joined_at: datetime | None = None,
    vpn_detected_by: Sequence[str] = (),
) -> RiskAssessment:
    current_time = _utc_datetime(now or datetime.now(timezone.utc))
    base_score = 0
    base_reasons = []
    if _is_within_window(
        account_created_at,
        current_time,
        NEW_ACCOUNT_WINDOW,
    ):
        base_score += NEW_ACCOUNT_SCORE
        base_reasons.append("Cuenta de Discord creada hace menos de 30 dias")
    if _is_within_window(
        server_joined_at,
        current_time,
        NEW_SERVER_MEMBER_WINDOW,
    ):
        base_score += NEW_SERVER_MEMBER_SCORE
        base_reasons.append("Ingreso al servidor hace menos de 30 dias")

    vpn_providers = tuple(dict.fromkeys(vpn_detected_by))
    if len(vpn_providers) >= 2:
        base_score += VPN_MULTIPLE_PROVIDER_SCORE
    elif vpn_providers:
        base_score += VPN_SINGLE_PROVIDER_SCORE
    for provider in vpn_providers:
        base_reasons.append(f"VPN/Proxy detectado por {provider}")

    related_users = {
        int(_value(candidate, "user_id"))
        for candidate in candidates
        if _value(candidate, "user_id") is not None
    }
    exact_ip_users = {
        int(_value(candidate, "user_id"))
        for candidate in candidates
        if _same_nonempty(current, candidate, "ip_hash")
    }
    network_users = {
        int(_value(candidate, "user_id"))
        for candidate in candidates
        if _same_nonempty(current, candidate, "ip_network_hash")
    }

    assessed_candidates = []
    for candidate in candidates:
        candidate_user_id = _value(candidate, "user_id")
        if candidate_user_id is None:
            continue

        score = base_score
        reasons = list(base_reasons)
        exact_ip = _same_nonempty(current, candidate, "ip_hash")
        same_network = _same_nonempty(current, candidate, "ip_network_hash")
        same_fingerprint = _same_nonempty(current, candidate, "fingerprint_hash")
        same_country = _same_nonempty(current, candidate, "country_code")

        if exact_ip:
            score += 45
            reasons.append("IP exacta coincidente")
        elif same_network:
            score += 20
            reasons.append("Rango de red coincidente")

        if same_country and (exact_ip or same_network):
            score += COUNTRY_NETWORK_MATCH_SCORE
            reasons.append("Pais coincidente junto a la conexion de red")

        if same_fingerprint:
            score += 45
            reasons.append("Huella tecnica limitada coincidente")
        else:
            context_matches = sum(
                _same_nonempty(current, candidate, key)
                for key in (
                    "timezone",
                    "browser_family",
                    "os_family",
                    "device_type",
                )
            )
            if context_matches == 4:
                score += 5
                reasons.append("Entorno tecnico general coincidente")

        created_at = _utc_datetime(_value(candidate, "created_at"))
        age = max(timedelta(0), current_time - created_at)
        if age <= RECENT_WINDOW:
            score += 15
            reasons.append("Coincidencia registrada en las ultimas 24 horas")
        elif age <= RELATED_WINDOW:
            score += 8
            reasons.append("Coincidencia registrada en los ultimos 7 dias")

        if exact_ip and age <= EXACT_IP_REVIEW_WINDOW:
            score = max(score, REVIEW_THRESHOLD)
            reasons.append(
                "IP exacta reutilizada por otra cuenta en los ultimos 30 dias"
            )

        if exact_ip and len(exact_ip_users) >= 2:
            score += 20
            reasons.append("Varias cuentas previas usaron la misma IP exacta")
        elif same_network and len(network_users) >= 3:
            score += 10
            reasons.append("Varias cuentas previas pertenecen al mismo rango de red")

        assessed_candidates.append(
            _CandidateAssessment(
                user_id=int(candidate_user_id),
                score=min(score, 100),
                reasons=tuple(reasons),
                created_at=created_at,
                preferred_main=(
                    _value(candidate, "decision") == "approved"
                    and bool(_value(candidate, "role_granted"))
                ),
            )
        )

    if not assessed_candidates:
        score = min(base_score, 100)
        if score >= HIGH_RISK_THRESHOLD:
            level = "high"
        elif score >= REVIEW_THRESHOLD:
            level = "medium"
        else:
            level = "low"
        return RiskAssessment(
            score=score,
            level=level,
            decision="review" if score >= REVIEW_THRESHOLD else "approved",
            possible_main_user_id=None,
            reasons=tuple(base_reasons),
            related_user_count=0,
        )

    strongest = max(
        assessed_candidates,
        key=lambda item: (
            item.score,
            item.preferred_main,
            -item.created_at.timestamp(),
        ),
    )
    if strongest.score >= HIGH_RISK_THRESHOLD:
        level = "high"
    elif strongest.score >= REVIEW_THRESHOLD:
        level = "medium"
    else:
        level = "low"

    requires_review = strongest.score >= REVIEW_THRESHOLD
    return RiskAssessment(
        score=strongest.score,
        level=level,
        decision="review" if requires_review else "approved",
        possible_main_user_id=strongest.user_id if requires_review else None,
        reasons=strongest.reasons,
        related_user_count=len(related_users),
    )
