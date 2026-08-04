import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote


logger = logging.getLogger(__name__)
PROXYCHECK_PROVIDER = "proxycheck.io"
IPAPI_PROVIDER = "ipapi.is"
PROXYCHECK_URL = "https://proxycheck.io/v3/{ip_address}"
IPAPI_URL = "https://api.ipapi.is"
REQUEST_TIMEOUT_SECONDS = 4
MAX_RESPONSE_BYTES = 128 * 1024
DISPLAY_SIGNALS = ("vpn",)
ANONYMITY_SIGNALS = frozenset(("vpn",))
SIGNAL_LABELS = {
    "vpn": "VPN",
    "proxy": "Proxy",
    "tor": "Tor",
    "hosting": "Hosting",
    "datacenter": "Datacenter",
}


class InvalidProviderResponse(ValueError):
    pass


def _same_ip(value: object, expected: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value) == ipaddress.ip_address(expected)
    except ValueError:
        return False


def _clean_text(value: object, limit: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split()).strip()
    return cleaned[:limit] or None


def _score(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 100:
        raise InvalidProviderResponse(f"{field_name} invalido.")
    return value


def _iso_timestamp(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(value / 1000, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return parsed.isoformat().replace("+00:00", "Z")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _discord_timestamp(value: str | None) -> str:
    if not value:
        return "No proporcionada"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value[:64]
    return f"<t:{int(parsed.timestamp())}:f> (<t:{int(parsed.timestamp())}:R>)"


def _nested_dict(payload: dict, key: str) -> dict:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True, slots=True)
class ProviderVerdict:
    provider: str
    available: bool
    detected: bool
    signals: tuple[str, ...] = ()
    signal_states: tuple[tuple[str, bool | None], ...] = ()
    risk_score: int | None = None
    confidence_score: int | None = None
    last_seen: str | None = None
    service: str | None = None
    network_type: str | None = None
    network_provider: str | None = None

    @classmethod
    def unavailable(cls, provider: str) -> "ProviderVerdict":
        return cls(provider=provider, available=False, detected=False)

    def signal_state(self, signal: str) -> bool | None:
        return dict(self.signal_states).get(signal)

    @property
    def anonymity_signals(self) -> tuple[str, ...]:
        return tuple(
            signal for signal in self.signals if signal in ANONYMITY_SIGNALS
        )


@dataclass(frozen=True, slots=True)
class VPNCheckResult:
    proxycheck: ProviderVerdict
    ipapi: ProviderVerdict

    @property
    def verdicts(self) -> tuple[ProviderVerdict, ProviderVerdict]:
        return self.proxycheck, self.ipapi

    @property
    def detected_providers(self) -> tuple[str, ...]:
        return tuple(
            verdict.provider
            for verdict in self.verdicts
            if verdict.available and verdict.detected
        )

    @property
    def available_count(self) -> int:
        return sum(verdict.available for verdict in self.verdicts)

    @property
    def unavailable_providers(self) -> tuple[str, ...]:
        return tuple(
            verdict.provider for verdict in self.verdicts if not verdict.available
        )

    @property
    def status(self) -> str:
        if self.available_count == 0:
            return "not_evaluated"
        if self.available_count == 1:
            return "partial"
        return "completed"

    @property
    def signal_types(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                signal
                for verdict in self.verdicts
                if verdict.available
                for signal in verdict.signals
            )
        )

    def provider_results(self) -> dict[str, dict]:
        return {
            verdict.provider: {
                "available": verdict.available,
                "detected": verdict.detected,
                "signals": list(verdict.signals),
                "checks": dict(verdict.signal_states),
                "risk_score": verdict.risk_score,
                "confidence_score": verdict.confidence_score,
                "last_seen": verdict.last_seen,
                "service": verdict.service,
                "network_type": verdict.network_type,
                "network_provider": verdict.network_provider,
            }
            for verdict in self.verdicts
        }

    def detected_signal_map(self) -> dict[str, tuple[str, ...]]:
        return {
            verdict.provider: verdict.anonymity_signals
            for verdict in self.verdicts
            if verdict.available and verdict.detected
        }

    def discord_summary(self) -> str:
        lines = []
        for verdict in self.verdicts:
            lines.append(f"**{verdict.provider}**")
            if not verdict.available:
                lines.append("Servicio sin respuesta")
                continue

            states = []
            for signal in DISPLAY_SIGNALS:
                state = verdict.signal_state(signal)
                state_label = "Sí" if state is True else "No" if state is False else "N/D"
                states.append(f"{SIGNAL_LABELS[signal]} `{state_label}`")
            lines.append(" · ".join(states))

            risk = (
                f"{verdict.risk_score}/100"
                if verdict.risk_score is not None
                else "N/D"
            )
            confidence = (
                f"{verdict.confidence_score}/100"
                if verdict.confidence_score is not None
                else "N/D"
            )
            lines.append(f"Riesgo `{risk}` · Confianza `{confidence}`")
            lines.append(f"Última detección: {_discord_timestamp(verdict.last_seen)}")

            context = []
            if verdict.service:
                context.append(f"Servicio: `{verdict.service}`")
            if verdict.network_type:
                context.append(f"Red: `{verdict.network_type}`")
            if verdict.network_provider:
                context.append(f"Proveedor: `{verdict.network_provider}`")
            if context:
                lines.append(" · ".join(context))

        detected_count = len(self.detected_providers)
        if detected_count == 2:
            lines.append("**Coincidencia de proveedores:** Sí")
        elif detected_count == 1:
            lines.append("**Señal aislada:** Revisión manual")
        elif self.available_count == 0:
            lines.append("**Estado:** Servicios no disponibles")
        else:
            lines.append("**Coincidencia de proveedores:** No detectada")
        return "\n".join(lines)[:1024]


def parse_proxycheck_response(payload: object, ip_address: str) -> ProviderVerdict:
    if not isinstance(payload, dict) or payload.get("status") not in {
        "ok",
        "warning",
    }:
        raise InvalidProviderResponse("Estado invalido de proxycheck.io.")

    result = payload.get(ip_address)
    if not isinstance(result, dict):
        result = next(
            (
                value
                for key, value in payload.items()
                if _same_ip(key, ip_address) and isinstance(value, dict)
            ),
            None,
        )
    if not isinstance(result, dict) and _same_ip(payload.get("ip"), ip_address):
        result = payload
    if not isinstance(result, dict):
        raise InvalidProviderResponse("Resultado ausente de proxycheck.io.")

    detections = result.get("detections")
    if not isinstance(detections, dict):
        raise InvalidProviderResponse("Detecciones ausentes de proxycheck.io.")
    checked_fields = ("vpn",)
    if any(type(detections.get(field)) is not bool for field in checked_fields):
        raise InvalidProviderResponse("Detecciones invalidas de proxycheck.io.")

    signal_states = tuple(
        (signal, detections[signal]) for signal in checked_fields
    )
    signals = tuple(signal for signal, state in signal_states if state is True)
    network = _nested_dict(result, "network")
    operator = _nested_dict(result, "operator")
    return ProviderVerdict(
        provider=PROXYCHECK_PROVIDER,
        available=True,
        detected=any(signal in ANONYMITY_SIGNALS for signal in signals),
        signals=signals,
        signal_states=signal_states,
        risk_score=_score(result.get("risk"), "Riesgo de proxycheck.io"),
        confidence_score=_score(
            detections.get("confidence"),
            "Confianza de proxycheck.io",
        ),
        last_seen=_iso_timestamp(detections.get("last_seen")),
        service=_clean_text(operator.get("name")),
        network_type=_clean_text(network.get("type")),
        network_provider=(
            _clean_text(network.get("provider"))
            or _clean_text(network.get("organisation"))
        ),
    )


def parse_ipapi_response(payload: object, ip_address: str) -> ProviderVerdict:
    if not isinstance(payload, dict) or not _same_ip(payload.get("ip"), ip_address):
        raise InvalidProviderResponse("Resultado invalido de ipapi.is.")

    checked_fields = ("is_vpn",)
    if any(type(payload.get(field)) is not bool for field in checked_fields):
        raise InvalidProviderResponse("Detecciones ausentes de ipapi.is.")

    company = _nested_dict(payload, "company")
    asn = _nested_dict(payload, "asn")
    vpn = _nested_dict(payload, "vpn")
    signal_states = (("vpn", payload["is_vpn"]),)
    signals = tuple(signal for signal, state in signal_states if state is True)
    return ProviderVerdict(
        provider=IPAPI_PROVIDER,
        available=True,
        detected=any(signal in ANONYMITY_SIGNALS for signal in signals),
        signals=signals,
        signal_states=signal_states,
        last_seen=(
            _iso_timestamp(vpn.get("last_seen_str"))
            or _iso_timestamp(vpn.get("last_seen"))
        ),
        service=_clean_text(vpn.get("service")),
        network_type=(
            _clean_text(company.get("type"))
            or _clean_text(asn.get("type"))
        ),
        network_provider=(
            _clean_text(company.get("name"))
            or _clean_text(asn.get("org"))
        ),
    )


async def _read_json_response(response) -> object:
    if response.status != 200:
        raise InvalidProviderResponse(
            f"El proveedor respondio con HTTP {response.status}."
        )
    body = await response.content.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise InvalidProviderResponse("La respuesta del proveedor es demasiado grande.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidProviderResponse("El proveedor no devolvio JSON valido.") from exc


async def _query_proxycheck(session, ip_address: str) -> ProviderVerdict:
    encoded_ip = quote(ip_address, safe="")
    # API v3 returns all detection types by default. Omitting ``days`` keeps
    # proxycheck.io's conservative per-source expiration for stale mobile/CGNAT data.
    async with session.get(
        PROXYCHECK_URL.format(ip_address=encoded_ip),
        params={"tag": "0", "p": "0"},
    ) as response:
        payload = await _read_json_response(response)
    return parse_proxycheck_response(payload, ip_address)


async def _query_ipapi(session, ip_address: str) -> ProviderVerdict:
    async with session.get(
        IPAPI_URL,
        params={"q": ip_address},
    ) as response:
        payload = await _read_json_response(response)
    return parse_ipapi_response(payload, ip_address)


async def check_vpn_services(ip_address: str) -> VPNCheckResult:
    from aiohttp import ClientSession, ClientTimeout

    timeout = ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
    headers = {"User-Agent": "Verification-SA/1.0"}
    async with ClientSession(timeout=timeout, headers=headers) as session:
        responses = await asyncio.gather(
            _query_proxycheck(session, ip_address),
            _query_ipapi(session, ip_address),
            return_exceptions=True,
        )

    verdicts = []
    for provider, response in zip(
        (PROXYCHECK_PROVIDER, IPAPI_PROVIDER),
        responses,
    ):
        if isinstance(response, asyncio.CancelledError):
            raise response
        if isinstance(response, Exception):
            logger.warning(
                "Consulta VPN no disponible | proveedor=%s | error=%s",
                provider,
                type(response).__name__,
            )
            verdicts.append(ProviderVerdict.unavailable(provider))
        else:
            verdicts.append(response)

    return VPNCheckResult(proxycheck=verdicts[0], ipapi=verdicts[1])
