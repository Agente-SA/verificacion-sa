import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass
from urllib.parse import quote


logger = logging.getLogger(__name__)
PROXYCHECK_PROVIDER = "proxycheck.io"
IPAPI_PROVIDER = "ipapi.is"
PROXYCHECK_URL = "https://proxycheck.io/v3/{ip_address}"
IPAPI_URL = "https://api.ipapi.is"
REQUEST_TIMEOUT_SECONDS = 4
MAX_RESPONSE_BYTES = 128 * 1024


class InvalidProviderResponse(ValueError):
    pass


def _same_ip(value: object, expected: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value) == ipaddress.ip_address(expected)
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class ProviderVerdict:
    provider: str
    available: bool
    detected: bool
    signals: tuple[str, ...] = ()

    @classmethod
    def unavailable(cls, provider: str) -> "ProviderVerdict":
        return cls(provider=provider, available=False, detected=False)


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
            }
            for verdict in self.verdicts
        }

    def discord_summary(self) -> str:
        lines = []
        for verdict in self.verdicts:
            if not verdict.available:
                status = "Sin respuesta"
            elif verdict.detected:
                status = "Detectado"
            else:
                status = "No detectado"
            lines.append(f"**{verdict.provider}:** {status}")

        detected_count = len(self.detected_providers)
        if detected_count == 2:
            lines.append("**Confianza:** Alta")
        elif detected_count == 1:
            lines.append("**Confianza:** Revisión manual")
        elif self.available_count == 0:
            lines.append("**Estado:** Servicios no disponibles")
        return "\n".join(lines)


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
    anonymous = detections.get("anonymous")
    if type(anonymous) is not bool:
        raise InvalidProviderResponse("Deteccion invalida de proxycheck.io.")

    signals = tuple(
        key
        for key in (
            "vpn",
            "proxy",
            "tor",
            "hosting",
            "datacenter",
            "anonymous",
        )
        if detections.get(key) is True
    )
    return ProviderVerdict(
        provider=PROXYCHECK_PROVIDER,
        available=True,
        detected=anonymous,
        signals=signals,
    )


def parse_ipapi_response(payload: object, ip_address: str) -> ProviderVerdict:
    if not isinstance(payload, dict) or not _same_ip(payload.get("ip"), ip_address):
        raise InvalidProviderResponse("Resultado invalido de ipapi.is.")

    checked_fields = ("is_vpn", "is_proxy", "is_tor")
    if any(type(payload.get(field)) is not bool for field in checked_fields):
        raise InvalidProviderResponse("Detecciones ausentes de ipapi.is.")

    signals = tuple(
        field.removeprefix("is_")
        for field in checked_fields
        if payload[field]
    )
    if payload.get("is_datacenter") is True:
        signals += ("datacenter",)
    if payload.get("is_hosting") is True:
        signals += ("hosting",)
    return ProviderVerdict(
        provider=IPAPI_PROVIDER,
        available=True,
        detected=any(
            signal in {"vpn", "proxy", "tor"} for signal in signals
        ),
        signals=signals,
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
