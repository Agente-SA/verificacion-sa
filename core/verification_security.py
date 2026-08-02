import base64
import hashlib
import hmac
import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from uuid import UUID, uuid4

from core.config import (
    FRONTEND_URL,
    IP_HASH_SECRET,
    TOKEN_EXPIRATION_MINUTES,
    TOKEN_SECRET,
)


TOKEN_VERSION = 1
TOKEN_SECRET_MIN_LENGTH = 32
PRIVACY_SECRET_MIN_LENGTH = 32
TOKEN_MAX_LENGTH = 2048
CLOCK_SKEW_SECONDS = 30


class VerificationSecurityError(Exception):
    pass


class VerificationConfigurationError(VerificationSecurityError):
    pass


class InvalidVerificationToken(VerificationSecurityError):
    pass


class ExpiredVerificationToken(InvalidVerificationToken):
    pass


@dataclass(frozen=True, slots=True)
class VerificationTokenPayload:
    token_id: UUID
    guild_id: int
    user_id: int
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedVerificationToken:
    value: str
    digest: str
    verification_url: str
    payload: VerificationTokenPayload


def _token_secret_bytes() -> bytes:
    if len(TOKEN_SECRET) < TOKEN_SECRET_MIN_LENGTH:
        raise VerificationConfigurationError(
            "TOKEN_SECRET debe contener al menos 32 caracteres."
        )
    return TOKEN_SECRET.encode("utf-8")


def _privacy_secret_bytes() -> bytes:
    if len(IP_HASH_SECRET) < PRIVACY_SECRET_MIN_LENGTH:
        raise VerificationConfigurationError(
            "IP_HASH_SECRET debe contener al menos 32 caracteres."
        )
    return IP_HASH_SECRET.encode("utf-8")


def _privacy_digest(namespace: str, value: str) -> str:
    message = f"{namespace}\0{value}".encode("utf-8")
    return hmac.new(
        _privacy_secret_bytes(),
        message,
        hashlib.sha256,
    ).hexdigest()


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _urlsafe_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise InvalidVerificationToken("Codificacion de token invalida.") from exc


def _utc_now(now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("La fecha debe incluir zona horaria.")
    return current.astimezone(timezone.utc).replace(microsecond=0)


def _positive_snowflake(value: object, field_name: str) -> int:
    if not isinstance(value, str) or not value.isdigit():
        raise InvalidVerificationToken(f"Campo {field_name} invalido.")
    parsed = int(value)
    if parsed <= 0:
        raise InvalidVerificationToken(f"Campo {field_name} invalido.")
    return parsed


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_ip_address(ip_address: str) -> str:
    try:
        canonical_ip = ipaddress.ip_address(ip_address).compressed
    except ValueError as exc:
        raise ValueError("Direccion IP invalida.") from exc
    return _privacy_digest("verification-ip:v1", canonical_ip)


def hash_ip_network(ip_address: str) -> str:
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValueError("Direccion IP invalida.") from exc

    prefix_length = 24 if parsed_ip.version == 4 else 64
    network = ipaddress.ip_network(
        f"{parsed_ip.compressed}/{prefix_length}",
        strict=False,
    )
    canonical_network = f"ipv{parsed_ip.version}:{network.with_prefixlen}"
    return _privacy_digest("verification-ip-network:v1", canonical_network)


def hash_limited_fingerprint(signals: Mapping[str, object]) -> str:
    canonical_signals = json.dumps(
        dict(signals),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _privacy_digest("verification-fingerprint:v1", canonical_signals)


def build_verification_url(token: str) -> str:
    if not FRONTEND_URL.startswith("https://"):
        raise VerificationConfigurationError(
            "FRONTEND_URL debe ser una direccion HTTPS valida."
        )
    return f"{FRONTEND_URL}/#token={quote(token, safe='')}"


def create_signed_verification_token(
    guild_id: int,
    user_id: int,
    *,
    now: datetime | None = None,
) -> IssuedVerificationToken:
    if guild_id <= 0 or user_id <= 0:
        raise ValueError("guild_id y user_id deben ser identificadores validos.")

    issued_at = _utc_now(now)
    expires_at = issued_at + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    token_id = uuid4()
    payload_data = {
        "v": TOKEN_VERSION,
        "jti": str(token_id),
        "gid": str(guild_id),
        "uid": str(user_id),
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    payload_json = json.dumps(
        payload_data,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    payload_segment = _urlsafe_encode(payload_json)
    signature = hmac.new(
        _token_secret_bytes(),
        payload_segment.encode("ascii"),
        hashlib.sha256,
    ).digest()
    token = f"{payload_segment}.{_urlsafe_encode(signature)}"
    payload = VerificationTokenPayload(
        token_id=token_id,
        guild_id=guild_id,
        user_id=user_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return IssuedVerificationToken(
        value=token,
        digest=token_digest(token),
        verification_url=build_verification_url(token),
        payload=payload,
    )


def validate_signed_verification_token(
    token: str,
    *,
    now: datetime | None = None,
    expected_guild_id: int | None = None,
    expected_user_id: int | None = None,
) -> VerificationTokenPayload:
    if (
        not isinstance(token, str)
        or len(token) > TOKEN_MAX_LENGTH
        or token.count(".") != 1
    ):
        raise InvalidVerificationToken("Formato de token invalido.")

    payload_segment, signature_segment = token.split(".", 1)
    try:
        payload_bytes = payload_segment.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidVerificationToken("Formato de token invalido.") from exc
    expected_signature = hmac.new(
        _token_secret_bytes(),
        payload_bytes,
        hashlib.sha256,
    ).digest()
    supplied_signature = _urlsafe_decode(signature_segment)
    if not hmac.compare_digest(expected_signature, supplied_signature):
        raise InvalidVerificationToken("Firma de token invalida.")

    try:
        payload_data = json.loads(_urlsafe_decode(payload_segment).decode("utf-8"))
        token_id = UUID(payload_data["jti"])
        version = payload_data["v"]
        issued_timestamp = payload_data["iat"]
        expires_timestamp = payload_data["exp"]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidVerificationToken("Contenido de token invalido.") from exc

    if version != TOKEN_VERSION:
        raise InvalidVerificationToken("Version de token no compatible.")
    if not isinstance(issued_timestamp, int) or isinstance(issued_timestamp, bool):
        raise InvalidVerificationToken("Fecha de emision invalida.")
    if not isinstance(expires_timestamp, int) or isinstance(expires_timestamp, bool):
        raise InvalidVerificationToken("Fecha de expiracion invalida.")

    guild_id = _positive_snowflake(payload_data.get("gid"), "gid")
    user_id = _positive_snowflake(payload_data.get("uid"), "uid")
    issued_at = datetime.fromtimestamp(issued_timestamp, timezone.utc)
    expires_at = datetime.fromtimestamp(expires_timestamp, timezone.utc)
    current = _utc_now(now)

    if expires_at <= issued_at:
        raise InvalidVerificationToken("Periodo de token invalido.")
    if issued_at > current + timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise InvalidVerificationToken("Fecha de emision futura.")
    if current >= expires_at:
        raise ExpiredVerificationToken("El token ha expirado.")
    if expected_guild_id is not None and guild_id != expected_guild_id:
        raise InvalidVerificationToken("Servidor de token invalido.")
    if expected_user_id is not None and user_id != expected_user_id:
        raise InvalidVerificationToken("Usuario de token invalido.")

    return VerificationTokenPayload(
        token_id=token_id,
        guild_id=guild_id,
        user_id=user_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
