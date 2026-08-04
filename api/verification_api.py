import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

import discord
from aiohttp import ClientSession, ClientTimeout, web

from core import database
from core.config import (
    API_HOST,
    API_PORT,
    BASE_DIR,
    DATA_RETENTION_DAYS,
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DISCORD_OAUTH_REDIRECT_URI,
    FRONTEND_URL,
    GUILD_ID,
    IP_HASH_SECRET_VERSION,
    LEGACY_VERIFIED_ROLE_ID,
    OAUTH_STATE_EXPIRATION_MINUTES,
    REGIONAL_REVIEW_ROLE_IDS,
    STAFF_CHANNEL_ID,
    STAFF_ROLE_IDS,
    TRUSTED_PROXY_NETWORKS,
    VERIFIED_ROLE_ID,
    VERIFICATION_PUBLIC_URL,
)
from core.verification_risk import RiskAssessment, assess_verification_risk
from core.verification_security import (
    ExpiredVerificationToken,
    InvalidVerificationToken,
    VerificationConfigurationError,
    hash_ip_address,
    hash_ip_address_candidates,
    hash_ip_network,
    hash_ip_network_candidates,
    hash_limited_fingerprint,
    hash_limited_fingerprint_candidates,
    token_digest,
    validate_signed_verification_token,
)
from core.vpn_detection import VPNCheckResult, check_vpn_services


logger = logging.getLogger(__name__)
API_NAME = "verification-sa-api"
API_VERSION = 6
MAX_REQUEST_SIZE = 64 * 1024
RATE_WINDOW = timedelta(minutes=15)
USER_SUBMISSION_LIMIT = 5
IP_SUBMISSION_LIMIT = 60
SUBMISSION_KEYS = frozenset({"token", "consent", "signals"})
SIGNAL_KEYS = frozenset({
    "signalVersion",
    "language",
    "timezone",
    "userAgent",
    "platform",
    "mobile",
    "deviceClass",
    "touchSupport",
})
DEVICE_CLASSES = frozenset({"phone", "tablet", "desktop"})
COUNTRY_CODE_PATTERN = re.compile(r"^[A-Z0-9]{2}$")
OAUTH_STATE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,128}$")
DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_CURRENT_USER_URL = "https://discord.com/api/v10/users/@me"
OAUTH_HTTP_TIMEOUT = ClientTimeout(total=15)
SERVICE_READY_GRACE_SECONDS = 12


class InvalidSubmission(ValueError):
    pass


class RoleGrantError(RuntimeError):
    def __init__(self, message: str, diagnostics: str | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


def _url_origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("La URL publica debe ser una direccion HTTPS valida.")
    return f"{parsed.scheme}://{parsed.netloc}"


def _frontend_origins() -> frozenset[str]:
    return frozenset(
        _url_origin(url)
        for url in (VERIFICATION_PUBLIC_URL, FRONTEND_URL)
        if url
    )


def _apply_security_headers(
    response: web.StreamResponse,
    *,
    web_content: bool = False,
    cache_assets: bool = False,
) -> None:
    response.headers.setdefault(
        "Cache-Control",
        "public, max-age=3600" if cache_assets else "no-store",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'"
            if web_content
            else "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        ),
    )


def _error_response(code: str, status: int) -> web.Response:
    return web.json_response(
        {"status": "error", "code": code},
        status=status,
    )


async def _wait_for_guardian_ready(bot) -> bool:
    if database.bot_pool is None:
        return False
    if bot.is_ready():
        return True

    try:
        await asyncio.wait_for(
            bot.wait_until_ready(),
            timeout=SERVICE_READY_GRACE_SECONDS,
        )
    except (TimeoutError, RuntimeError):
        logger.warning(
            "Guardian no recuperó la conexión con Discord dentro de %s segundos.",
            SERVICE_READY_GRACE_SECONDS,
        )
        return False
    return database.bot_pool is not None and bot.is_ready()


def _oauth_state_digest(state: str) -> str:
    return hashlib.sha256(state.encode("ascii")).hexdigest()


def _discord_authorization_url(state: str) -> str:
    query = urlencode(
        {
            "client_id": str(DISCORD_CLIENT_ID),
            "response_type": "code",
            "redirect_uri": DISCORD_OAUTH_REDIRECT_URI,
            "scope": "identify",
            "state": state,
        }
    )
    return f"{DISCORD_AUTHORIZE_URL}?{query}"


def _oauth_result_url(result: str) -> str:
    safe_result = result if result in {
        "received",
        "rejected",
        "retry",
    } else "retry"
    return f"{VERIFICATION_PUBLIC_URL}/#result={safe_result}"


def _oauth_redirect(result: str) -> web.HTTPFound:
    return web.HTTPFound(location=_oauth_result_url(result))


async def _exchange_oauth_identity(code: str) -> int:
    token_payload = {
        "client_id": str(DISCORD_CLIENT_ID),
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_OAUTH_REDIRECT_URI,
    }
    async with ClientSession(timeout=OAUTH_HTTP_TIMEOUT) as session:
        async with session.post(
            DISCORD_TOKEN_URL,
            data=token_payload,
            headers={"Accept": "application/json"},
        ) as response:
            if response.status != 200:
                body = await response.text()
                raise RuntimeError(
                    f"Discord rechazo el codigo OAuth ({response.status}): "
                    f"{body[:200]}"
                )
            token_data = await response.json()

        access_token = token_data.get("access_token")
        token_type = token_data.get("token_type", "Bearer")
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("Discord no devolvio un access token OAuth.")

        async with session.get(
            DISCORD_CURRENT_USER_URL,
            headers={
                "Authorization": f"{token_type} {access_token}",
                "Accept": "application/json",
            },
        ) as response:
            if response.status != 200:
                raise RuntimeError(
                    "Discord no permitio consultar la identidad OAuth "
                    f"({response.status})."
                )
            identity = await response.json()

    user_id = identity.get("id")
    if not isinstance(user_id, str) or not user_id.isdigit():
        raise RuntimeError("Discord devolvio una identidad OAuth invalida.")
    return int(user_id)


def _safe_string(signals: dict, key: str, max_length: int) -> str:
    value = signals.get(key)
    if not isinstance(value, str):
        raise InvalidSubmission(f"Campo {key} invalido.")
    value = value.strip()
    if not value or len(value) > max_length:
        raise InvalidSubmission(f"Campo {key} invalido.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InvalidSubmission(f"Campo {key} invalido.")
    return value


def _parse_submission(payload: object) -> tuple[str, dict]:
    if not isinstance(payload, dict) or frozenset(payload) != SUBMISSION_KEYS:
        raise InvalidSubmission("Estructura de solicitud invalida.")
    if payload.get("consent") is not True:
        raise InvalidSubmission("Consentimiento requerido.")

    token = payload.get("token")
    if not isinstance(token, str) or not token:
        raise InvalidSubmission("Token invalido.")

    signals = payload.get("signals")
    if not isinstance(signals, dict) or frozenset(signals) != SIGNAL_KEYS:
        raise InvalidSubmission("Senales invalidas.")
    if type(signals.get("signalVersion")) is not int:
        raise InvalidSubmission("Version de senales invalida.")
    if signals["signalVersion"] != 1:
        raise InvalidSubmission("Version de senales no compatible.")
    if type(signals.get("mobile")) is not bool:
        raise InvalidSubmission("Campo mobile invalido.")
    if type(signals.get("touchSupport")) is not bool:
        raise InvalidSubmission("Campo touchSupport invalido.")

    device_class = signals.get("deviceClass")
    if device_class not in DEVICE_CLASSES:
        raise InvalidSubmission("Clase de dispositivo invalida.")

    sanitized = {
        "signal_version": signals["signalVersion"],
        "language": _safe_string(signals, "language", 32),
        "timezone": _safe_string(signals, "timezone", 64),
        "user_agent": _safe_string(signals, "userAgent", 512),
        "platform": _safe_string(signals, "platform", 64),
        "mobile": signals["mobile"],
        "device_class": device_class,
        "touch_support": signals["touchSupport"],
    }
    return token, sanitized


def _load_oauth_signals(value: object) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise InvalidSubmission("Senales OAuth invalidas.") from exc
    if not isinstance(value, dict):
        raise InvalidSubmission("Senales OAuth invalidas.")
    return value


def _member_regional_review_role_ids(member: discord.Member) -> tuple[int, ...]:
    return tuple(
        sorted(
            role.id
            for role in member.roles
            if role.id in REGIONAL_REVIEW_ROLE_IDS
        )
    )


def _force_regional_manual_review(
    assessment: RiskAssessment,
    role_ids: tuple[int, ...],
) -> RiskAssessment:
    if not role_ids:
        return assessment
    reason = "Rol regional sujeto a revisión manual obligatoria"
    return RiskAssessment(
        score=assessment.score,
        level=assessment.level,
        decision="review",
        possible_main_user_id=assessment.possible_main_user_id,
        reasons=tuple(dict.fromkeys((*assessment.reasons, reason))),
        related_user_count=assessment.related_user_count,
    )


def _browser_family(user_agent: str) -> str:
    lowered = user_agent.lower()
    if "edg/" in lowered or "edgios/" in lowered or "edga/" in lowered:
        return "Edge"
    if "opr/" in lowered or "opera" in lowered:
        return "Opera"
    if "samsungbrowser/" in lowered:
        return "Samsung Internet"
    if "crios/" in lowered or "chrome/" in lowered:
        return "Chrome"
    if "fxios/" in lowered or "firefox/" in lowered:
        return "Firefox"
    if "safari/" in lowered:
        return "Safari"
    return "Other"


def _os_family(user_agent: str) -> str:
    lowered = user_agent.lower()
    if "iphone" in lowered or "ipad" in lowered or "ipod" in lowered:
        return "iOS"
    if "android" in lowered:
        return "Android"
    if "windows" in lowered:
        return "Windows"
    if "cros" in lowered:
        return "ChromeOS"
    if "mac os" in lowered or "macintosh" in lowered:
        return "macOS"
    if "linux" in lowered:
        return "Linux"
    return "Other"


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not value:
        raise InvalidSubmission("Direccion de red no disponible.")
    try:
        parsed_ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise InvalidSubmission("Direccion de red invalida.") from exc
    if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped:
        parsed_ip = parsed_ip.ipv4_mapped
    return parsed_ip


def _request_uses_trusted_proxy(request: web.Request) -> bool:
    remote_ip = _parse_ip(request.remote)
    return any(remote_ip in network for network in TRUSTED_PROXY_NETWORKS)


def _client_ip(request: web.Request) -> str:
    forwarded_ip = request.headers.get("CF-Connecting-IP")
    if forwarded_ip:
        if not _request_uses_trusted_proxy(request):
            logger.warning(
                "Encabezado CF-Connecting-IP rechazado desde un proxy no confiable."
            )
            raise InvalidSubmission("Proxy de solicitud no confiable.")
        return _parse_ip(forwarded_ip).compressed
    return _parse_ip(request.remote).compressed


def _country_code(request: web.Request) -> str | None:
    if not request.headers.get("CF-Connecting-IP"):
        return None
    if not _request_uses_trusted_proxy(request):
        return None
    country = request.headers.get("CF-IPCountry", "").strip().upper()
    return country if COUNTRY_CODE_PATTERN.fullmatch(country) else None


async def _get_member(bot, guild_id: int, user_id: int):
    guild = bot.get_guild(guild_id)
    if guild is None:
        return None
    member = guild.get_member(user_id)
    if member is not None:
        return member
    try:
        return await guild.fetch_member(user_id)
    except discord.NotFound:
        return None


def _effective_permissions(roles: list[discord.Role]) -> discord.Permissions:
    permissions = discord.Permissions.none()
    for role in roles:
        permissions.value |= role.permissions.value
    if permissions.administrator:
        return discord.Permissions.all()
    return permissions


def _role_grant_diagnostics(
    guild: discord.Guild,
    member: discord.Member,
    bot_member: discord.Member,
    role: discord.Role,
    bot_roles: list[discord.Role],
) -> str:
    bot_top_role = max(bot_roles) if bot_roles else guild.default_role
    permissions = _effective_permissions(bot_roles)
    target_top_role = member.top_role
    return (
        f"Servidor: `{guild.id}`\n"
        f"Bot: {bot_member.mention} (`{bot_member.id}`)\n"
        f"Rol superior del bot: {bot_top_role.mention} "
        f"(`{bot_top_role.id}`, posicion `{bot_top_role.position}`)\n"
        f"Rol verificado: {role.mention} "
        f"(`{role.id}`, posicion `{role.position}`, managed=`{role.managed}`)\n"
        f"Manage Roles: `{permissions.manage_roles}` | "
        f"Administrator: `{permissions.administrator}`\n"
        f"Usuario objetivo: {member.mention} (`{member.id}`) | "
        f"rol superior `{target_top_role.name}` (`{target_top_role.id}`, "
        f"posicion `{target_top_role.position}`) | "
        f"owner=`{guild.owner_id == member.id}` | pending=`{member.pending}`"
    )


async def _grant_verified_role(
    member: discord.Member,
    *,
    reason: str = "Verificacion SA aprobada automaticamente",
) -> bool:
    guild = member.guild
    cached_bot_member = guild.me
    if cached_bot_member is None:
        raise RoleGrantError("No se pudo localizar al bot dentro del servidor.")

    try:
        roles = await guild.fetch_roles()
        fresh_member = await guild.fetch_member(member.id)
        bot_member = await guild.fetch_member(cached_bot_member.id)
    except discord.HTTPException as exc:
        raise RoleGrantError(
            f"No se pudo actualizar el estado del servidor antes de asignar el rol: {exc}"
        ) from exc

    role = discord.utils.get(roles, id=VERIFIED_ROLE_ID)
    if role is None or role.managed or role.id == guild.id:
        raise RoleGrantError("El rol verificado no existe o no es asignable.")

    bot_role_ids = {cached_role.id for cached_role in bot_member.roles}
    bot_roles = [fresh_role for fresh_role in roles if fresh_role.id in bot_role_ids]
    diagnostics = _role_grant_diagnostics(
        guild,
        fresh_member,
        bot_member,
        role,
        bot_roles,
    )
    permissions = _effective_permissions(bot_roles)
    if not (permissions.administrator or permissions.manage_roles):
        raise RoleGrantError(
            "El bot no posee el permiso Manage Roles.",
            diagnostics,
        )

    bot_top_role = max(bot_roles) if bot_roles else guild.default_role
    if bot_top_role <= role:
        raise RoleGrantError(
            "El rol del bot no esta por encima del rol verificado.",
            diagnostics,
        )
    role_added = fresh_member.get_role(role.id) is None
    if role_added:
        try:
            await fresh_member.add_roles(
                role,
                reason=reason,
            )
            fresh_member = await guild.fetch_member(member.id)
        except discord.HTTPException as exc:
            raise RoleGrantError(str(exc), diagnostics) from exc
        if fresh_member.get_role(role.id) is None:
            raise RoleGrantError(
                "Discord no confirmó la asignación del rol verificado.",
                diagnostics,
            )

    try:
        await _remove_legacy_verified_role(
            fresh_member,
            roles,
            reason="Retiro del rol de verificación antiguo",
        )
    except discord.HTTPException as exc:
        raise RoleGrantError(
            (
                "El rol verificado fue confirmado, pero no se pudo retirar "
                f"el rol antiguo: {exc}"
            ),
            diagnostics,
        ) from exc
    return role_added


async def _remove_legacy_verified_role(
    member: discord.Member,
    roles: list[discord.Role],
    *,
    reason: str,
) -> bool:
    legacy_role = discord.utils.get(roles, id=LEGACY_VERIFIED_ROLE_ID)
    if legacy_role is None:
        return False
    if member.get_role(legacy_role.id) is None:
        return False

    await member.remove_roles(legacy_role, reason=reason)
    return True


async def _remove_verified_role(member: discord.Member) -> None:
    guild = member.guild
    roles = await guild.fetch_roles()
    role = discord.utils.get(roles, id=VERIFIED_ROLE_ID)
    if role is None:
        return

    try:
        fresh_member = await guild.fetch_member(member.id)
    except discord.NotFound:
        return
    await fresh_member.remove_roles(
        role,
        reason="Reversion por error al guardar la verificacion SA",
    )


async def _staff_channel(bot):
    channel = bot.get_channel(STAFF_CHANNEL_ID)
    if channel is not None:
        return channel
    try:
        return await bot.fetch_channel(STAFF_CHANNEL_ID)
    except discord.HTTPException:
        return None


async def _send_private_result(
    bot,
    token_id,
    user_id: int,
    outcome: str,
) -> bool:
    manager = getattr(bot, "verification_manager", None)
    if manager is None:
        logger.warning(
            "No hay gestor disponible para notificar la verificacion de %s.",
            user_id,
        )
        return False

    try:
        delivered = await manager.send_verification_result(
            token_id,
            user_id,
            outcome,
        )
    except Exception:
        logger.exception(
            "No se pudo enviar el resultado privado de verificacion a %s.",
            user_id,
        )
        return False

    if not delivered:
        logger.info(
            "La interaccion privada de verificacion ya no estaba activa para %s.",
            user_id,
        )
    return delivered


async def _send_identity_mismatch_alert(
    bot,
    expected_user_id: int,
    oauth_user_id: int,
) -> None:
    channel = await _staff_channel(bot)
    if channel is None:
        return
    embed = discord.Embed(
        title="Identidad OAuth2 no coincidente",
        description=(
            "El enlace personal fue abierto con una cuenta de Discord "
            "diferente. La solicitud fue invalidada."
        ),
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="Usuario esperado",
        value=f"<@{expected_user_id}> (`{expected_user_id}`)",
        inline=True,
    )
    embed.add_field(
        name="Identidad autenticada",
        value=f"<@{oauth_user_id}> (`{oauth_user_id}`)",
        inline=True,
    )
    await channel.send(
        embed=embed,
        allowed_mentions=discord.AllowedMentions.none(),
    )


async def _send_review_alert(
    bot,
    member: discord.Member,
    assessment: RiskAssessment,
    attempt_id: int,
    country_code: str | None,
    vpn_check: VPNCheckResult,
    regional_role_ids: tuple[int, ...] = (),
) -> None:
    channel = await _staff_channel(bot)
    if channel is None:
        raise RuntimeError("No se pudo localizar el canal de alertas del staff.")

    manager = getattr(bot, "verification_manager", None)
    if manager is None:
        raise RuntimeError("No se pudo localizar el gestor de revisiones.")

    staff_mentions = " ".join(
        f"<@&{role_id}>" for role_id in sorted(STAFF_ROLE_IDS)
    )

    main_user_id = assessment.possible_main_user_id
    if main_user_id is None:
        content = f"{staff_mentions} Revisión manual para {member.mention} ({member.id})"
        main_account_value = "No detectada"
    else:
        content = (
            f"{staff_mentions} Posible ALT-ACCOUNT {member.mention} ({member.id}) - "
            f"Main Acc: <@{main_user_id}> ({main_user_id})"
        )
        main_account_value = f"<@{main_user_id}>\n`{main_user_id}`"
    reasons = "\n".join(f"- {reason}" for reason in assessment.reasons)
    embed = discord.Embed(
        title="Revision de Verificacion SA",
        color=(
            discord.Color.red()
            if assessment.level == "high"
            else discord.Color.orange()
        ),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="Usuario detectado",
        value=f"{member.mention}\n`{member.id}`",
        inline=True,
    )
    embed.add_field(
        name="Posible cuenta principal",
        value=main_account_value,
        inline=True,
    )
    embed.add_field(
        name="Riesgo",
        value=f"{assessment.level.upper()} ({assessment.score}/100)",
        inline=True,
    )
    embed.add_field(
        name="Coincidencias",
        value=reasons[:1024] or "Sin motivos detallados",
        inline=False,
    )
    embed.add_field(
        name="Análisis de red por proveedor",
        value=vpn_check.discord_summary(),
        inline=False,
    )
    embed.add_field(
        name="Verificacion interna",
        value=f"`{attempt_id}`",
        inline=True,
    )
    country_value = "No disponible"
    if country_code:
        country_code = country_code.upper()
        if len(country_code) == 2 and country_code.isalpha():
            flag = "".join(
                chr(127397 + ord(character)) for character in country_code
            )
            country_value = f"{flag} `{country_code}`"
        else:
            country_value = f"`{country_code}`"
    embed.add_field(
        name="Pais detectado",
        value=country_value,
        inline=True,
    )
    if regional_role_ids:
        embed.add_field(
            name="Roles regionales detectados",
            value="\n".join(
                f"<@&{role_id}> (`{role_id}`)"
                for role_id in regional_role_ids
            ),
            inline=False,
        )
    embed.set_footer(
        text=(
            "La coincidencia es una senal preventiva y requiere revision humana."
        )
    )
    message = await channel.send(
        content,
        embed=embed,
        view=manager.manual_review_view(attempt_id),
        allowed_mentions=discord.AllowedMentions(
            everyone=False,
            users=True,
            roles=[discord.Object(id=role_id) for role_id in STAFF_ROLE_IDS],
            replied_user=False,
        ),
    )
    saved = await database.save_manual_review_message(
        attempt_id,
        channel.id,
        message.id,
    )
    if saved is None:
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        raise RuntimeError("La revisión dejó de estar pendiente antes de publicarse.")


async def _send_rejection_alert(
    bot,
    member: discord.Member,
    assessment: RiskAssessment,
    attempt_id: int,
    country_code: str | None,
    vpn_check: VPNCheckResult,
) -> None:
    channel = await _staff_channel(bot)
    if channel is None:
        raise RuntimeError("No se pudo localizar el canal de alertas del staff.")
    main_account = (
        f"<@{assessment.possible_main_user_id}> (`{assessment.possible_main_user_id}`)"
        if assessment.possible_main_user_id
        else "No detectada"
    )
    reasons = "\n".join(f"- {reason}" for reason in assessment.reasons)
    embed = discord.Embed(
        title="Verificación SA rechazada",
        description=f"Solicitud de {member.mention} (`{member.id}`)",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="Riesgo",
        value=f"{assessment.level.upper()} ({assessment.score}/100)",
        inline=True,
    )
    embed.add_field(
        name="Posible cuenta principal",
        value=main_account,
        inline=True,
    )
    embed.add_field(
        name="Verificación interna",
        value=f"`{attempt_id}`",
        inline=True,
    )
    embed.add_field(
        name="Coincidencias",
        value=reasons[:1024] or "Sin motivos detallados",
        inline=False,
    )
    embed.add_field(
        name="Análisis de red por proveedor",
        value=vpn_check.discord_summary(),
        inline=False,
    )
    embed.add_field(
        name="País aproximado",
        value=country_code or "No disponible",
        inline=True,
    )
    await channel.send(
        embed=embed,
        allowed_mentions=discord.AllowedMentions.none(),
    )


async def _send_vpn_unavailable_alert(
    bot,
    member: discord.Member,
    attempt_id: int,
    vpn_check: VPNCheckResult,
) -> None:
    channel = await _staff_channel(bot)
    if channel is None:
        raise RuntimeError("No se pudo localizar el canal de alertas del staff.")
    embed = discord.Embed(
        title="Verificación SA no evaluada",
        description=(
            f"La solicitud de {member.mention} (`{member.id}`) debe repetirse "
            "porque ambos proveedores VPN estuvieron indisponibles."
        ),
        color=discord.Color.gold(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="Proveedores",
        value=vpn_check.discord_summary(),
        inline=False,
    )
    embed.set_footer(text=f"Verificación interna: {attempt_id}")
    await channel.send(embed=embed)


async def _send_role_error_alert(
    bot,
    member: discord.Member,
    attempt_id: int,
    reason: str,
    diagnostics: str | None = None,
) -> None:
    channel = await _staff_channel(bot)
    if channel is None:
        return
    embed = discord.Embed(
        title="Error al otorgar rol de Verificacion SA",
        description=(
            f"Usuario: {member.mention} (`{member.id}`)\n"
            f"Verificacion: `{attempt_id}`\n"
            f"Motivo: {reason[:500]}"
        ),
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    if diagnostics:
        embed.add_field(
            name="Diagnostico de permisos",
            value=diagnostics[:1024],
            inline=False,
        )
    await channel.send(embed=embed)


async def _send_success_alert(bot, member: discord.Member) -> None:
    channel = await _staff_channel(bot)
    if channel is None:
        raise RuntimeError("No se pudo localizar el canal de alertas del staff.")

    role = member.guild.get_role(VERIFIED_ROLE_ID)
    role_mention = role.mention if role is not None else f"<@&{VERIFIED_ROLE_ID}>"
    await channel.send(
        (
            f"😃 {member.mention} realizó la verificación exitosamente y "
            f"se ha otorgado el rol {role_mention}."
        ),
        allowed_mentions=discord.AllowedMentions(
            everyone=False,
            users=True,
            roles=False,
            replied_user=False,
        ),
    )


def create_verification_app(bot) -> web.Application:
    allowed_origins = _frontend_origins()
    configured_guild_id = GUILD_ID
    web_documents = {
        "/": BASE_DIR / "index.html",
        "/index.html": BASE_DIR / "index.html",
        "/privacy.html": BASE_DIR / "privacy.html",
        "/terms.html": BASE_DIR / "terms.html",
    }

    @web.middleware
    async def request_security(
        request: web.Request,
        handler,
    ) -> web.StreamResponse:
        origin = request.headers.get("Origin")
        is_api_request = request.path.startswith("/api/")
        if is_api_request and origin and origin not in allowed_origins:
            response = _error_response("origin_not_allowed", 403)
            _apply_security_headers(response)
            response.headers["Vary"] = "Origin"
            return response

        try:
            response = await handler(request)
        except web.HTTPException as http_error:
            response = http_error

        is_web_content = (
            request.path in web_documents
            or request.path.startswith("/assets/")
        )
        _apply_security_headers(
            response,
            web_content=is_web_content,
            cache_assets=request.path.startswith("/assets/"),
        )
        if is_api_request:
            response.headers["Vary"] = "Origin"
        if is_api_request and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Max-Age"] = "600"
        return response

    async def web_document(request: web.Request) -> web.FileResponse:
        return web.FileResponse(web_documents[request.path])

    async def health(_request: web.Request) -> web.Response:
        discord_ready = bot.is_ready()
        database_ready = database.bot_pool is not None
        return web.json_response(
            {
                "status": (
                    "ok" if discord_ready and database_ready else "degraded"
                ),
                "service": API_NAME,
                "version": API_VERSION,
                "discord_ready": discord_ready,
                "database_ready": database_ready,
            }
        )

    async def _evaluate_authenticated_submission(
        request: web.Request,
        oauth_session,
    ) -> web.Response:
        if not await _wait_for_guardian_ready(bot):
            return _error_response("temporarily_unavailable", 503)

        try:
            signals = _load_oauth_signals(oauth_session["signals"])
        except InvalidSubmission:
            return _error_response("invalid_request", 400)
        token_id = oauth_session["token_id"]
        guild_id = int(oauth_session["guild_id"])
        user_id = int(oauth_session["expected_user_id"])
        supplied_digest = str(oauth_session["token_digest"])

        try:
            member = await _get_member(
                bot,
                guild_id,
                user_id,
            )
        except discord.HTTPException:
            logger.exception(
                "No se pudo comprobar el miembro de verificacion %s.",
                user_id,
            )
            return _error_response("temporarily_unavailable", 503)

        if member is None or member.bot:
            return _error_response("membership_required", 403)

        if member.get_role(VERIFIED_ROLE_ID) is not None:
            await database.revoke_verification_token(
                token_id,
                supplied_digest,
            )
            await _send_private_result(
                bot,
                token_id,
                user_id,
                "approved",
            )
            return web.json_response({"status": "completed"})

        regional_review_role_ids = _member_regional_review_role_ids(member)

        try:
            client_ip = _client_ip(request)
            ip_hash = hash_ip_address(client_ip)
            ip_hashes = hash_ip_address_candidates(client_ip)
            ip_network_hash = hash_ip_network(client_ip)
            ip_network_hashes = hash_ip_network_candidates(client_ip)
            browser_family = _browser_family(signals["user_agent"])
            os_family = _os_family(signals["user_agent"])
            fingerprint_basis = {
                "version": signals["signal_version"],
                "language": signals["language"].lower(),
                "timezone": signals["timezone"],
                "browser_family": browser_family,
                "os_family": os_family,
                "platform": signals["platform"],
                "mobile": signals["mobile"],
                "device_class": signals["device_class"],
                "touch_support": signals["touch_support"],
            }
            fingerprint_hash = hash_limited_fingerprint(fingerprint_basis)
            fingerprint_hashes = hash_limited_fingerprint_candidates(
                fingerprint_basis
            )
            country_code = _country_code(request)
        except (InvalidSubmission, VerificationConfigurationError):
            return _error_response("temporarily_unavailable", 503)

        current_time = datetime.now(timezone.utc)
        vpn_check = await check_vpn_services(client_ip)
        attempt = None
        assessment = None
        try:
            async with database.verification_signal_transaction(
                ip_hash,
                ip_network_hash,
            ) as conn:
                user_count, ip_count = (
                    await database.get_verification_submission_counts(
                        guild_id,
                        user_id,
                        ip_hashes,
                        current_time - RATE_WINDOW,
                        conn=conn,
                    )
                )
                if (
                    user_count >= USER_SUBMISSION_LIMIT
                    or ip_count >= IP_SUBMISSION_LIMIT
                ):
                    return _error_response("too_many_requests", 429)

                attempt = await database.record_pending_verification_attempt(
                    token_id=token_id,
                    token_digest=supplied_digest,
                    guild_id=guild_id,
                    user_id=user_id,
                    discord_tag=str(member)[:128],
                    ip_hash=ip_hash,
                    ip_network_hash=ip_network_hash,
                    fingerprint_hash=fingerprint_hash,
                    country_code=country_code,
                    region=None,
                    timezone_name=signals["timezone"],
                    language=signals["language"],
                    browser_family=browser_family,
                    os_family=os_family,
                    device_type=signals["device_class"],
                    signals={
                        "signal_version": signals["signal_version"],
                        "platform": signals["platform"],
                        "mobile": signals["mobile"],
                        "touch_support": signals["touch_support"],
                        "regional_review_role_ids": list(
                            regional_review_role_ids
                        ),
                    },
                    retention_until=(
                        current_time + timedelta(days=DATA_RETENTION_DAYS)
                    ),
                    hash_key_version=IP_HASH_SECRET_VERSION,
                    vpn_check_status=vpn_check.status,
                    vpn_provider_results=vpn_check.provider_results(),
                    vpn_checked_at=current_time,
                    vpn_signal_types=vpn_check.signal_types,
                    vpn_detected="vpn" in vpn_check.signal_types,
                    conn=conn,
                )
                if attempt is None:
                    return _error_response("invalid_or_expired_link", 400)

                if (
                    vpn_check.available_count == 0
                    and not regional_review_role_ids
                ):
                    await database.finalize_verification_attempt(
                        attempt["id"],
                        risk_score=0,
                        risk_level="low",
                        decision="error",
                        role_granted=False,
                        possible_main_user_id=None,
                        risk_reasons=[
                            "Proveedores VPN no disponibles; se requiere reintento"
                        ],
                        conn=conn,
                    )
                else:
                    candidates = (
                        await database.get_verification_match_candidates(
                            guild_id,
                            user_id,
                            ip_hashes,
                            ip_network_hashes,
                            fingerprint_hashes,
                            conn=conn,
                        )
                    )
                    assessment = assess_verification_risk(
                        attempt,
                        candidates,
                        now=current_time,
                        account_created_at=member.created_at,
                        server_joined_at=member.joined_at,
                        vpn_detected_by=vpn_check.detected_providers,
                        vpn_detected_signals=(
                            vpn_check.detected_signal_map()
                        ),
                        vpn_unavailable_by=vpn_check.unavailable_providers,
                    )
                    assessment = _force_regional_manual_review(
                        assessment,
                        regional_review_role_ids,
                    )
                    logger.info(
                        (
                            "Verificacion evaluada | usuario=%s | intento=%s | "
                            "decision=%s | riesgo=%s/100 | relacionadas=%s | "
                            "vpn=%s | motivos=%s"
                        ),
                        user_id,
                        attempt["id"],
                        assessment.decision,
                        assessment.score,
                        assessment.related_user_count,
                        vpn_check.status,
                        ", ".join(assessment.reasons) or "sin coincidencias",
                    )

                    if assessment.requires_review:
                        await database.finalize_verification_attempt(
                            attempt["id"],
                            risk_score=assessment.score,
                            risk_level=assessment.level,
                            decision="review",
                            role_granted=False,
                            possible_main_user_id=(
                                assessment.possible_main_user_id
                            ),
                            risk_reasons=list(assessment.reasons),
                            manual_review_required=True,
                            manual_review_status="pending",
                            conn=conn,
                        )
                    elif assessment.is_rejected:
                        await database.finalize_verification_attempt(
                            attempt["id"],
                            risk_score=assessment.score,
                            risk_level=assessment.level,
                            decision="rejected",
                            role_granted=False,
                            possible_main_user_id=(
                                assessment.possible_main_user_id
                            ),
                            risk_reasons=list(assessment.reasons),
                            conn=conn,
                        )
                    else:
                        queued = await database.queue_approved_role_delivery(
                            attempt["id"],
                            risk_score=assessment.score,
                            risk_level=assessment.level,
                            possible_main_user_id=None,
                            risk_reasons=list(assessment.reasons),
                            conn=conn,
                        )
                        if queued is None:
                            raise RuntimeError(
                                "La verificacion pendiente ya no existe."
                            )
        except Exception:
            logger.exception(
                "No se pudo evaluar o finalizar la solicitud del usuario %s.",
                user_id,
            )
            return _error_response("temporarily_unavailable", 503)

        if attempt is None:
            return _error_response("temporarily_unavailable", 503)

        if vpn_check.available_count == 0 and not regional_review_role_ids:
            await _send_private_result(
                bot,
                token_id,
                user_id,
                "retry",
            )
            try:
                await _send_vpn_unavailable_alert(
                    bot,
                    member,
                    attempt["id"],
                    vpn_check,
                )
            except Exception:
                logger.exception(
                    "No se pudo notificar la indisponibilidad VPN %s.",
                    attempt["id"],
                )
            return _error_response("temporarily_unavailable", 503)

        if assessment is None:
            return _error_response("temporarily_unavailable", 503)

        if assessment.requires_review:
            try:
                await _send_review_alert(
                    bot,
                    member,
                    assessment,
                    attempt["id"],
                    country_code,
                    vpn_check,
                    regional_review_role_ids,
                )
            except Exception:
                logger.exception(
                    "No se pudo publicar la revision manual %s.",
                    attempt["id"],
                )
                try:
                    await database.finalize_verification_attempt(
                        attempt["id"],
                        risk_score=assessment.score,
                        risk_level=assessment.level,
                        decision="error",
                        role_granted=False,
                        possible_main_user_id=(
                            assessment.possible_main_user_id
                        ),
                        risk_reasons=[
                            *assessment.reasons,
                            "No fue posible publicar la revisión manual",
                        ],
                    )
                except Exception:
                    logger.exception(
                        "No se pudo cancelar la revision manual %s.",
                        attempt["id"],
                    )
                await _send_private_result(
                    bot,
                    token_id,
                    user_id,
                    "retry",
                )
                return _error_response("temporarily_unavailable", 503)

            await _send_private_result(
                bot,
                token_id,
                user_id,
                "review",
            )
            return web.json_response({"status": "review"}, status=202)

        if assessment.is_rejected:
            await _send_private_result(
                bot,
                token_id,
                user_id,
                "rejected",
            )
            try:
                await _send_rejection_alert(
                    bot,
                    member,
                    assessment,
                    attempt["id"],
                    country_code,
                    vpn_check,
                )
            except Exception:
                logger.exception(
                    "No se pudo enviar el rechazo al staff %s.",
                    attempt["id"],
                )
            return web.json_response({"status": "rejected"}, status=202)

        manager = getattr(bot, "verification_manager", None)
        if manager is not None:
            try:
                await manager.process_pending_role_delivery(attempt["id"])
            except Exception:
                logger.exception(
                    "La entrega inmediata del rol %s quedo pendiente.",
                    attempt["id"],
                )
        return web.json_response({"status": "received"}, status=202)

    async def start_oauth(request: web.Request) -> web.Response:
        if not await _wait_for_guardian_ready(bot):
            return _error_response("temporarily_unavailable", 503)
        if request.content_type != "application/json":
            return _error_response("invalid_request", 415)

        try:
            request_payload = await request.json(loads=json.loads)
            supplied_token, signals = _parse_submission(request_payload)
            try:
                verification_token = validate_signed_verification_token(
                    supplied_token,
                    expected_guild_id=configured_guild_id,
                )
            except ExpiredVerificationToken:
                verification_token = validate_signed_verification_token(
                    supplied_token,
                    expected_guild_id=configured_guild_id,
                    allow_expired=True,
                )
                recoverable = (
                    await database.is_recoverable_verification_token(
                        verification_token.token_id,
                        token_digest(supplied_token),
                        verification_token.guild_id,
                        verification_token.user_id,
                    )
                )
                if not recoverable:
                    return _error_response("invalid_or_expired_link", 400)
            client_ip = _client_ip(request)
            ip_hash = hash_ip_address(client_ip)
            ip_hashes = hash_ip_address_candidates(client_ip)
            ip_network_hash = hash_ip_network(client_ip)
        except (json.JSONDecodeError, InvalidSubmission):
            return _error_response("invalid_request", 400)
        except InvalidVerificationToken:
            return _error_response("invalid_or_expired_link", 400)
        except VerificationConfigurationError:
            logger.exception("Configuracion criptografica de verificacion invalida.")
            return _error_response("temporarily_unavailable", 503)
        except Exception:
            logger.exception("No se pudo validar la reserva del enlace OAuth.")
            return _error_response("temporarily_unavailable", 503)

        try:
            member = await _get_member(
                bot,
                verification_token.guild_id,
                verification_token.user_id,
            )
        except discord.HTTPException:
            logger.exception(
                "No se pudo comprobar el miembro OAuth %s.",
                verification_token.user_id,
            )
            return _error_response("temporarily_unavailable", 503)
        if member is None or member.bot:
            return _error_response("membership_required", 403)

        supplied_digest = token_digest(supplied_token)
        if member.get_role(VERIFIED_ROLE_ID) is not None:
            await database.revoke_verification_token(
                verification_token.token_id,
                supplied_digest,
            )
            await _send_private_result(
                bot,
                verification_token.token_id,
                verification_token.user_id,
                "approved",
            )
            return web.json_response(
                {
                    "status": "completed",
                    "result_url": _oauth_result_url("received"),
                }
            )

        current_time = datetime.now(timezone.utc)
        try:
            user_count, ip_count = await database.get_oauth_start_counts(
                verification_token.guild_id,
                verification_token.user_id,
                ip_hashes,
                current_time - RATE_WINDOW,
            )
            if (
                user_count >= USER_SUBMISSION_LIMIT
                or ip_count >= IP_SUBMISSION_LIMIT
            ):
                logger.warning(
                    (
                        "Inicio OAuth limitado | usuario=%s | usuario_intentos=%s "
                        "| usuarios_ip=%s"
                    ),
                    verification_token.user_id,
                    user_count,
                    ip_count,
                )
                return _error_response("too_many_requests", 429)

            state = secrets.token_urlsafe(32)
            oauth_session = await database.create_oauth_session(
                session_id=uuid4(),
                state_digest=_oauth_state_digest(state),
                token_id=verification_token.token_id,
                token_digest=supplied_digest,
                guild_id=verification_token.guild_id,
                expected_user_id=verification_token.user_id,
                signals=signals,
                initial_ip_hash=ip_hash,
                initial_ip_network_hash=ip_network_hash,
                hash_key_version=IP_HASH_SECRET_VERSION,
                expires_at=(
                    current_time
                    + timedelta(minutes=OAUTH_STATE_EXPIRATION_MINUTES)
                ),
            )
        except Exception:
            logger.exception(
                "No se pudo crear la sesion OAuth del usuario %s.",
                verification_token.user_id,
            )
            return _error_response("temporarily_unavailable", 503)
        if oauth_session is None:
            return _error_response("invalid_or_expired_link", 400)

        logger.info(
            "Sesion OAuth preparada | usuario=%s | sesion=%s | vence=%s",
            verification_token.user_id,
            oauth_session["session_id"],
            oauth_session["expires_at"],
        )

        return web.json_response(
            {
                "status": "oauth_required",
                "authorization_url": _discord_authorization_url(state),
            }
        )

    async def oauth_callback(request: web.Request) -> web.Response:
        if not await _wait_for_guardian_ready(bot):
            raise _oauth_redirect("retry")

        state = request.query.get("state", "")
        if not OAUTH_STATE_PATTERN.fullmatch(state):
            raise _oauth_redirect("retry")

        oauth_session = await database.claim_oauth_session(
            _oauth_state_digest(state)
        )
        if oauth_session is None:
            raise _oauth_redirect("retry")

        oauth_user_id = None
        try:
            code = request.query.get("code", "")
            oauth_error = request.query.get("error")
            if oauth_error or not code or len(code) > 2048:
                raise RuntimeError("La autorizacion OAuth fue cancelada o es invalida.")

            oauth_user_id = await _exchange_oauth_identity(code)
            expected_user_id = int(oauth_session["expected_user_id"])
            if oauth_user_id != expected_user_id:
                await database.revoke_verification_token(
                    oauth_session["token_id"],
                    str(oauth_session["token_digest"]),
                )
                await database.complete_oauth_session(
                    oauth_session["session_id"],
                    "identity_mismatch",
                    oauth_user_id=oauth_user_id,
                    last_error="La identidad OAuth no coincide con el enlace.",
                )
                await _send_private_result(
                    bot,
                    oauth_session["token_id"],
                    expected_user_id,
                    "rejected",
                )
                try:
                    await _send_identity_mismatch_alert(
                        bot,
                        expected_user_id,
                        oauth_user_id,
                    )
                except Exception:
                    logger.exception(
                        "No se pudo alertar la identidad OAuth no coincidente."
                    )
                raise _oauth_redirect("rejected")

            response = await _evaluate_authenticated_submission(
                request,
                oauth_session,
            )
            if response.status < 400:
                await database.complete_oauth_session(
                    oauth_session["session_id"],
                    "completed",
                    oauth_user_id=oauth_user_id,
                )
                raise _oauth_redirect("received")

            await database.complete_oauth_session(
                oauth_session["session_id"],
                "error",
                oauth_user_id=oauth_user_id,
                last_error=f"La evaluacion termino con HTTP {response.status}.",
            )
            result = "rejected" if response.status == 403 else "retry"
            raise _oauth_redirect(result)
        except web.HTTPException:
            raise
        except Exception as exc:
            logger.exception("No se pudo completar el callback OAuth2.")
            try:
                await database.complete_oauth_session(
                    oauth_session["session_id"],
                    "error",
                    oauth_user_id=oauth_user_id,
                    last_error=str(exc),
                )
            except Exception:
                logger.exception("No se pudo cerrar la sesion OAuth con error.")
            raise _oauth_redirect("retry")

    async def options(_request: web.Request) -> web.Response:
        return web.Response(status=204)

    app = web.Application(
        middlewares=[request_security],
        client_max_size=MAX_REQUEST_SIZE,
    )
    app.router.add_get("/health", health)
    app.router.add_post("/api/oauth/start", start_oauth)
    app.router.add_get("/oauth/callback", oauth_callback)
    app.router.add_route("OPTIONS", "/{path:.*}", options)
    for path in web_documents:
        app.router.add_get(path, web_document)
    app.router.add_static(
        "/assets/",
        path=BASE_DIR / "assets",
        show_index=False,
    )
    return app


class VerificationAPIServer:
    def __init__(self, bot):
        self.bot = bot
        self._runner = None
        self._site = None

    @property
    def is_running(self) -> bool:
        return self._site is not None

    async def start(self) -> None:
        if self.is_running:
            return

        runner = web.AppRunner(
            create_verification_app(self.bot),
            access_log=None,
        )
        await runner.setup()
        try:
            site = web.TCPSite(runner, API_HOST, API_PORT)
            await site.start()
        except Exception:
            await runner.cleanup()
            raise

        self._runner = runner
        self._site = site
        print(f"✅ API de Verificacion SA activa en {API_HOST}:{API_PORT}/health")

    async def stop(self) -> None:
        if self._runner is None:
            return
        await self._runner.cleanup()
        self._runner = None
        self._site = None
