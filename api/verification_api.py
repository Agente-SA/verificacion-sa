import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import discord
from aiohttp import web

from core import database
from core.config import (
    API_HOST,
    API_PORT,
    DATA_RETENTION_DAYS,
    FRONTEND_URL,
    GUILD_ID,
    STAFF_CHANNEL_ID,
    VERIFIED_ROLE_ID,
)
from core.verification_risk import RiskAssessment, assess_verification_risk
from core.verification_security import (
    InvalidVerificationToken,
    VerificationConfigurationError,
    hash_ip_address,
    hash_ip_network,
    hash_limited_fingerprint,
    token_digest,
    validate_signed_verification_token,
)
from core.vpn_detection import VPNCheckResult, check_vpn_services


logger = logging.getLogger(__name__)
API_NAME = "verification-sa-api"
API_VERSION = 1
MAX_REQUEST_SIZE = 64 * 1024
RATE_WINDOW = timedelta(minutes=15)
USER_SUBMISSION_LIMIT = 5
IP_SUBMISSION_LIMIT = 30
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


class InvalidSubmission(ValueError):
    pass


class RoleGrantError(RuntimeError):
    def __init__(self, message: str, diagnostics: str | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


def _frontend_origin() -> str:
    parsed = urlsplit(FRONTEND_URL)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("FRONTEND_URL debe ser una direccion HTTPS valida.")
    return f"{parsed.scheme}://{parsed.netloc}"


def _apply_security_headers(response: web.StreamResponse) -> None:
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )


def _error_response(code: str, status: int) -> web.Response:
    return web.json_response(
        {"status": "error", "code": code},
        status=status,
    )


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


def _client_ip(request: web.Request) -> str:
    supplied_ip = request.headers.get("CF-Connecting-IP") or request.remote
    if not supplied_ip:
        raise InvalidSubmission("Direccion de red no disponible.")
    try:
        parsed_ip = ipaddress.ip_address(supplied_ip.strip())
    except ValueError as exc:
        raise InvalidSubmission("Direccion de red invalida.") from exc
    if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped:
        parsed_ip = parsed_ip.ipv4_mapped
    return parsed_ip.compressed


def _country_code(request: web.Request) -> str | None:
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


async def _grant_verified_role(member: discord.Member) -> bool:
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
    if fresh_member.get_role(role.id) is not None:
        return False

    try:
        await fresh_member.add_roles(
            role,
            reason="Verificacion SA aprobada automaticamente",
        )
    except discord.HTTPException as exc:
        raise RoleGrantError(str(exc), diagnostics) from exc
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
    approved: bool,
) -> None:
    manager = getattr(bot, "verification_manager", None)
    if manager is None:
        logger.warning(
            "No hay gestor disponible para notificar la verificacion de %s.",
            user_id,
        )
        return

    try:
        delivered = await manager.send_verification_result(
            token_id,
            user_id,
            approved,
        )
    except Exception:
        logger.exception(
            "No se pudo enviar el resultado privado de verificacion a %s.",
            user_id,
        )
        return

    if not delivered:
        logger.info(
            "La interaccion privada de verificacion ya no estaba activa para %s.",
            user_id,
        )


async def _send_review_alert(
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

    main_user_id = assessment.possible_main_user_id
    if main_user_id is None:
        content = (
            f"Verificacion rechazada por VPN/Proxy {member.mention} "
            f"({member.id})"
        )
        main_account_value = "No detectada"
    else:
        content = (
            f"Posible ALT-ACCOUNT {member.mention} ({member.id}) - "
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
        name="VPN / Proxy",
        value=vpn_check.discord_summary(),
        inline=True,
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
    embed.set_footer(
        text=(
            "La coincidencia es una senal preventiva y requiere revision humana."
        )
    )
    await channel.send(
        content,
        embed=embed,
        allowed_mentions=discord.AllowedMentions(
            everyone=False,
            users=True,
            roles=False,
            replied_user=False,
        ),
    )


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
    allowed_origin = _frontend_origin()
    configured_guild_id = GUILD_ID

    @web.middleware
    async def request_security(
        request: web.Request,
        handler,
    ) -> web.StreamResponse:
        origin = request.headers.get("Origin")
        if origin and origin != allowed_origin:
            response = _error_response("origin_not_allowed", 403)
            _apply_security_headers(response)
            response.headers["Vary"] = "Origin"
            return response

        try:
            response = await handler(request)
        except web.HTTPException as http_error:
            response = http_error

        _apply_security_headers(response)
        response.headers["Vary"] = "Origin"
        if origin == allowed_origin:
            response.headers["Access-Control-Allow-Origin"] = allowed_origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Max-Age"] = "600"
        return response

    async def health(_request: web.Request) -> web.Response:
        return web.json_response(
            {
                "status": "ok",
                "service": API_NAME,
                "version": API_VERSION,
            }
        )

    async def submit(request: web.Request) -> web.Response:
        if database.bot_pool is None or not bot.is_ready():
            return _error_response("temporarily_unavailable", 503)
        if request.content_type != "application/json":
            return _error_response("invalid_request", 415)

        try:
            request_payload = await request.json(loads=json.loads)
            supplied_token, signals = _parse_submission(request_payload)
            verification_token = validate_signed_verification_token(
                supplied_token,
                expected_guild_id=configured_guild_id,
            )
        except (json.JSONDecodeError, InvalidSubmission):
            return _error_response("invalid_request", 400)
        except InvalidVerificationToken:
            return _error_response("invalid_or_expired_link", 400)
        except VerificationConfigurationError:
            logger.exception("Configuracion criptografica de verificacion invalida.")
            return _error_response("temporarily_unavailable", 503)

        try:
            member = await _get_member(
                bot,
                verification_token.guild_id,
                verification_token.user_id,
            )
        except discord.HTTPException:
            logger.exception(
                "No se pudo comprobar el miembro de verificacion %s.",
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
                approved=True,
            )
            return web.json_response({"status": "completed"})

        try:
            client_ip = _client_ip(request)
            ip_hash = hash_ip_address(client_ip)
            ip_network_hash = hash_ip_network(client_ip)
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
        except (InvalidSubmission, VerificationConfigurationError):
            return _error_response("temporarily_unavailable", 503)

        current_time = datetime.now(timezone.utc)
        try:
            user_count, ip_count = await database.get_verification_submission_counts(
                verification_token.guild_id,
                verification_token.user_id,
                ip_hash,
                current_time - RATE_WINDOW,
            )
            if user_count >= USER_SUBMISSION_LIMIT or ip_count >= IP_SUBMISSION_LIMIT:
                return _error_response("too_many_requests", 429)

            attempt = await database.record_pending_verification_attempt(
                token_id=verification_token.token_id,
                token_digest=supplied_digest,
                guild_id=verification_token.guild_id,
                user_id=verification_token.user_id,
                discord_tag=str(member)[:128],
                ip_hash=ip_hash,
                ip_network_hash=ip_network_hash,
                fingerprint_hash=fingerprint_hash,
                country_code=_country_code(request),
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
                },
                retention_until=current_time + timedelta(days=DATA_RETENTION_DAYS),
            )
        except Exception:
            logger.exception(
                "No se pudo registrar la solicitud de verificacion del usuario %s.",
                verification_token.user_id,
            )
            return _error_response("temporarily_unavailable", 503)

        if attempt is None:
            return _error_response("invalid_or_expired_link", 400)

        vpn_check = await check_vpn_services(client_ip)
        if vpn_check.available_count == 0:
            logger.warning(
                "Evaluacion VPN omitida temporalmente | usuario=%s | intento=%s",
                verification_token.user_id,
                attempt["id"],
            )

        try:
            candidates = await database.get_verification_match_candidates(
                verification_token.guild_id,
                verification_token.user_id,
                ip_hash,
                ip_network_hash,
                fingerprint_hash,
            )
            assessment = assess_verification_risk(
                attempt,
                candidates,
                now=current_time,
                account_created_at=member.created_at,
                server_joined_at=member.joined_at,
                vpn_detected_by=vpn_check.detected_providers,
            )
            logger.info(
                (
                    "Verificacion evaluada | usuario=%s | intento=%s | "
                    "decision=%s | riesgo=%s/100 | relacionadas=%s | motivos=%s"
                ),
                verification_token.user_id,
                attempt["id"],
                assessment.decision,
                assessment.score,
                assessment.related_user_count,
                ", ".join(assessment.reasons) or "sin coincidencias",
            )
        except Exception:
            logger.exception(
                "No se pudo evaluar el riesgo de la verificacion %s.",
                attempt["id"],
            )
            return _error_response("temporarily_unavailable", 503)

        if assessment.requires_review:
            try:
                await database.finalize_verification_attempt(
                    attempt["id"],
                    risk_score=assessment.score,
                    risk_level=assessment.level,
                    decision="review",
                    role_granted=False,
                    possible_main_user_id=assessment.possible_main_user_id,
                    risk_reasons=list(assessment.reasons),
                )
            except Exception:
                logger.exception(
                    "No se pudo finalizar la verificacion en revision %s.",
                    attempt["id"],
                )
                return _error_response("temporarily_unavailable", 503)

            await _send_private_result(
                bot,
                verification_token.token_id,
                verification_token.user_id,
                approved=False,
            )
            try:
                await _send_review_alert(
                    bot,
                    member,
                    assessment,
                    attempt["id"],
                    attempt["country_code"],
                    vpn_check,
                )
            except Exception:
                logger.exception(
                    "No se pudo enviar la alerta de la verificacion %s.",
                    attempt["id"],
                )
            return web.json_response({"status": "accepted"}, status=202)

        role_added = False
        try:
            role_added = await _grant_verified_role(member)
        except (RoleGrantError, discord.HTTPException) as exc:
            logger.exception(
                "No se pudo otorgar el rol de verificacion al usuario %s.",
                member.id,
            )
            try:
                await database.finalize_verification_attempt(
                    attempt["id"],
                    risk_score=assessment.score,
                    risk_level=assessment.level,
                    decision="error",
                    role_granted=False,
                    possible_main_user_id=None,
                    risk_reasons=["No fue posible otorgar el rol verificado"],
                )
                await _send_role_error_alert(
                    bot,
                    member,
                    attempt["id"],
                    str(exc),
                    getattr(exc, "diagnostics", None),
                )
            except Exception:
                logger.exception(
                    "No se pudo registrar o alertar el error de rol de %s.",
                    attempt["id"],
                )
            await _send_private_result(
                bot,
                verification_token.token_id,
                verification_token.user_id,
                approved=False,
            )
            return web.json_response({"status": "accepted"}, status=202)

        try:
            finalized = await database.finalize_verification_attempt(
                attempt["id"],
                risk_score=assessment.score,
                risk_level=assessment.level,
                decision="approved",
                role_granted=True,
                possible_main_user_id=None,
                risk_reasons=list(assessment.reasons),
            )
            if finalized is None:
                raise RuntimeError("La verificacion pendiente ya no existe.")
        except Exception:
            logger.exception(
                "No se pudo guardar la aprobacion de la verificacion %s.",
                attempt["id"],
            )
            if role_added:
                try:
                    await _remove_verified_role(member)
                except discord.HTTPException:
                    logger.exception(
                        "No se pudo revertir el rol del usuario %s.",
                        member.id,
                    )
            return _error_response("temporarily_unavailable", 503)

        await _send_private_result(
            bot,
            verification_token.token_id,
            verification_token.user_id,
            approved=True,
        )
        try:
            await _send_success_alert(bot, member)
        except Exception:
            logger.exception(
                "No se pudo enviar el aviso de verificacion exitosa %s.",
                attempt["id"],
            )

        return web.json_response({"status": "accepted"}, status=202)

    async def options(_request: web.Request) -> web.Response:
        return web.Response(status=204)

    app = web.Application(
        middlewares=[request_security],
        client_max_size=MAX_REQUEST_SIZE,
    )
    app.router.add_get("/health", health)
    app.router.add_post("/api/verification/submit", submit)
    app.router.add_route("OPTIONS", "/{path:.*}", options)
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
