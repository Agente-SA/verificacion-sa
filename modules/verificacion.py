import asyncio
import logging
import math

import discord

from core import database
from core.config import (
    DB_NO_DISPONIBLE,
    GUILD_ID,
    TOKEN_EXPIRATION_MINUTES,
    VERIFICATION_TICKET_CHANNEL_ID,
    VERIFIED_ROLE_ID,
    get_configuration_errors,
    require_staff,
)
from core.verification_security import create_signed_verification_token


logger = logging.getLogger(__name__)
ISSUE_COOLDOWN_SECONDS = 15
RESULT_INTERACTION_LIFETIME_SECONDS = TOKEN_EXPIRATION_MINUTES * 60
VERIFIED_USERS_PER_PAGE = 10


def _discord_timestamp(value, style: str = "d") -> str:
    if value is None:
        return "No disponible"
    return f"<t:{int(value.timestamp())}:{style}>"


def _format_country(country_code: str | None) -> str:
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "No disponible"
    flag = "".join(chr(127397 + ord(character)) for character in code)
    return f"{flag} {code}"


class PersonalVerificationLinkView(discord.ui.View):
    def __init__(self, verification_url: str):
        super().__init__(timeout=TOKEN_EXPIRATION_MINUTES * 60)
        self.add_item(
            discord.ui.Button(
                label="Verificarme Ahora",
                style=discord.ButtonStyle.link,
                url=verification_url,
            )
        )


class VerificationPanelView(discord.ui.View):
    def __init__(self, manager: "VerificationManager"):
        super().__init__(timeout=None)
        self.manager = manager

    @discord.ui.button(
        label="Verificar",
        style=discord.ButtonStyle.success,
        custom_id="verification_sa:start:v1",
    )
    async def verify(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button,
    ):
        await self.manager.issue_personal_link(interaction)


class VerifiedUsersPaginator(discord.ui.View):
    def __init__(
        self,
        manager: "VerificationManager",
        requested_by: int,
        page: int,
        total: int,
    ):
        super().__init__(timeout=180)
        self.manager = manager
        self.requested_by = requested_by
        self.page = page
        self.total = total
        self._sync_buttons()

    @property
    def max_page(self) -> int:
        return max(0, math.ceil(self.total / VERIFIED_USERS_PER_PAGE) - 1)

    def _sync_buttons(self) -> None:
        self.previous_page.disabled = self.page <= 0
        self.next_page.disabled = self.page >= self.max_page

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.requested_by:
            return True
        await interaction.response.send_message(
            "Solo quien ejecutó el comando puede navegar esta consulta.",
            ephemeral=True,
        )
        return False

    async def _change_page(
        self,
        interaction: discord.Interaction,
        new_page: int,
    ) -> None:
        await interaction.response.defer()
        try:
            self.total = int(
                await database.get_verified_users_count(interaction.guild.id)
            )
            self.page = min(max(0, new_page), self.max_page)
            self._sync_buttons()
            embed = await self.manager.verified_users_embed(
                interaction.guild,
                self.page,
                self.total,
            )
        except Exception:
            logger.exception("No se pudo cambiar la pagina de verificados.")
            await interaction.followup.send(
                "No fue posible actualizar la consulta en este momento.",
                ephemeral=True,
            )
            return
        await interaction.edit_original_response(embed=embed, view=self)

    @discord.ui.button(label="◀", style=discord.ButtonStyle.secondary)
    async def previous_page(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button,
    ):
        await self._change_page(interaction, self.page - 1)

    @discord.ui.button(label="▶", style=discord.ButtonStyle.secondary)
    async def next_page(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button,
    ):
        await self._change_page(interaction, self.page + 1)


class ClearVerificationRecordsView(discord.ui.View):
    def __init__(
        self,
        manager: "VerificationManager",
        requested_by: int,
        target: discord.Member,
    ):
        super().__init__(timeout=60)
        self.manager = manager
        self.requested_by = requested_by
        self.target = target
        self._operation_lock = asyncio.Lock()
        self._completed = False

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.requested_by:
            return True
        await interaction.response.send_message(
            "Solo quien ejecutó el comando puede confirmar esta limpieza.",
            ephemeral=True,
        )
        return False

    @discord.ui.button(label="Confirmar", style=discord.ButtonStyle.danger)
    async def confirm(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button,
    ):
        async with self._operation_lock:
            if self._completed:
                await interaction.response.send_message(
                    "Esta solicitud ya fue procesada.",
                    ephemeral=True,
                )
                return

            self._completed = True
            await interaction.response.defer()
            try:
                deleted = await database.clear_verification_records(
                    self.target.guild.id,
                    self.target.id,
                )
            except Exception:
                self._completed = False
                logger.exception(
                    "No se pudo limpiar la verificacion del usuario %s.",
                    self.target.id,
                )
                await interaction.edit_original_response(
                    content=(
                        "No fue posible limpiar los registros. "
                        "Inténtalo nuevamente más tarde."
                    ),
                    embed=None,
                    view=None,
                )
                return

            self.manager.clear_user_runtime_state(self.target.id)
            logger.warning(
                (
                    "Registros de verificacion eliminados | ejecutor=%s | "
                    "usuario=%s | intentos=%s | tokens=%s | "
                    "antifraude=%s | perfiles=%s"
                ),
                interaction.user.id,
                self.target.id,
                deleted["attempts"],
                deleted["tokens"],
                deleted["antifraud"],
                deleted["profiles"],
            )
            await interaction.edit_original_response(
                content=(
                    f"Limpieza completada para {self.target.mention}.\n"
                    f"Intentos eliminados: **{deleted['attempts']}**\n"
                    f"Tokens eliminados: **{deleted['tokens']}**\n"
                    f"Señales antifraude eliminadas: "
                    f"**{deleted['antifraud']}**\n"
                    f"Perfiles permanentes eliminados: "
                    f"**{deleted['profiles']}**\n\n"
                    "El rol de Discord no fue modificado."
                ),
                embed=None,
                view=None,
            )
            self.stop()

    @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.secondary)
    async def cancel(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button,
    ):
        if self._completed:
            await interaction.response.send_message(
                "Esta solicitud ya fue procesada.",
                ephemeral=True,
            )
            return
        self._completed = True
        await interaction.response.edit_message(
            content="Limpieza cancelada.",
            embed=None,
            view=None,
        )
        self.stop()


class VerificationManager:
    def __init__(self, bot):
        self.bot = bot
        self._issue_locks = {}
        self._last_issued_at = {}
        self._pending_result_interactions = {}

    def _purge_expired_result_interactions(self, now: float) -> None:
        expired_tokens = [
            token_id
            for token_id, (_user_id, _interaction, expires_at) in (
                self._pending_result_interactions.items()
            )
            if expires_at <= now
        ]
        for token_id in expired_tokens:
            self._pending_result_interactions.pop(token_id, None)

    def remember_result_interaction(
        self,
        token_id,
        user_id: int,
        interaction: discord.Interaction,
    ) -> None:
        now = asyncio.get_running_loop().time()
        self._purge_expired_result_interactions(now)
        self._pending_result_interactions[token_id] = (
            user_id,
            interaction,
            now + RESULT_INTERACTION_LIFETIME_SECONDS,
        )

    async def send_verification_result(
        self,
        token_id,
        user_id: int,
        approved: bool,
    ) -> bool:
        now = asyncio.get_running_loop().time()
        self._purge_expired_result_interactions(now)
        pending = self._pending_result_interactions.get(token_id)
        if pending is None or pending[0] != user_id:
            return False

        self._pending_result_interactions.pop(token_id, None)
        if approved:
            content = "Tu cuenta ha sido Verificada con Éxito ✔️"
        else:
            content = (
                "❌ Tu cuenta no ha podido ser verificada. Si crees que se trata "
                "de un error, abre un ticket en "
                f"<#{VERIFICATION_TICKET_CHANNEL_ID}> y selecciona la **Opción 1**."
            )

        await pending[1].followup.send(content, ephemeral=True)
        return True

    def clear_user_runtime_state(self, user_id: int) -> None:
        self._last_issued_at.pop(user_id, None)
        lock = self._issue_locks.get(user_id)
        if lock is None or not lock.locked():
            self._issue_locks.pop(user_id, None)
        user_tokens = [
            token_id
            for token_id, pending in self._pending_result_interactions.items()
            if pending[0] == user_id
        ]
        for token_id in user_tokens:
            self._pending_result_interactions.pop(token_id, None)

    async def verified_users_embed(
        self,
        guild: discord.Guild,
        page: int,
        total: int,
    ) -> discord.Embed:
        offset = page * VERIFIED_USERS_PER_PAGE
        rows = await database.get_verified_users_page(
            guild.id,
            VERIFIED_USERS_PER_PAGE,
            offset,
        )
        embed = discord.Embed(
            title="Usuarios Verificados SA",
            description=f"Registros permanentes: **{total}**",
            color=discord.Color.blue(),
        )

        if not rows:
            embed.description = "No hay usuarios verificados registrados."
        for position, row in enumerate(rows, start=offset + 1):
            user_id = int(row["user_id"])
            member = guild.get_member(user_id)
            if member is None:
                try:
                    member = await guild.fetch_member(user_id)
                except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                    member = None
            created_at = (
                member.created_at
                if member is not None
                else discord.utils.snowflake_time(user_id)
            )
            joined_at = member.joined_at if member is not None else None
            joined_relative = (
                f" ({_discord_timestamp(joined_at, 'R')})" if joined_at else ""
            )
            if member is None:
                display_name = f"Usuario {user_id}"
                role_status = "Fuera del servidor"
            else:
                display_name = discord.utils.escape_markdown(member.display_name)
                role_status = (
                    "Rol activo"
                    if member.get_role(VERIFIED_ROLE_ID) is not None
                    else "Sin rol verificado"
                )

            if row["risk_score"] is None:
                latest_risk = "Detalle técnico purgado"
            else:
                risk_level = (row["risk_level"] or "sin nivel").upper()
                latest_risk = f"{risk_level} ({row['risk_score']}/100)"

            embed.add_field(
                name=f"{position}. {display_name}",
                value=(
                    f"{member.mention if member else f'<@{user_id}>'} "
                    f"(`{user_id}`)\n"
                    f"Primera verificación: "
                    f"{_discord_timestamp(row['first_verified_at'])}\n"
                    f"Última verificación: "
                    f"{_discord_timestamp(row['last_verified_at'])}\n"
                    f"Cuenta creada: {_discord_timestamp(created_at)} "
                    f"({_discord_timestamp(created_at, 'R')})\n"
                    f"Ingreso al servidor: {_discord_timestamp(joined_at)}"
                    f"{joined_relative}\n"
                    f"País aproximado: "
                    f"{_format_country(row['last_country_code'])}\n"
                    f"Estado: **{role_status}** | Riesgo reciente: "
                    f"**{latest_risk}**"
                ),
                inline=False,
            )

        max_page = max(1, math.ceil(total / VERIFIED_USERS_PER_PAGE))
        embed.set_footer(text=f"Página {page + 1}/{max_page}")
        return embed

    @staticmethod
    def panel_embed() -> discord.Embed:
        embed = discord.Embed(
            title="Verificación Super Sus SA Oficial",
            description="Conviértete en un usuario Verificado de la Comunidad...",
            color=discord.Color.blue(),
        )
        embed.set_thumbnail(
            url=(
                "https://pub-a09b3609b6b34dfab5c7aa7742cd1a8a.r2.dev/"
                "verify.png"
            )
        )
        embed.set_footer(text="Desarrollado por Super Sus SA Oficial")
        return embed

    async def issue_personal_link(self, interaction: discord.Interaction):
        if interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message(
                "La verificación solo está disponible dentro del servidor.",
                ephemeral=True,
            )
            return

        if interaction.guild.id != GUILD_ID:
            await interaction.response.send_message(
                "Este panel no pertenece al servidor configurado.",
                ephemeral=True,
            )
            return

        if get_configuration_errors():
            await interaction.response.send_message(
                "La verificación no está disponible temporalmente.",
                ephemeral=True,
            )
            return

        if database.bot_pool is None:
            await interaction.response.send_message(
                DB_NO_DISPONIBLE,
                ephemeral=True,
            )
            return

        if any(role.id == VERIFIED_ROLE_ID for role in interaction.user.roles):
            await interaction.response.send_message(
                "Tu cuenta ya está verificada en el servidor.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        user_id = interaction.user.id
        lock = self._issue_locks.setdefault(user_id, asyncio.Lock())

        async with lock:
            loop_time = asyncio.get_running_loop().time()
            last_issued_at = self._last_issued_at.get(user_id, 0.0)
            remaining = ISSUE_COOLDOWN_SECONDS - (loop_time - last_issued_at)
            if remaining > 0:
                await interaction.followup.send(
                    f"Espera {math.ceil(remaining)} segundos antes de solicitar otro enlace.",
                    ephemeral=True,
                )
                return

            try:
                issued = create_signed_verification_token(
                    interaction.guild.id,
                    user_id,
                )
                await database.create_verification_token(
                    issued.payload.token_id,
                    issued.digest,
                    issued.payload.guild_id,
                    issued.payload.user_id,
                    issued.payload.expires_at,
                )
            except Exception:
                logger.exception(
                    "No se pudo emitir un enlace de verificacion para el usuario %s",
                    user_id,
                )
                await interaction.followup.send(
                    "No fue posible generar tu enlace. Inténtalo nuevamente más tarde.",
                    ephemeral=True,
                )
                return

            self._last_issued_at[user_id] = asyncio.get_running_loop().time()
            embed = discord.Embed(
                title="Proceso de Verificación.",
                description=(
                    "Presiona **Verificarme Ahora** para recibir un enlace personal "
                    "y temporal visible únicamente para ti. Te recomendamos leer "
                    "y aceptar el aviso de privacidad."
                ),
                color=discord.Color.green(),
            )
            embed.set_footer(text="El enlace solo puede utilizarse una vez.")
            await interaction.followup.send(
                embed=embed,
                view=PersonalVerificationLinkView(issued.verification_url),
                ephemeral=True,
            )
            self.remember_result_interaction(
                issued.payload.token_id,
                user_id,
                interaction,
            )


def setup(bot):
    verification = VerificationManager(bot)
    bot.verification_manager = verification
    bot.add_view(VerificationPanelView(verification))

    @bot.tree.command(
        name="verificacion_sa",
        description="(Staff) Publica el panel de verificación del servidor.",
    )
    @require_staff()
    @discord.app_commands.describe(
        canal="Canal donde se publicará el panel permanente de verificación.",
    )
    async def verificacion_sa(
        interaction: discord.Interaction,
        canal: discord.TextChannel,
    ):
        bot_member = canal.guild.me
        if bot_member is None:
            await interaction.response.send_message(
                "No fue posible localizar al bot dentro del servidor.",
                ephemeral=True,
            )
            return

        permissions = canal.permissions_for(bot_member)
        if not (
            permissions.view_channel
            and permissions.send_messages
            and permissions.embed_links
        ):
            await interaction.response.send_message(
                (
                    "El bot necesita **Ver canal**, **Enviar mensajes** e "
                    "**Insertar enlaces** en el canal seleccionado."
                ),
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            await canal.send(
                embed=verification.panel_embed(),
                view=VerificationPanelView(verification),
            )
        except discord.Forbidden:
            await interaction.followup.send(
                "Discord rechazó la publicación por falta de permisos en ese canal.",
                ephemeral=True,
            )
            return
        except discord.HTTPException:
            logger.exception(
                "No se pudo publicar el panel de verificacion en el canal %s.",
                canal.id,
            )
            await interaction.followup.send(
                "No fue posible publicar el panel. Inténtalo nuevamente más tarde.",
                ephemeral=True,
            )
            return

        await interaction.followup.send(
            f"Panel permanente de verificación publicado en {canal.mention}.",
            ephemeral=True,
        )

    @bot.tree.command(
        name="usuarios_verificados",
        description="(Staff) Consulta los usuarios verificados del servidor.",
    )
    @require_staff()
    async def usuarios_verificados(interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message(
                "Este comando solo está disponible dentro del servidor.",
                ephemeral=True,
            )
            return
        if database.bot_pool is None:
            await interaction.response.send_message(
                DB_NO_DISPONIBLE,
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            total = int(
                await database.get_verified_users_count(interaction.guild.id)
            )
            embed = await verification.verified_users_embed(
                interaction.guild,
                0,
                total,
            )
        except Exception:
            logger.exception("No se pudo consultar los usuarios verificados.")
            await interaction.followup.send(
                "No fue posible consultar los registros en este momento.",
                ephemeral=True,
            )
            return

        await interaction.followup.send(
            embed=embed,
            view=VerifiedUsersPaginator(
                verification,
                interaction.user.id,
                0,
                total,
            ),
            ephemeral=True,
        )

    @bot.tree.command(
        name="limpiar_registro",
        description="(Admin) Elimina todos los datos de verificación de un usuario.",
    )
    @discord.app_commands.describe(
        usuario="Usuario cuyos datos de verificación serán eliminados.",
    )
    async def limpiar_registro(
        interaction: discord.Interaction,
        usuario: discord.Member,
    ):
        if not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message(
                "Este comando está limitado a administradores.",
                ephemeral=True,
            )
            return

        if database.bot_pool is None:
            await interaction.response.send_message(
                DB_NO_DISPONIBLE,
                ephemeral=True,
            )
            return

        embed = discord.Embed(
            title="Confirmar limpieza de verificación",
            description=(
                f"Se eliminarán de PostgreSQL los intentos, tokens, perfil "
                f"permanente y señales antifraude de {usuario.mention} "
                f"(`{usuario.id}`).\n\n"
                "Esta acción es irreversible y no retirará su rol de Discord."
            ),
            color=discord.Color.red(),
        )
        await interaction.response.send_message(
            embed=embed,
            view=ClearVerificationRecordsView(
                verification,
                interaction.user.id,
                usuario,
            ),
            ephemeral=True,
        )
