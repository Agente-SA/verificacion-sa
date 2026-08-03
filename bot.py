import asyncio
import logging

import discord
from discord.ext import commands, tasks

from api.verification_api import VerificationAPIServer
from core.config import DISCORD_TOKEN, GUILD_ID, intents, validate_configuration
from core.database import close_db, init_db, purge_expired_verification_data
from modules import verificacion


logger = logging.getLogger(__name__)


class VerificationBot(commands.Bot):
    def __init__(self) -> None:
        super().__init__(
            command_prefix=commands.when_mentioned,
            intents=intents,
            allowed_mentions=discord.AllowedMentions(
                everyone=False,
                roles=False,
                users=True,
                replied_user=False,
            ),
        )
        self.verification_api: VerificationAPIServer | None = None

    async def setup_hook(self) -> None:
        validate_configuration()
        await init_db()

        verification_manager = verificacion.setup(self)
        restored_reviews = (
            await verification_manager.restore_pending_manual_reviews()
        )
        if restored_reviews:
            print(
                f"Revisiones manuales restauradas: {restored_reviews} pendiente(s)."
            )
        self.verification_api = VerificationAPIServer(self)
        await self.verification_api.start()
        self.cleanup_verification_data_task.start()

        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        synced = await self.tree.sync(guild=guild)
        print(f"Comandos sincronizados en el servidor: {len(synced)}")

    async def close(self) -> None:
        if self.cleanup_verification_data_task.is_running():
            self.cleanup_verification_data_task.cancel()
        if self.verification_api is not None:
            await self.verification_api.stop()
        await close_db()
        await super().close()

    @tasks.loop(hours=24)
    async def cleanup_verification_data_task(self) -> None:
        try:
            deleted = await purge_expired_verification_data()
        except Exception:
            logger.exception("No se pudo aplicar la retención de verificación.")
            return
        if any(deleted.values()):
            print(
                "Retención aplicada: "
                f"{deleted['attempts']} intento(s), "
                f"{deleted['tokens']} token(s) y "
                f"{deleted['antifraud']} señal(es) eliminados."
            )

    @cleanup_verification_data_task.before_loop
    async def before_verification_cleanup(self) -> None:
        await self.wait_until_ready()
        await asyncio.sleep(30)


bot = VerificationBot()


@bot.event
async def on_ready() -> None:
    print(f"🛡️ Guardian SUS conectado correctamente como {bot.user}")
    print("✅ Enlace con Discord establecido. Sistema de verificación listo.")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("discord").setLevel(logging.WARNING)
    bot.run(DISCORD_TOKEN, log_handler=None)
