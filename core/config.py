import os
import ipaddress
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import discord
from discord import app_commands
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=BASE_DIR / ".env")


def _env_int(name: str, default: int = 0) -> int:
    raw_value = os.getenv(name, str(default)).strip()
    if not raw_value:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def _env_snowflake_set(name: str) -> frozenset[int]:
    values = set()
    for raw_value in os.getenv(name, "").split(","):
        value = raw_value.strip()
        if value.isdigit() and int(value) > 0:
            values.add(int(value))
    return frozenset(values)


def _env_ip_networks(name: str, default: str) -> tuple:
    networks = []
    raw_values = os.getenv(name, default)
    for raw_value in raw_values.split(","):
        value = raw_value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise RuntimeError(f"{name} contiene una red invalida: {value}") from exc
    return tuple(networks)


DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
GUILD_ID = _env_int("GUILD_ID")
def _normalize_database_url(raw_url: str) -> str:
    database_url = raw_url.strip()
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    if not database_url:
        return database_url

    parsed = urlsplit(database_url)
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() != "channel_binding"
    ]
    return urlunsplit(parsed._replace(query=urlencode(query)))


DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL", ""))

VERIFIED_ROLE_ID = _env_int("VERIFIED_ROLE_ID")
STAFF_CHANNEL_ID = _env_int("STAFF_CHANNEL_ID")
VERIFICATION_TICKET_CHANNEL_ID = _env_int("VERIFICATION_TICKET_CHANNEL_ID")
STAFF_ROLE_IDS = _env_snowflake_set("STAFF_ROLE_IDS")

FRONTEND_URL = os.getenv("FRONTEND_URL", "").strip().rstrip("/")
TOKEN_EXPIRATION_MINUTES = max(1, _env_int("TOKEN_EXPIRATION_MINUTES", 10))
DATA_RETENTION_DAYS = max(1, _env_int("DATA_RETENTION_DAYS", 90))
ANTIFRAUD_RETENTION_DAYS = max(1, _env_int("ANTIFRAUD_RETENTION_DAYS", 400))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "").strip()
IP_HASH_SECRET = os.getenv("IP_HASH_SECRET", "").strip()
IP_HASH_SECRET_PREVIOUS = os.getenv("IP_HASH_SECRET_PREVIOUS", "").strip()
IP_HASH_SECRET_VERSION = max(1, _env_int("IP_HASH_SECRET_VERSION", 1))

TRUSTED_PROXY_NETWORKS = _env_ip_networks(
    "TRUSTED_PROXY_CIDRS",
    "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
)

API_HOST = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
API_PORT = _env_int("PORT", 80)
if not 1 <= API_PORT <= 65535:
    API_PORT = 80

DB_NO_DISPONIBLE = (
    "La base de datos no está disponible temporalmente. "
    "Inténtalo nuevamente más tarde."
)


def get_configuration_errors() -> tuple[str, ...]:
    errors = []
    required_values = {
        "DISCORD_TOKEN": DISCORD_TOKEN,
        "GUILD_ID": GUILD_ID,
        "DATABASE_URL": DATABASE_URL,
        "VERIFIED_ROLE_ID": VERIFIED_ROLE_ID,
        "STAFF_CHANNEL_ID": STAFF_CHANNEL_ID,
        "VERIFICATION_TICKET_CHANNEL_ID": VERIFICATION_TICKET_CHANNEL_ID,
        "FRONTEND_URL": FRONTEND_URL,
        "TOKEN_SECRET": TOKEN_SECRET,
        "IP_HASH_SECRET": IP_HASH_SECRET,
    }
    errors.extend(name for name, value in required_values.items() if not value)

    if FRONTEND_URL:
        parsed_frontend = urlsplit(FRONTEND_URL)
        if parsed_frontend.scheme != "https" or not parsed_frontend.netloc:
            errors.append("FRONTEND_URL debe usar HTTPS")
    if DATABASE_URL and not DATABASE_URL.startswith("postgresql://"):
        errors.append("DATABASE_URL debe ser una URL PostgreSQL")
    if TOKEN_SECRET and len(TOKEN_SECRET) < 32:
        errors.append("TOKEN_SECRET debe tener al menos 32 caracteres")
    if IP_HASH_SECRET and len(IP_HASH_SECRET) < 32:
        errors.append("IP_HASH_SECRET debe tener al menos 32 caracteres")
    if IP_HASH_SECRET_PREVIOUS and len(IP_HASH_SECRET_PREVIOUS) < 32:
        errors.append(
            "IP_HASH_SECRET_PREVIOUS debe tener al menos 32 caracteres"
        )
    if IP_HASH_SECRET_PREVIOUS and IP_HASH_SECRET_PREVIOUS == IP_HASH_SECRET:
        errors.append(
            "IP_HASH_SECRET_PREVIOUS debe ser diferente de IP_HASH_SECRET"
        )
    if not TRUSTED_PROXY_NETWORKS:
        errors.append("TRUSTED_PROXY_CIDRS debe contener al menos una red")
    if not STAFF_ROLE_IDS:
        errors.append("STAFF_ROLE_IDS debe contener al menos un ID de rol")
    return tuple(errors)


def validate_configuration() -> None:
    errors = get_configuration_errors()
    if errors:
        raise RuntimeError("Configuración incompleta: " + "; ".join(errors))


def is_staff(interaction: discord.Interaction) -> bool:
    if interaction.guild is None or not isinstance(interaction.user, discord.Member):
        return False
    if interaction.user.id == interaction.guild.owner_id:
        return True
    return any(role.id in STAFF_ROLE_IDS for role in interaction.user.roles)


def require_staff():
    async def predicate(interaction: discord.Interaction) -> bool:
        if is_staff(interaction):
            return True
        if interaction.response.is_done():
            await interaction.followup.send("No tienes permisos.", ephemeral=True)
        else:
            await interaction.response.send_message(
                "No tienes permisos.",
                ephemeral=True,
            )
        return False

    return app_commands.check(predicate)


intents = discord.Intents.none()
intents.guilds = True
