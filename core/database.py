import json

import asyncpg

from core.config import ANTIFRAUD_RETENTION_DAYS, DATABASE_URL


bot_pool: asyncpg.Pool | None = None


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS verification_tokens (
    token_id UUID PRIMARY KEY,
    token_digest CHAR(64) NOT NULL UNIQUE,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued'
        CHECK (status IN ('issued', 'used', 'expired', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS verification_tokens_user_status_idx
    ON verification_tokens (guild_id, user_id, status);
CREATE INDEX IF NOT EXISTS verification_tokens_expiration_idx
    ON verification_tokens (expires_at)
    WHERE status = 'issued';
CREATE UNIQUE INDEX IF NOT EXISTS verification_tokens_one_issued_user_uidx
    ON verification_tokens (guild_id, user_id)
    WHERE status = 'issued';

CREATE TABLE IF NOT EXISTS verification_attempts (
    id BIGSERIAL PRIMARY KEY,
    token_id UUID UNIQUE
        REFERENCES verification_tokens(token_id) ON DELETE SET NULL,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    discord_tag TEXT,
    ip_hash CHAR(64) NOT NULL,
    ip_network_hash CHAR(64),
    fingerprint_hash CHAR(64),
    country_code VARCHAR(2),
    region TEXT,
    timezone TEXT,
    language TEXT,
    browser_family TEXT,
    os_family TEXT,
    device_type TEXT,
    vpn_detected BOOLEAN,
    proxy_detected BOOLEAN,
    hosting_detected BOOLEAN,
    risk_score SMALLINT NOT NULL DEFAULT 0
        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL DEFAULT 'pending'
        CHECK (risk_level IN ('pending', 'low', 'medium', 'high')),
    decision TEXT NOT NULL DEFAULT 'pending'
        CHECK (decision IN ('pending', 'approved', 'review', 'rejected', 'error')),
    role_granted BOOLEAN NOT NULL DEFAULT FALSE,
    possible_main_user_id BIGINT,
    risk_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    consent_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signals JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retention_until TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS verification_attempts_user_idx
    ON verification_attempts (guild_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS verification_attempts_ip_idx
    ON verification_attempts (guild_id, ip_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS verification_attempts_network_idx
    ON verification_attempts (guild_id, ip_network_hash, created_at DESC)
    WHERE ip_network_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS verification_attempts_retention_idx
    ON verification_attempts (retention_until);

CREATE TABLE IF NOT EXISTS verified_users (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    first_verified_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_verified_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_country_code VARCHAR(2),
    status TEXT NOT NULL DEFAULT 'verified'
        CHECK (status IN ('verified', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (guild_id, user_id)
);
CREATE INDEX IF NOT EXISTS verified_users_last_verified_idx
    ON verified_users (guild_id, last_verified_at DESC);

CREATE TABLE IF NOT EXISTS verification_antifraud_signals (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    ip_hash CHAR(64) NOT NULL,
    ip_network_hash CHAR(64) NOT NULL,
    fingerprint_hash CHAR(64) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE (
        guild_id,
        user_id,
        ip_hash,
        ip_network_hash,
        fingerprint_hash
    )
);
CREATE INDEX IF NOT EXISTS verification_antifraud_ip_idx
    ON verification_antifraud_signals (guild_id, ip_hash, expires_at DESC);
CREATE INDEX IF NOT EXISTS verification_antifraud_network_idx
    ON verification_antifraud_signals
    (guild_id, ip_network_hash, expires_at DESC);
CREATE INDEX IF NOT EXISTS verification_antifraud_fingerprint_idx
    ON verification_antifraud_signals
    (guild_id, fingerprint_hash, expires_at DESC);
CREATE INDEX IF NOT EXISTS verification_antifraud_expiration_idx
    ON verification_antifraud_signals (expires_at);
"""


BACKFILL_VERIFIED_USERS_SQL = """
WITH approved AS (
    SELECT
        guild_id,
        user_id,
        country_code,
        created_at,
        MIN(created_at) OVER (
            PARTITION BY guild_id, user_id
        ) AS first_verified_at,
        ROW_NUMBER() OVER (
            PARTITION BY guild_id, user_id
            ORDER BY created_at DESC
        ) AS row_number
    FROM verification_attempts
    WHERE decision='approved' AND role_granted=TRUE
)
INSERT INTO verified_users (
    guild_id,
    user_id,
    first_verified_at,
    last_verified_at,
    last_country_code,
    status
)
SELECT
    guild_id,
    user_id,
    first_verified_at,
    created_at,
    country_code,
    'verified'
FROM approved
WHERE row_number=1
ON CONFLICT (guild_id, user_id) DO UPDATE
SET
    first_verified_at=LEAST(
        verified_users.first_verified_at,
        EXCLUDED.first_verified_at
    ),
    last_country_code=CASE
        WHEN EXCLUDED.last_verified_at >= verified_users.last_verified_at
        THEN COALESCE(
            EXCLUDED.last_country_code,
            verified_users.last_country_code
        )
        ELSE verified_users.last_country_code
    END,
    last_verified_at=GREATEST(
        verified_users.last_verified_at,
        EXCLUDED.last_verified_at
    ),
    status='verified',
    updated_at=CURRENT_TIMESTAMP
"""


BACKFILL_ANTIFRAUD_SQL = """
INSERT INTO verification_antifraud_signals (
    guild_id,
    user_id,
    ip_hash,
    ip_network_hash,
    fingerprint_hash,
    first_seen,
    last_seen,
    expires_at
)
SELECT
    guild_id,
    user_id,
    ip_hash,
    ip_network_hash,
    fingerprint_hash,
    MIN(created_at),
    MAX(created_at),
    MAX(created_at) + ($1::INTEGER * INTERVAL '1 day')
FROM verification_attempts
WHERE decision='approved'
  AND role_granted=TRUE
  AND ip_network_hash IS NOT NULL
  AND fingerprint_hash IS NOT NULL
  AND created_at + ($1::INTEGER * INTERVAL '1 day') > CURRENT_TIMESTAMP
GROUP BY guild_id, user_id, ip_hash, ip_network_hash, fingerprint_hash
ON CONFLICT (
    guild_id,
    user_id,
    ip_hash,
    ip_network_hash,
    fingerprint_hash
) DO UPDATE
SET
    first_seen=LEAST(
        verification_antifraud_signals.first_seen,
        EXCLUDED.first_seen
    ),
    last_seen=GREATEST(
        verification_antifraud_signals.last_seen,
        EXCLUDED.last_seen
    ),
    expires_at=GREATEST(
        verification_antifraud_signals.expires_at,
        EXCLUDED.expires_at
    )
"""


def _pool() -> asyncpg.Pool:
    if bot_pool is None:
        raise RuntimeError("La conexión PostgreSQL no está disponible.")
    return bot_pool


async def init_db() -> None:
    global bot_pool
    if bot_pool is not None:
        return

    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=5,
        command_timeout=30,
    )
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(SCHEMA_SQL)
                await conn.execute(BACKFILL_VERIFIED_USERS_SQL)
                await conn.execute(
                    BACKFILL_ANTIFRAUD_SQL,
                    ANTIFRAUD_RETENTION_DAYS,
                )
                cleanup = await _purge_expired_verification_data(conn)
    except Exception:
        await pool.close()
        raise

    bot_pool = pool
    print("Conexión a Neon PostgreSQL exitosa y tablas verificadas.")
    if any(cleanup.values()):
        print(
            "Retención inicial aplicada: "
            f"{cleanup['attempts']} intento(s), "
            f"{cleanup['tokens']} token(s) y "
            f"{cleanup['antifraud']} señal(es) eliminados."
        )


async def close_db() -> None:
    global bot_pool
    if bot_pool is None:
        return
    pool = bot_pool
    bot_pool = None
    await pool.close()


async def create_verification_token(
    token_id,
    token_digest,
    guild_id,
    user_id,
    expires_at,
):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1::BIGINT)", user_id)
            await conn.execute(
                """
                UPDATE verification_tokens
                SET status = CASE
                    WHEN expires_at <= CURRENT_TIMESTAMP THEN 'expired'
                    ELSE 'revoked'
                END
                WHERE guild_id=$1 AND user_id=$2 AND status='issued'
                """,
                guild_id,
                user_id,
            )
            return await conn.fetchrow(
                """
                INSERT INTO verification_tokens (
                    token_id, token_digest, guild_id, user_id, expires_at
                )
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
                """,
                token_id,
                token_digest,
                guild_id,
                user_id,
                expires_at,
            )


async def revoke_verification_token(token_id, token_digest):
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            UPDATE verification_tokens
            SET status='revoked'
            WHERE token_id=$1 AND token_digest=$2 AND status='issued'
            RETURNING *
            """,
            token_id,
            token_digest,
        )


async def get_verification_submission_counts(guild_id, user_id, ip_hash, since):
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                (
                    SELECT COUNT(*)
                    FROM verification_attempts
                    WHERE guild_id=$1 AND user_id=$2 AND created_at >= $4
                ) AS user_count,
                (
                    SELECT COUNT(*)
                    FROM verification_attempts
                    WHERE guild_id=$1 AND ip_hash=$3 AND created_at >= $4
                ) AS ip_count
            """,
            guild_id,
            user_id,
            ip_hash,
            since,
        )
        return int(row["user_count"]), int(row["ip_count"])


async def record_pending_verification_attempt(
    *,
    token_id,
    token_digest,
    guild_id,
    user_id,
    discord_tag,
    ip_hash,
    ip_network_hash,
    fingerprint_hash,
    country_code,
    region,
    timezone_name,
    language,
    browser_family,
    os_family,
    device_type,
    signals,
    retention_until,
):
    signals_json = json.dumps(
        signals,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    async with _pool().acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE verification_tokens
                SET status='expired'
                WHERE token_id=$1
                  AND token_digest=$2
                  AND status='issued'
                  AND expires_at <= CURRENT_TIMESTAMP
                """,
                token_id,
                token_digest,
            )
            consumed_token = await conn.fetchrow(
                """
                UPDATE verification_tokens
                SET status='used', used_at=CURRENT_TIMESTAMP
                WHERE token_id=$1
                  AND token_digest=$2
                  AND guild_id=$3
                  AND user_id=$4
                  AND status='issued'
                  AND expires_at > CURRENT_TIMESTAMP
                RETURNING token_id
                """,
                token_id,
                token_digest,
                guild_id,
                user_id,
            )
            if consumed_token is None:
                return None

            return await conn.fetchrow(
                """
                INSERT INTO verification_attempts (
                    token_id, guild_id, user_id, discord_tag, ip_hash,
                    ip_network_hash, fingerprint_hash, country_code, region,
                    timezone, language, browser_family, os_family, device_type,
                    signals, retention_until
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15::jsonb, $16
                )
                RETURNING *
                """,
                token_id,
                guild_id,
                user_id,
                discord_tag,
                ip_hash,
                ip_network_hash,
                fingerprint_hash,
                country_code,
                region,
                timezone_name,
                language,
                browser_family,
                os_family,
                device_type,
                signals_json,
                retention_until,
            )


async def get_verification_match_candidates(
    guild_id,
    user_id,
    ip_hash,
    ip_network_hash,
    fingerprint_hash,
    limit=100,
):
    async with _pool().acquire() as conn:
        return await conn.fetch(
            """
            WITH candidates AS (
                SELECT
                    id,
                    user_id,
                    discord_tag,
                    ip_hash,
                    ip_network_hash,
                    fingerprint_hash,
                    country_code,
                    timezone,
                    language,
                    browser_family,
                    os_family,
                    device_type,
                    decision,
                    role_granted,
                    created_at
                FROM verification_attempts
                WHERE guild_id=$1
                  AND user_id<>$2
                  AND retention_until > CURRENT_TIMESTAMP
                  AND decision IN ('pending', 'approved', 'review')
                  AND (
                        ip_hash=$3
                        OR ip_network_hash=$4
                        OR fingerprint_hash=$5
                  )

                UNION ALL

                SELECT
                    antifraud.id,
                    antifraud.user_id,
                    NULL::TEXT AS discord_tag,
                    antifraud.ip_hash,
                    antifraud.ip_network_hash,
                    antifraud.fingerprint_hash,
                    users.last_country_code AS country_code,
                    NULL::TEXT AS timezone,
                    NULL::TEXT AS language,
                    NULL::TEXT AS browser_family,
                    NULL::TEXT AS os_family,
                    NULL::TEXT AS device_type,
                    'approved'::TEXT AS decision,
                    TRUE AS role_granted,
                    antifraud.last_seen AS created_at
                FROM verification_antifraud_signals AS antifraud
                LEFT JOIN verified_users AS users
                  ON users.guild_id=antifraud.guild_id
                 AND users.user_id=antifraud.user_id
                WHERE antifraud.guild_id=$1
                  AND antifraud.user_id<>$2
                  AND antifraud.expires_at > CURRENT_TIMESTAMP
                  AND (
                        antifraud.ip_hash=$3
                        OR antifraud.ip_network_hash=$4
                        OR antifraud.fingerprint_hash=$5
                  )
            )
            SELECT *
            FROM candidates
            ORDER BY created_at ASC
            LIMIT $6
            """,
            guild_id,
            user_id,
            ip_hash,
            ip_network_hash,
            fingerprint_hash,
            limit,
        )


async def finalize_verification_attempt(
    attempt_id,
    *,
    risk_score,
    risk_level,
    decision,
    role_granted,
    possible_main_user_id,
    risk_reasons,
):
    reasons_json = json.dumps(
        risk_reasons,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    async with _pool().acquire() as conn:
        async with conn.transaction():
            updated = await conn.fetchrow(
                """
                UPDATE verification_attempts
                SET risk_score=$2,
                    risk_level=$3,
                    decision=$4,
                    role_granted=$5,
                    possible_main_user_id=$6,
                    risk_reasons=$7::jsonb,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=$1
                RETURNING *
                """,
                attempt_id,
                risk_score,
                risk_level,
                decision,
                role_granted,
                possible_main_user_id,
                reasons_json,
            )
            if updated is None or decision != "approved" or not role_granted:
                return updated

            await conn.execute(
                """
                INSERT INTO verified_users (
                    guild_id,
                    user_id,
                    first_verified_at,
                    last_verified_at,
                    last_country_code,
                    status
                )
                VALUES ($1, $2, $3, $3, $4, 'verified')
                ON CONFLICT (guild_id, user_id) DO UPDATE
                SET
                    first_verified_at=LEAST(
                        verified_users.first_verified_at,
                        EXCLUDED.first_verified_at
                    ),
                    last_verified_at=GREATEST(
                        verified_users.last_verified_at,
                        EXCLUDED.last_verified_at
                    ),
                    last_country_code=COALESCE(
                        EXCLUDED.last_country_code,
                        verified_users.last_country_code
                    ),
                    status='verified',
                    updated_at=CURRENT_TIMESTAMP
                """,
                updated["guild_id"],
                updated["user_id"],
                updated["created_at"],
                updated["country_code"],
            )
            if (
                updated["ip_network_hash"] is not None
                and updated["fingerprint_hash"] is not None
            ):
                await conn.execute(
                    """
                    INSERT INTO verification_antifraud_signals (
                        guild_id,
                        user_id,
                        ip_hash,
                        ip_network_hash,
                        fingerprint_hash,
                        first_seen,
                        last_seen,
                        expires_at
                    )
                    VALUES (
                        $1, $2, $3, $4, $5,
                        $6::TIMESTAMPTZ,
                        $6::TIMESTAMPTZ,
                        $6::TIMESTAMPTZ
                            + ($7::INTEGER * INTERVAL '1 day')
                    )
                    ON CONFLICT (
                        guild_id,
                        user_id,
                        ip_hash,
                        ip_network_hash,
                        fingerprint_hash
                    ) DO UPDATE
                    SET
                        first_seen=LEAST(
                            verification_antifraud_signals.first_seen,
                            EXCLUDED.first_seen
                        ),
                        last_seen=GREATEST(
                            verification_antifraud_signals.last_seen,
                            EXCLUDED.last_seen
                        ),
                        expires_at=GREATEST(
                            verification_antifraud_signals.expires_at,
                            EXCLUDED.expires_at
                        )
                    """,
                    updated["guild_id"],
                    updated["user_id"],
                    updated["ip_hash"],
                    updated["ip_network_hash"],
                    updated["fingerprint_hash"],
                    updated["created_at"],
                    ANTIFRAUD_RETENTION_DAYS,
                )
            return updated


async def clear_verification_records(guild_id, user_id):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1::BIGINT)", user_id)
            deleted_attempts = await conn.fetch(
                """
                DELETE FROM verification_attempts
                WHERE guild_id=$1 AND user_id=$2
                RETURNING id
                """,
                guild_id,
                user_id,
            )
            deleted_tokens = await conn.fetch(
                """
                DELETE FROM verification_tokens
                WHERE guild_id=$1 AND user_id=$2
                RETURNING token_id
                """,
                guild_id,
                user_id,
            )
            deleted_antifraud = await conn.fetch(
                """
                DELETE FROM verification_antifraud_signals
                WHERE guild_id=$1 AND user_id=$2
                RETURNING id
                """,
                guild_id,
                user_id,
            )
            deleted_profile = await conn.fetchrow(
                """
                DELETE FROM verified_users
                WHERE guild_id=$1 AND user_id=$2
                RETURNING user_id
                """,
                guild_id,
                user_id,
            )
            return {
                "attempts": len(deleted_attempts),
                "tokens": len(deleted_tokens),
                "antifraud": len(deleted_antifraud),
                "profiles": int(deleted_profile is not None),
            }


async def _purge_expired_verification_data(conn):
    deleted_attempts = await conn.fetchval(
        """
        WITH deleted AS (
            DELETE FROM verification_attempts
            WHERE retention_until <= CURRENT_TIMESTAMP
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        """
    )
    deleted_antifraud = await conn.fetchval(
        """
        WITH deleted AS (
            DELETE FROM verification_antifraud_signals
            WHERE expires_at <= CURRENT_TIMESTAMP
            RETURNING id
        )
        SELECT COUNT(*) FROM deleted
        """
    )
    deleted_tokens = await conn.fetchval(
        """
        WITH deleted AS (
            DELETE FROM verification_tokens
            WHERE expires_at <= CURRENT_TIMESTAMP
            RETURNING token_id
        )
        SELECT COUNT(*) FROM deleted
        """
    )
    return {
        "attempts": int(deleted_attempts or 0),
        "tokens": int(deleted_tokens or 0),
        "antifraud": int(deleted_antifraud or 0),
    }


async def purge_expired_verification_data():
    async with _pool().acquire() as conn:
        async with conn.transaction():
            return await _purge_expired_verification_data(conn)


async def get_verified_users_count(guild_id):
    async with _pool().acquire() as conn:
        return await conn.fetchval(
            "SELECT COUNT(*) FROM verified_users WHERE guild_id=$1",
            guild_id,
        )


async def get_verified_users_page(guild_id, limit, offset):
    async with _pool().acquire() as conn:
        return await conn.fetch(
            """
            SELECT
                users.guild_id,
                users.user_id,
                users.first_verified_at,
                users.last_verified_at,
                users.last_country_code,
                users.status,
                latest.risk_score,
                latest.risk_level,
                latest.created_at AS latest_attempt_at
            FROM verified_users AS users
            LEFT JOIN LATERAL (
                SELECT risk_score, risk_level, created_at
                FROM verification_attempts
                WHERE guild_id=users.guild_id
                  AND user_id=users.user_id
                  AND decision='approved'
                  AND role_granted=TRUE
                ORDER BY created_at DESC
                LIMIT 1
            ) AS latest ON TRUE
            WHERE users.guild_id=$1
            ORDER BY users.last_verified_at DESC, users.user_id ASC
            LIMIT $2 OFFSET $3
            """,
            guild_id,
            limit,
            offset,
        )
