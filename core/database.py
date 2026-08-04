import hashlib
import json
from contextlib import asynccontextmanager

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

CREATE TABLE IF NOT EXISTS verification_oauth_sessions (
    session_id UUID PRIMARY KEY,
    state_digest CHAR(64) NOT NULL UNIQUE,
    token_id UUID NOT NULL
        REFERENCES verification_tokens(token_id) ON DELETE CASCADE,
    guild_id BIGINT NOT NULL,
    expected_user_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued'
        CHECK (
            status IN (
                'issued', 'processing', 'completed', 'identity_mismatch',
                'expired', 'superseded', 'error'
            )
        ),
    signals JSONB NOT NULL DEFAULT '{}'::jsonb,
    initial_ip_hash CHAR(64) NOT NULL,
    initial_ip_network_hash CHAR(64),
    hash_key_version INTEGER NOT NULL DEFAULT 1,
    oauth_user_id BIGINT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    processing_started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS verification_oauth_sessions_token_idx
    ON verification_oauth_sessions (token_id, created_at DESC);
CREATE INDEX IF NOT EXISTS verification_oauth_sessions_expiration_idx
    ON verification_oauth_sessions (expires_at)
    WHERE status IN ('issued', 'processing');

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
    tor_detected BOOLEAN,
    hosting_detected BOOLEAN,
    datacenter_detected BOOLEAN,
    vpn_check_status TEXT NOT NULL DEFAULT 'not_evaluated'
        CHECK (vpn_check_status IN ('not_evaluated', 'partial', 'completed')),
    vpn_provider_results JSONB NOT NULL DEFAULT '{}'::jsonb,
    vpn_checked_at TIMESTAMP WITH TIME ZONE,
    hash_key_version INTEGER NOT NULL DEFAULT 1,
    risk_score SMALLINT NOT NULL DEFAULT 0
        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL DEFAULT 'pending'
        CHECK (risk_level IN ('pending', 'low', 'medium', 'high')),
    decision TEXT NOT NULL DEFAULT 'pending'
        CHECK (decision IN ('pending', 'approved', 'review', 'rejected', 'error')),
    role_granted BOOLEAN NOT NULL DEFAULT FALSE,
    role_delivery_status TEXT NOT NULL DEFAULT 'not_required'
        CHECK (
            role_delivery_status IN (
                'not_required', 'approved_pending_role', 'processing',
                'granted', 'failed'
            )
        ),
    role_attempts SMALLINT NOT NULL DEFAULT 0,
    role_claimed_at TIMESTAMP WITH TIME ZONE,
    role_next_retry_at TIMESTAMP WITH TIME ZONE,
    role_last_error TEXT,
    role_granted_at TIMESTAMP WITH TIME ZONE,
    user_notified_at TIMESTAMP WITH TIME ZONE,
    staff_notified_at TIMESTAMP WITH TIME ZONE,
    role_error_notified_at TIMESTAMP WITH TIME ZONE,
    possible_main_user_id BIGINT,
    manual_review_required BOOLEAN NOT NULL DEFAULT FALSE,
    manual_review_status TEXT NOT NULL DEFAULT 'not_required'
        CHECK (
            manual_review_status IN (
                'not_required', 'pending', 'processing', 'accepted', 'rejected'
            )
        ),
    reviewed_by BIGINT,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    staff_channel_id BIGINT,
    staff_message_id BIGINT,
    appeal_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    false_positive BOOLEAN NOT NULL DEFAULT FALSE,
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


MIGRATION_SQL = """
ALTER TABLE verification_attempts
    ADD COLUMN IF NOT EXISTS tor_detected BOOLEAN,
    ADD COLUMN IF NOT EXISTS datacenter_detected BOOLEAN,
    ADD COLUMN IF NOT EXISTS vpn_check_status TEXT NOT NULL DEFAULT 'not_evaluated',
    ADD COLUMN IF NOT EXISTS vpn_provider_results JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS vpn_checked_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS hash_key_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS manual_review_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS manual_review_status TEXT NOT NULL DEFAULT 'not_required',
    ADD COLUMN IF NOT EXISTS reviewed_by BIGINT,
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS staff_channel_id BIGINT,
    ADD COLUMN IF NOT EXISTS staff_message_id BIGINT,
    ADD COLUMN IF NOT EXISTS appeal_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS false_positive BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS role_delivery_status TEXT NOT NULL DEFAULT 'not_required',
    ADD COLUMN IF NOT EXISTS role_attempts SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS role_claimed_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS role_next_retry_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS role_last_error TEXT,
    ADD COLUMN IF NOT EXISTS role_granted_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS user_notified_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS staff_notified_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS role_error_notified_at TIMESTAMP WITH TIME ZONE;
UPDATE verification_attempts
SET role_delivery_status='granted',
    role_granted_at=COALESCE(role_granted_at, updated_at),
    user_notified_at=COALESCE(user_notified_at, updated_at),
    staff_notified_at=COALESCE(staff_notified_at, updated_at)
WHERE decision='approved'
  AND role_granted=TRUE
  AND role_delivery_status='not_required';
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname='verification_attempts_role_delivery_status_check'
    ) THEN
        ALTER TABLE verification_attempts
        ADD CONSTRAINT verification_attempts_role_delivery_status_check
        CHECK (
            role_delivery_status IN (
                'not_required', 'approved_pending_role', 'processing',
                'granted', 'failed'
            )
        );
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS verification_attempts_manual_review_idx
    ON verification_attempts (manual_review_status, created_at DESC)
    WHERE manual_review_required=TRUE;
CREATE INDEX IF NOT EXISTS verification_attempts_role_delivery_idx
    ON verification_attempts (role_delivery_status, role_next_retry_at, id)
    WHERE role_delivery_status IN (
        'approved_pending_role', 'processing', 'failed'
    );
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


@asynccontextmanager
async def _connection(conn: asyncpg.Connection | None = None):
    if conn is not None:
        yield conn
        return
    async with _pool().acquire() as acquired:
        yield acquired


def _advisory_lock_key(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("ascii"),
        digest_size=8,
        person=b"verify-lock-v1",
    ).digest()
    return int.from_bytes(digest, "big", signed=True)


@asynccontextmanager
async def verification_signal_transaction(
    ip_hash: str,
    ip_network_hash: str | None,
):
    values = {value for value in (ip_hash, ip_network_hash) if value}
    lock_keys = sorted(_advisory_lock_key(value) for value in values)
    async with _pool().acquire() as conn:
        async with conn.transaction():
            for lock_key in lock_keys:
                await conn.execute(
                    "SELECT pg_advisory_xact_lock($1::BIGINT)",
                    lock_key,
                )
            yield conn


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
                await conn.execute(MIGRATION_SQL)
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
            f"{cleanup['oauth']} sesión(es) OAuth, "
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


async def create_oauth_session(
    *,
    session_id,
    state_digest,
    token_id,
    token_digest,
    guild_id,
    expected_user_id,
    signals,
    initial_ip_hash,
    initial_ip_network_hash,
    hash_key_version,
    expires_at,
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
                "SELECT pg_advisory_xact_lock($1::BIGINT)",
                expected_user_id,
            )
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
            valid_token = await conn.fetchrow(
                """
                SELECT expires_at
                FROM verification_tokens
                WHERE token_id=$1
                  AND token_digest=$2
                  AND guild_id=$3
                  AND user_id=$4
                  AND status='issued'
                  AND expires_at > CURRENT_TIMESTAMP
                FOR UPDATE
                """,
                token_id,
                token_digest,
                guild_id,
                expected_user_id,
            )
            if valid_token is None:
                return None

            await conn.execute(
                """
                UPDATE verification_oauth_sessions
                SET status='superseded',
                    completed_at=CURRENT_TIMESTAMP
                WHERE token_id=$1
                  AND status IN ('issued', 'processing')
                """,
                token_id,
            )
            return await conn.fetchrow(
                """
                INSERT INTO verification_oauth_sessions (
                    session_id, state_digest, token_id, guild_id,
                    expected_user_id, signals, initial_ip_hash,
                    initial_ip_network_hash, hash_key_version, expires_at
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9,
                    LEAST($10::TIMESTAMPTZ, $11::TIMESTAMPTZ)
                )
                RETURNING *
                """,
                session_id,
                state_digest,
                token_id,
                guild_id,
                expected_user_id,
                signals_json,
                initial_ip_hash,
                initial_ip_network_hash,
                hash_key_version,
                expires_at,
                valid_token["expires_at"],
            )


async def claim_oauth_session(state_digest):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE verification_oauth_sessions
                SET status='expired',
                    completed_at=CURRENT_TIMESTAMP
                WHERE state_digest=$1
                  AND status='issued'
                  AND expires_at <= CURRENT_TIMESTAMP
                """,
                state_digest,
            )
            return await conn.fetchrow(
                """
                UPDATE verification_oauth_sessions AS oauth
                SET status='processing',
                    processing_started_at=CURRENT_TIMESTAMP,
                    last_error=NULL
                FROM verification_tokens AS token
                WHERE oauth.state_digest=$1
                  AND oauth.status='issued'
                  AND oauth.expires_at > CURRENT_TIMESTAMP
                  AND token.token_id=oauth.token_id
                  AND token.status='issued'
                  AND token.expires_at > CURRENT_TIMESTAMP
                RETURNING oauth.*, token.token_digest,
                          token.expires_at AS token_expires_at
                """,
                state_digest,
            )


async def complete_oauth_session(
    session_id,
    status,
    *,
    oauth_user_id=None,
    last_error=None,
):
    allowed_statuses = {
        "completed",
        "identity_mismatch",
        "expired",
        "error",
    }
    if status not in allowed_statuses:
        raise ValueError("Estado final OAuth invalido.")
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            UPDATE verification_oauth_sessions
            SET status=$2,
                oauth_user_id=$3,
                completed_at=CURRENT_TIMESTAMP,
                last_error=$4
            WHERE session_id=$1 AND status='processing'
            RETURNING *
            """,
            session_id,
            status,
            oauth_user_id,
            (last_error or "")[:500] or None,
        )


async def get_oauth_start_counts(
    guild_id,
    expected_user_id,
    initial_ip_hashes,
    since,
):
    if isinstance(initial_ip_hashes, str):
        initial_ip_hashes = (initial_ip_hashes,)
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE expected_user_id=$2
                      AND status NOT IN ('superseded', 'error', 'expired')
                ) AS user_count,
                COUNT(DISTINCT expected_user_id) FILTER (
                    WHERE initial_ip_hash::TEXT=ANY($3::TEXT[])
                      AND status NOT IN ('superseded', 'error', 'expired')
                ) AS ip_count
            FROM verification_oauth_sessions
            WHERE guild_id=$1 AND created_at >= $4
            """,
            guild_id,
            expected_user_id,
            list(initial_ip_hashes),
            since,
        )
        return int(row["user_count"]), int(row["ip_count"])


async def get_verification_submission_counts(
    guild_id,
    user_id,
    ip_hashes,
    since,
    *,
    conn=None,
):
    if isinstance(ip_hashes, str):
        ip_hashes = (ip_hashes,)
    async with _connection(conn) as active_conn:
        row = await active_conn.fetchrow(
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
                    WHERE guild_id=$1
                      AND ip_hash::TEXT=ANY($3::TEXT[])
                      AND created_at >= $4
                ) AS ip_count
            """,
            guild_id,
            user_id,
            list(ip_hashes),
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
    hash_key_version=1,
    vpn_check_status="not_evaluated",
    vpn_provider_results=None,
    vpn_checked_at=None,
    vpn_signal_types=(),
    vpn_detected=False,
    conn=None,
):
    signals_json = json.dumps(
        signals,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    provider_results_json = json.dumps(
        vpn_provider_results or {},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    signal_types = set(vpn_signal_types)
    async with _connection(conn) as active_conn:
        async with active_conn.transaction():
            await active_conn.execute(
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
            consumed_token = await active_conn.fetchrow(
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

            return await active_conn.fetchrow(
                """
                INSERT INTO verification_attempts (
                    token_id, guild_id, user_id, discord_tag, ip_hash,
                    ip_network_hash, fingerprint_hash, country_code, region,
                    timezone, language, browser_family, os_family, device_type,
                    signals, retention_until, hash_key_version,
                    vpn_detected, proxy_detected, tor_detected,
                    hosting_detected, datacenter_detected,
                    vpn_check_status, vpn_provider_results, vpn_checked_at
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15::jsonb, $16, $17,
                    $18, $19, $20, $21, $22, $23, $24::jsonb, $25
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
                hash_key_version,
                vpn_detected or "vpn" in signal_types,
                "proxy" in signal_types,
                "tor" in signal_types,
                "hosting" in signal_types,
                "datacenter" in signal_types,
                vpn_check_status,
                provider_results_json,
                vpn_checked_at,
            )


async def get_verification_match_candidates(
    guild_id,
    user_id,
    ip_hashes,
    ip_network_hashes,
    fingerprint_hashes,
    limit=100,
    *,
    conn=None,
):
    async with _connection(conn) as active_conn:
        return await active_conn.fetch(
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
                    created_at,
                    ip_hash::TEXT=ANY($3::TEXT[]) AS exact_ip_match,
                    ip_network_hash::TEXT=ANY($4::TEXT[]) AS network_match,
                    fingerprint_hash::TEXT=ANY($5::TEXT[]) AS fingerprint_match
                FROM verification_attempts
                WHERE guild_id=$1
                  AND user_id<>$2
                  AND retention_until > CURRENT_TIMESTAMP
                  AND decision='approved'
                  AND role_granted=TRUE
                  AND (
                        ip_hash::TEXT=ANY($3::TEXT[])
                        OR ip_network_hash::TEXT=ANY($4::TEXT[])
                        OR fingerprint_hash::TEXT=ANY($5::TEXT[])
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
                    antifraud.last_seen AS created_at,
                    antifraud.ip_hash::TEXT=ANY($3::TEXT[]) AS exact_ip_match,
                    antifraud.ip_network_hash::TEXT=ANY($4::TEXT[]) AS network_match,
                    antifraud.fingerprint_hash::TEXT=ANY($5::TEXT[]) AS fingerprint_match
                FROM verification_antifraud_signals AS antifraud
                LEFT JOIN verified_users AS users
                  ON users.guild_id=antifraud.guild_id
                 AND users.user_id=antifraud.user_id
                WHERE antifraud.guild_id=$1
                  AND antifraud.user_id<>$2
                  AND antifraud.expires_at > CURRENT_TIMESTAMP
                  AND (
                        antifraud.ip_hash::TEXT=ANY($3::TEXT[])
                        OR antifraud.ip_network_hash::TEXT=ANY($4::TEXT[])
                        OR antifraud.fingerprint_hash::TEXT=ANY($5::TEXT[])
                  )
            )
            SELECT *
            FROM candidates
            ORDER BY created_at DESC
            LIMIT $6
            """,
            guild_id,
            user_id,
            list(ip_hashes),
            list(ip_network_hashes),
            list(fingerprint_hashes),
            limit,
        )


async def _persist_approved_verification(conn, updated) -> None:
    await conn.execute(
        """
        INSERT INTO verified_users (
            guild_id, user_id, first_verified_at, last_verified_at,
            last_country_code, status
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
        updated["ip_network_hash"] is None
        or updated["fingerprint_hash"] is None
    ):
        return
    await conn.execute(
        """
        INSERT INTO verification_antifraud_signals (
            guild_id, user_id, ip_hash, ip_network_hash, fingerprint_hash,
            first_seen, last_seen, expires_at
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6::TIMESTAMPTZ,
            $6::TIMESTAMPTZ,
            $6::TIMESTAMPTZ + ($7::INTEGER * INTERVAL '1 day')
        )
        ON CONFLICT (
            guild_id, user_id, ip_hash, ip_network_hash, fingerprint_hash
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


async def finalize_verification_attempt(
    attempt_id,
    *,
    risk_score,
    risk_level,
    decision,
    role_granted,
    possible_main_user_id,
    risk_reasons,
    manual_review_required=False,
    manual_review_status="not_required",
    conn=None,
):
    reasons_json = json.dumps(
        risk_reasons,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    async with _connection(conn) as active_conn:
        async with active_conn.transaction():
            updated = await active_conn.fetchrow(
                """
                UPDATE verification_attempts
                SET risk_score=$2,
                    risk_level=$3,
                    decision=$4,
                    role_granted=$5,
                    possible_main_user_id=$6,
                    risk_reasons=$7::jsonb,
                    manual_review_required=$8,
                    manual_review_status=$9,
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
                manual_review_required,
                manual_review_status,
            )
            if updated is None or decision != "approved" or not role_granted:
                return updated
            await _persist_approved_verification(active_conn, updated)
            return updated


async def queue_approved_role_delivery(
    attempt_id,
    *,
    risk_score,
    risk_level,
    possible_main_user_id,
    risk_reasons,
    conn=None,
):
    reasons_json = json.dumps(
        risk_reasons,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    async with _connection(conn) as active_conn:
        return await active_conn.fetchrow(
            """
            UPDATE verification_attempts
            SET risk_score=$2,
                risk_level=$3,
                decision='pending',
                role_granted=FALSE,
                role_delivery_status='approved_pending_role',
                role_next_retry_at=CURRENT_TIMESTAMP,
                role_last_error=NULL,
                possible_main_user_id=$4,
                risk_reasons=$5::jsonb,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=$1
              AND decision='pending'
              AND role_delivery_status='not_required'
            RETURNING *
            """,
            attempt_id,
            risk_score,
            risk_level,
            possible_main_user_id,
            reasons_json,
        )


async def claim_pending_role_delivery(attempt_id=None):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT id
                FROM verification_attempts
                WHERE ($1::BIGINT IS NULL OR id=$1)
                  AND (
                        (
                            role_delivery_status IN (
                                'approved_pending_role', 'failed'
                            )
                            AND COALESCE(
                                role_next_retry_at,
                                CURRENT_TIMESTAMP
                            ) <= CURRENT_TIMESTAMP
                        )
                        OR (
                            role_delivery_status='processing'
                            AND role_claimed_at < (
                                CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                            )
                        )
                  )
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                attempt_id,
            )
            if row is None:
                return None
            return await conn.fetchrow(
                """
                UPDATE verification_attempts
                SET role_delivery_status='processing',
                    role_attempts=LEAST(role_attempts + 1, 32767),
                    role_claimed_at=CURRENT_TIMESTAMP,
                    role_last_error=NULL,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=$1
                RETURNING *
                """,
                row["id"],
            )


async def recover_role_deliveries_on_startup():
    async with _pool().acquire() as conn:
        result = await conn.execute(
            """
            UPDATE verification_attempts
            SET role_delivery_status=CASE
                    WHEN role_delivery_status='processing'
                    THEN 'approved_pending_role'
                    ELSE role_delivery_status
                END,
                role_claimed_at=NULL,
                role_next_retry_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE role_delivery_status IN ('processing', 'failed')
            """
        )
    return int(result.rsplit(" ", 1)[-1])


async def complete_role_delivery(attempt_id):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            updated = await conn.fetchrow(
                """
                UPDATE verification_attempts
                SET decision='approved',
                    role_granted=TRUE,
                    role_delivery_status='granted',
                    role_granted_at=COALESCE(
                        role_granted_at,
                        CURRENT_TIMESTAMP
                    ),
                    role_claimed_at=NULL,
                    role_next_retry_at=NULL,
                    role_last_error=NULL,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=$1
                  AND role_delivery_status='processing'
                RETURNING *
                """,
                attempt_id,
            )
            if updated is not None:
                await _persist_approved_verification(conn, updated)
            return updated


async def reschedule_role_delivery(
    attempt_id,
    error,
    *,
    retry_after_seconds,
    permanent=False,
):
    status = "failed" if permanent else "approved_pending_role"
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            UPDATE verification_attempts
            SET role_delivery_status=$2,
                role_claimed_at=NULL,
                role_next_retry_at=(
                    CURRENT_TIMESTAMP
                    + ($3::INTEGER * INTERVAL '1 second')
                ),
                role_last_error=$4,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=$1
              AND role_delivery_status='processing'
            RETURNING *
            """,
            attempt_id,
            status,
            max(1, int(retry_after_seconds)),
            str(error)[:1000],
        )


async def mark_role_notification(attempt_id, audience):
    columns = {
        "user": "user_notified_at",
        "staff": "staff_notified_at",
        "error": "role_error_notified_at",
    }
    column = columns.get(audience)
    if column is None:
        raise ValueError("Audiencia de notificacion invalida.")
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            f"""
            UPDATE verification_attempts
            SET {column}=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=$1 AND {column} IS NULL
            RETURNING *
            """,
            attempt_id,
        )


async def get_unnotified_approved_role_deliveries(limit=25):
    async with _pool().acquire() as conn:
        return await conn.fetch(
            """
            SELECT *
            FROM verification_attempts
            WHERE role_delivery_status='granted'
              AND decision='approved'
              AND role_granted=TRUE
              AND (
                    user_notified_at IS NULL
                    OR staff_notified_at IS NULL
              )
            ORDER BY role_granted_at ASC NULLS FIRST
            LIMIT $1
            """,
            max(1, min(int(limit), 100)),
        )


async def save_manual_review_message(
    attempt_id,
    channel_id,
    message_id,
):
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            UPDATE verification_attempts
            SET staff_channel_id=$2,
                staff_message_id=$3,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=$1
              AND manual_review_status='pending'
            RETURNING *
            """,
            attempt_id,
            channel_id,
            message_id,
        )


async def get_pending_manual_reviews():
    async with _pool().acquire() as conn:
        return await conn.fetch(
            """
            SELECT *
            FROM verification_attempts
            WHERE manual_review_required=TRUE
              AND manual_review_status='pending'
              AND staff_channel_id IS NOT NULL
              AND staff_message_id IS NOT NULL
            ORDER BY created_at ASC
            """
        )


async def recover_incomplete_manual_reviews():
    async with _pool().acquire() as conn:
        result = await conn.execute(
            """
            UPDATE verification_attempts
            SET manual_review_status='pending',
                reviewed_by=NULL,
                updated_at=CURRENT_TIMESTAMP
            WHERE manual_review_status='processing'
            """
        )
    return int(result.rsplit(" ", 1)[-1])


async def claim_manual_review(attempt_id, reviewer_id):
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            UPDATE verification_attempts
            SET manual_review_status='processing',
                reviewed_by=$2,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=$1 AND manual_review_status='pending'
            RETURNING *
            """,
            attempt_id,
            reviewer_id,
        )


async def release_manual_review_claim(attempt_id, reviewer_id):
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            UPDATE verification_attempts
            SET manual_review_status='pending',
                reviewed_by=NULL,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=$1
              AND manual_review_status='processing'
              AND reviewed_by=$2
            RETURNING *
            """,
            attempt_id,
            reviewer_id,
        )


async def complete_manual_review(
    attempt_id,
    reviewer_id,
    *,
    accepted,
):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            status = "accepted" if accepted else "rejected"
            decision = "review" if accepted else "rejected"
            delivery_status = (
                "approved_pending_role" if accepted else "not_required"
            )
            updated = await conn.fetchrow(
                """
                UPDATE verification_attempts
                SET manual_review_status=$3,
                    decision=$4,
                    role_granted=FALSE,
                    role_delivery_status=$5,
                    role_next_retry_at=CASE
                        WHEN $6::BOOLEAN THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END,
                    role_last_error=NULL,
                    reviewed_at=CURRENT_TIMESTAMP,
                    false_positive=$6,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=$1
                  AND manual_review_status='processing'
                  AND reviewed_by=$2
                RETURNING *
                """,
                attempt_id,
                reviewer_id,
                status,
                decision,
                delivery_status,
                accepted,
            )
            return updated


async def get_monthly_verification_metrics(guild_id, month_start, month_end):
    async with _pool().acquire() as conn:
        return await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE decision='approved') AS approved,
                COUNT(*) FILTER (WHERE manual_review_required=TRUE) AS reviewed,
                COUNT(*) FILTER (WHERE decision='rejected') AS rejected,
                COUNT(*) FILTER (
                    WHERE vpn_detected IS TRUE
                       OR proxy_detected IS TRUE
                       OR tor_detected IS TRUE
                ) AS vpn_detected,
                COUNT(*) FILTER (WHERE appeal_accepted=TRUE) AS appeals_accepted,
                COUNT(*) FILTER (WHERE false_positive=TRUE) AS false_positives,
                COUNT(*) AS total
            FROM verification_attempts
            WHERE guild_id=$1
              AND created_at >= $2
              AND created_at < $3
            """,
            guild_id,
            month_start,
            month_end,
        )


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
    deleted_oauth = await conn.fetchval(
        """
        WITH deleted AS (
            DELETE FROM verification_oauth_sessions
            WHERE expires_at <= (CURRENT_TIMESTAMP - INTERVAL '1 day')
            RETURNING session_id
        )
        SELECT COUNT(*) FROM deleted
        """
    )
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
        "oauth": int(deleted_oauth or 0),
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
