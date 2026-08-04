import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from core import database


class _AsyncContext:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, _exc_type, _exc, _traceback):
        return False


class _FakeConnection:
    def __init__(self, token_status, token_expiration):
        self.rows = [
            {"status": token_status, "expires_at": token_expiration},
            {"token_id": uuid4()},
        ]
        self.insert_arguments = None

    def transaction(self):
        return _AsyncContext()

    async def execute(self, _query, *args):
        return "OK"

    async def fetchrow(self, query, *args):
        if "INSERT INTO verification_oauth_sessions" in query:
            self.insert_arguments = args
            return {
                "session_id": args[0],
                "expires_at": args[-1],
            }
        return self.rows.pop(0)


class _FakePool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return _AsyncContext(self.connection)


class OAuthTokenReservationTests(unittest.IsolatedAsyncioTestCase):
    async def _create_session(self, status, stored_expiration, requested_expiration):
        connection = _FakeConnection(status, stored_expiration)
        with patch("core.database.bot_pool", _FakePool(connection)):
            session = await database.create_oauth_session(
                session_id=uuid4(),
                state_digest="a" * 64,
                token_id=uuid4(),
                token_digest="b" * 64,
                guild_id=1,
                expected_user_id=2,
                signals={},
                initial_ip_hash="c" * 64,
                initial_ip_network_hash="d" * 64,
                hash_key_version=1,
                expires_at=requested_expiration,
            )
        return connection, session

    async def test_first_start_receives_a_complete_oauth_window(self):
        now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
        link_expiration = now + timedelta(minutes=1)
        oauth_expiration = now + timedelta(minutes=10)

        connection, session = await self._create_session(
            "issued",
            link_expiration,
            oauth_expiration,
        )

        self.assertEqual(session["expires_at"], oauth_expiration)
        self.assertEqual(connection.insert_arguments[-1], oauth_expiration)

    async def test_retry_reuses_reservation_without_extending_it(self):
        now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
        reserved_expiration = now + timedelta(minutes=6)
        requested_expiration = now + timedelta(minutes=10)

        connection, session = await self._create_session(
            "in_progress",
            reserved_expiration,
            requested_expiration,
        )

        self.assertEqual(session["expires_at"], reserved_expiration)
        self.assertEqual(connection.insert_arguments[-1], reserved_expiration)


if __name__ == "__main__":
    unittest.main()
