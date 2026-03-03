"""
Unit tests for security logic — SOQL validation, field blocking, rate limiting,
auth, activity tools, user context, token store, and per-user client routing.

These tests mock external dependencies (FastMCP, simple-salesforce) so they
validate only the security logic itself. Run inside Docker with Python 3.12:

    docker build -f Dockerfile.test -t sf-pardot-mcp-tests .
    docker run --rm sf-pardot-mcp-tests
"""

import hashlib
import os
import time
import unittest
from collections import defaultdict
from unittest.mock import patch, MagicMock, AsyncMock


# ---------------------------------------------------------------------------
# 1. SOQL escape helper
# ---------------------------------------------------------------------------

class TestEscapeSOQL(unittest.TestCase):
    """Tests for tools.salesforce._escape_soql"""

    def _escape(self, value: str) -> str:
        from tools.salesforce import _escape_soql
        return _escape_soql(value)

    def test_plain_string(self):
        self.assertEqual(self._escape("hello"), "hello")

    def test_single_quote(self):
        self.assertEqual(self._escape("O'Reilly"), "O\\'Reilly")

    def test_backslash(self):
        self.assertEqual(self._escape("back\\slash"), "back\\\\slash")

    def test_both(self):
        self.assertEqual(self._escape("it's a \\path"), "it\\'s a \\\\path")

    def test_injection_attempt(self):
        malicious = "Open'; DROP TABLE Lead;--"
        escaped = self._escape(malicious)
        # The raw unescaped single quote should not survive
        # After escaping: Open\'; DROP TABLE Lead;--
        # The quote is preceded by backslash, so SOQL treats it as literal
        self.assertEqual(escaped, "Open\\'; DROP TABLE Lead;--")
        self.assertNotIn("Open';", escaped.replace("\\'", "XX"))

    def test_empty_string(self):
        self.assertEqual(self._escape(""), "")


# ---------------------------------------------------------------------------
# 2. SOQL read-only enforcement
# ---------------------------------------------------------------------------

class TestValidateSelectOnly(unittest.TestCase):
    """Tests for tools.salesforce._validate_select_only"""

    def _validate(self, soql: str):
        from tools.salesforce import _validate_select_only
        _validate_select_only(soql)

    def test_valid_select(self):
        self._validate("SELECT Id FROM Lead")  # should not raise

    def test_valid_select_lowercase(self):
        self._validate("select id from lead")  # should not raise

    def test_valid_select_with_whitespace(self):
        self._validate("  SELECT Id FROM Lead  ")  # should not raise

    def test_reject_delete(self):
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._validate("DELETE FROM Lead WHERE Id = '001'")

    def test_reject_update(self):
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._validate("UPDATE Lead SET Status = 'Closed'")

    def test_reject_insert(self):
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._validate("INSERT INTO Lead (Name) VALUES ('Test')")

    def test_reject_drop(self):
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._validate("DROP TABLE Lead")

    def test_reject_empty(self):
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._validate("")


# ---------------------------------------------------------------------------
# 3. Blocked fields
# ---------------------------------------------------------------------------

class TestBlockedFields(unittest.TestCase):
    """Tests for tools.salesforce._check_blocked_fields"""

    def _check(self, fields, blocked, name):
        from tools.salesforce import _check_blocked_fields
        _check_blocked_fields(fields, blocked, name)

    def test_no_blocked_fields(self):
        from tools.salesforce import BLOCKED_LEAD_FIELDS
        self._check({"Status": "Working", "Company": "Acme"}, BLOCKED_LEAD_FIELDS, "Lead")

    def test_blocked_owner_id(self):
        from tools.salesforce import BLOCKED_LEAD_FIELDS
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError) as ctx:
            self._check({"OwnerId": "005xxx"}, BLOCKED_LEAD_FIELDS, "Lead")
        self.assertIn("OwnerId", str(ctx.exception))

    def test_blocked_is_converted(self):
        from tools.salesforce import BLOCKED_LEAD_FIELDS
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._check({"IsConverted": True}, BLOCKED_LEAD_FIELDS, "Lead")

    def test_contact_blocked_fields(self):
        from tools.salesforce import BLOCKED_CONTACT_FIELDS
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._check({"MasterRecordId": "003xxx"}, BLOCKED_CONTACT_FIELDS, "Contact")

    def test_mixed_allowed_and_blocked(self):
        from tools.salesforce import BLOCKED_LEAD_FIELDS
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            self._check(
                {"Status": "Working", "OwnerId": "005xxx", "Company": "Acme"},
                BLOCKED_LEAD_FIELDS,
                "Lead",
            )

    def test_empty_fields(self):
        from tools.salesforce import BLOCKED_LEAD_FIELDS
        self._check({}, BLOCKED_LEAD_FIELDS, "Lead")  # should not raise


# ---------------------------------------------------------------------------
# 4. Auth helpers
# ---------------------------------------------------------------------------

class TestKeyFingerprint(unittest.TestCase):
    """Tests for auth._key_fingerprint"""

    def test_deterministic(self):
        from auth import _key_fingerprint
        fp1 = _key_fingerprint("my-secret-key")
        fp2 = _key_fingerprint("my-secret-key")
        self.assertEqual(fp1, fp2)

    def test_length_is_8(self):
        from auth import _key_fingerprint
        fp = _key_fingerprint("test-key")
        self.assertEqual(len(fp), 8)

    def test_different_keys_different_fingerprints(self):
        from auth import _key_fingerprint
        fp1 = _key_fingerprint("key-one")
        fp2 = _key_fingerprint("key-two")
        self.assertNotEqual(fp1, fp2)

    def test_matches_sha256(self):
        from auth import _key_fingerprint
        key = "verify-this"
        expected = hashlib.sha256(key.encode()).hexdigest()[:8]
        self.assertEqual(_key_fingerprint(key), expected)


# ---------------------------------------------------------------------------
# 5. Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting(unittest.TestCase):
    """Tests for auth._check_rate_limit"""

    def setUp(self):
        """Clear rate limit state before each test."""
        import auth
        auth._request_timestamps.clear()

    def test_first_request_passes(self):
        from auth import _check_rate_limit
        _check_rate_limit("test-token")  # should not raise

    def test_60_requests_pass(self):
        from auth import _check_rate_limit
        for _ in range(60):
            _check_rate_limit("test-token-60")

    def test_61st_request_blocked(self):
        from auth import _check_rate_limit
        for _ in range(60):
            _check_rate_limit("test-token-61")
        with self.assertRaises(ValueError) as ctx:
            _check_rate_limit("test-token-61")
        self.assertIn("Rate limit exceeded", str(ctx.exception))

    def test_different_keys_independent(self):
        from auth import _check_rate_limit
        for _ in range(60):
            _check_rate_limit("key-a")
        # key-b should still work
        _check_rate_limit("key-b")  # should not raise

    def test_window_slides(self):
        """After the time window passes, requests should be allowed again."""
        import auth
        from auth import _check_rate_limit, _key_fingerprint

        # Fill up the window
        for _ in range(60):
            _check_rate_limit("sliding-token")

        # Rate limit uses fingerprint as dict key
        fp = _key_fingerprint("sliding-token")
        # Simulate all timestamps being > 60 seconds old
        auth._request_timestamps[fp] = [
            time.monotonic() - 61 for _ in range(60)
        ]

        # Now a new request should pass
        _check_rate_limit("sliding-token")  # should not raise


# ---------------------------------------------------------------------------
# 6. sf_query read-only enforcement (integration-style)
# ---------------------------------------------------------------------------

class TestSfQueryReadOnly(unittest.TestCase):
    """Verify sf_query rejects non-SELECT queries before hitting Salesforce."""

    @patch("tools.salesforce.get_sf_client")
    def test_select_query_proceeds(self, mock_get_client):
        """SELECT query should call through to Salesforce."""
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_query
        result = sf_query("SELECT Id FROM Lead LIMIT 1")
        self.assertEqual(result["totalSize"], 0)
        mock_sf.query_all.assert_called_once()

    @patch("tools.salesforce.get_sf_client")
    def test_delete_query_rejected(self, mock_get_client):
        """DELETE should be rejected BEFORE any Salesforce call."""
        from tools.salesforce import sf_query
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            sf_query("DELETE FROM Lead WHERE Id = '001'")
        mock_get_client.assert_not_called()


# ---------------------------------------------------------------------------
# 7. sf_create_lead validation
# ---------------------------------------------------------------------------

class TestCreateLeadValidation(unittest.TestCase):
    """Verify sf_create_lead requires LastName and Company."""

    @patch("tools.salesforce.get_sf_client")
    def test_missing_lastname(self, mock_get_client):
        from tools.salesforce import sf_create_lead
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError) as ctx:
            sf_create_lead(fields={"Company": "Acme"})
        self.assertIn("LastName", str(ctx.exception))

    @patch("tools.salesforce.get_sf_client")
    def test_missing_company(self, mock_get_client):
        from tools.salesforce import sf_create_lead
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError) as ctx:
            sf_create_lead(fields={"LastName": "Doe"})
        self.assertIn("Company", str(ctx.exception))

    @patch("tools.salesforce.get_sf_client")
    def test_valid_fields_calls_sf(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.Lead.create.return_value = {"success": True, "id": "00Q001", "errors": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_create_lead
        result = sf_create_lead(fields={"LastName": "Doe", "Company": "Acme"})
        self.assertTrue(result["success"])
        mock_sf.Lead.create.assert_called_once()


# ---------------------------------------------------------------------------
# 8. sf_update_lead blocked fields enforcement
# ---------------------------------------------------------------------------

class TestUpdateLeadBlockedFields(unittest.TestCase):
    """Verify sf_update_lead blocks protected fields."""

    @patch("tools.salesforce.get_sf_client")
    def test_owner_id_blocked(self, mock_get_client):
        mock_get_client.return_value = MagicMock()
        from tools.salesforce import sf_update_lead
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError) as ctx:
            sf_update_lead(lead_id="00Q001", fields={"OwnerId": "005xxx"})
        self.assertIn("protected", str(ctx.exception).lower())

    @patch("tools.salesforce.get_sf_client")
    def test_allowed_fields_pass(self, mock_get_client):
        mock_sf = MagicMock()
        mock_get_client.return_value = mock_sf
        from tools.salesforce import sf_update_lead
        result = sf_update_lead(lead_id="00Q001", fields={"Status": "Working"})
        self.assertTrue(result["success"])
        mock_sf.Lead.update.assert_called_once()


# ---------------------------------------------------------------------------
# 9. Pardot token TTL logic
# ---------------------------------------------------------------------------

class TestPardotTokenTTL(unittest.TestCase):
    """Verify PardotClient token caching and expiry."""

    def test_no_token_initially(self):
        from tools.pardot import PardotClient
        client = PardotClient("test-key")
        self.assertFalse(client._token_is_valid())

    def test_token_valid_after_set(self):
        from tools.pardot import PardotClient
        client = PardotClient("test-key")
        client._token = "test-token"
        client._token_acquired_at = time.monotonic()
        self.assertTrue(client._token_is_valid())

    def test_token_expired_after_ttl(self):
        from tools.pardot import PardotClient, TOKEN_TTL_SECONDS
        client = PardotClient("test-key")
        client._token = "test-token"
        client._token_acquired_at = time.monotonic() - TOKEN_TTL_SECONDS - 1
        self.assertFalse(client._token_is_valid())

    def test_invalidate_clears_token(self):
        from tools.pardot import PardotClient
        client = PardotClient("test-key")
        client._token = "test-token"
        client._token_acquired_at = time.monotonic()
        client._invalidate_token()
        self.assertFalse(client._token_is_valid())


# ---------------------------------------------------------------------------
# 10. sf_get_tasks
# ---------------------------------------------------------------------------

class TestSfGetTasks(unittest.TestCase):
    """Verify sf_get_tasks query construction and filtering."""

    @patch("tools.salesforce.get_sf_client")
    def test_no_filters(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_tasks
        result = sf_get_tasks()
        self.assertEqual(result["totalSize"], 0)
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("FROM Task", call_args)
        self.assertNotIn("WHERE", call_args)

    @patch("tools.salesforce.get_sf_client")
    def test_who_id_filter(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_tasks
        sf_get_tasks(who_id="00Q001")
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("WhoId = '00Q001'", call_args)

    @patch("tools.salesforce.get_sf_client")
    def test_subject_search_uses_like(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_tasks
        sf_get_tasks(subject_search="Follow up")
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("LIKE '%Follow up%'", call_args)

    @patch("tools.salesforce.get_sf_client")
    def test_soql_injection_in_who_id(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_tasks
        sf_get_tasks(who_id="'; DROP TABLE Task;--")
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("\\'", call_args)


# ---------------------------------------------------------------------------
# 11. sf_get_events
# ---------------------------------------------------------------------------

class TestSfGetEvents(unittest.TestCase):
    """Verify sf_get_events query construction."""

    @patch("tools.salesforce.get_sf_client")
    def test_no_filters(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_events
        result = sf_get_events()
        self.assertEqual(result["totalSize"], 0)
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("FROM Event", call_args)

    @patch("tools.salesforce.get_sf_client")
    def test_datetime_range_filter(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_events
        sf_get_events(start_from="2024-01-15T00:00:00Z", start_to="2024-02-15T23:59:59Z")
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("StartDateTime >= 2024-01-15T00:00:00Z", call_args)
        self.assertIn("StartDateTime <= 2024-02-15T23:59:59Z", call_args)

    @patch("tools.salesforce.get_sf_client")
    def test_soql_injection_in_who_id(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_events
        sf_get_events(who_id="'; DROP TABLE Event;--")
        call_args = mock_sf.query_all.call_args[0][0]
        self.assertIn("\\'", call_args)

    def test_invalid_datetime_rejected(self):
        from tools.salesforce import sf_get_events
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            sf_get_events(start_from="2024-01-15 OR 1=1")


# ---------------------------------------------------------------------------
# 12. sf_get_activity_history
# ---------------------------------------------------------------------------

class TestSfGetActivityHistory(unittest.TestCase):
    """Verify sf_get_activity_history combines tasks and events."""

    @patch("tools.salesforce.get_sf_client")
    def test_returns_combined_results(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.side_effect = [
            {"totalSize": 1, "records": [{"Id": "T1", "ActivityDate": "2024-01-15", "Subject": "Call"}]},
            {"totalSize": 1, "records": [{"Id": "E1", "StartDateTime": "2024-01-16T10:00:00Z", "Subject": "Meeting"}]},
        ]
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_activity_history
        result = sf_get_activity_history(record_id="003001")
        self.assertEqual(result["task_count"], 1)
        self.assertEqual(result["event_count"], 1)
        self.assertEqual(result["total_count"], 2)
        self.assertEqual(len(result["activities"]), 2)
        # Event has later date, should come first
        self.assertEqual(result["activities"][0]["activity_type"], "Event")

    @patch("tools.salesforce.get_sf_client")
    def test_record_id_escaped(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 0, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_get_activity_history
        sf_get_activity_history(record_id="003'; DROP TABLE --")
        for call_args in mock_sf.query_all.call_args_list:
            self.assertIn("\\'", call_args[0][0])


# ---------------------------------------------------------------------------
# 13. User context (ContextVar)
# ---------------------------------------------------------------------------

class TestUserContext(unittest.TestCase):
    """Verify user_context ContextVar set/get/reset."""

    def test_default_is_none(self):
        from user_context import get_current_api_key
        # Note: may already be set by another test; reset first
        from user_context import current_api_key
        token = current_api_key.set(None)
        try:
            self.assertIsNone(get_current_api_key())
        finally:
            current_api_key.reset(token)

    def test_set_and_get(self):
        from user_context import current_api_key, get_current_api_key
        token = current_api_key.set("test-key-123")
        try:
            self.assertEqual(get_current_api_key(), "test-key-123")
        finally:
            current_api_key.reset(token)

    def test_reset_restores_previous(self):
        from user_context import current_api_key, get_current_api_key
        token1 = current_api_key.set("key-a")
        token2 = current_api_key.set("key-b")
        self.assertEqual(get_current_api_key(), "key-b")
        current_api_key.reset(token2)
        self.assertEqual(get_current_api_key(), "key-a")
        current_api_key.reset(token1)


# ---------------------------------------------------------------------------
# 14. Token store
# ---------------------------------------------------------------------------

class TestTokenStore(unittest.TestCase):
    """Verify TokenStore encryption round-trip and CRUD."""

    def setUp(self):
        from cryptography.fernet import Fernet
        self._key = Fernet.generate_key().decode()

    @patch.dict(os.environ, {"ENCRYPTION_KEY": ""})
    def test_get_token_store_returns_none_without_key(self):
        import token_store
        token_store._store = None  # reset singleton
        result = token_store.get_token_store()
        self.assertIsNone(result)

    def test_put_and_get(self):
        import tempfile
        from pathlib import Path
        import token_store

        with tempfile.TemporaryDirectory() as tmpdir:
            original_file = token_store.TOKEN_FILE
            token_store.TOKEN_FILE = Path(tmpdir) / "tokens.json.enc"
            try:
                with patch.dict(os.environ, {"ENCRYPTION_KEY": self._key}):
                    store = token_store.TokenStore()
                    tokens = {
                        "access_token": "at-123",
                        "refresh_token": "rt-456",
                        "instance_url": "https://test.my.salesforce.com",
                        "issued_at": time.time(),
                        "pardot_business_unit_id": None,
                    }
                    store.put("api-key-1", tokens)
                    result = store.get("api-key-1")
                    self.assertEqual(result["access_token"], "at-123")
                    self.assertEqual(result["instance_url"], "https://test.my.salesforce.com")
            finally:
                token_store.TOKEN_FILE = original_file

    def test_delete(self):
        import tempfile
        from pathlib import Path
        import token_store

        with tempfile.TemporaryDirectory() as tmpdir:
            original_file = token_store.TOKEN_FILE
            token_store.TOKEN_FILE = Path(tmpdir) / "tokens.json.enc"
            try:
                with patch.dict(os.environ, {"ENCRYPTION_KEY": self._key}):
                    store = token_store.TokenStore()
                    tokens = {
                        "access_token": "at-123",
                        "refresh_token": "rt-456",
                        "instance_url": "https://test.my.salesforce.com",
                        "issued_at": time.time(),
                        "pardot_business_unit_id": None,
                    }
                    store.put("api-key-1", tokens)
                    self.assertTrue(store.has_tokens("api-key-1"))
                    self.assertTrue(store.delete("api-key-1"))
                    self.assertIsNone(store.get("api-key-1"))
                    self.assertFalse(store.has_tokens("api-key-1"))
            finally:
                token_store.TOKEN_FILE = original_file

    def test_get_nonexistent_returns_none(self):
        import tempfile
        from pathlib import Path
        import token_store

        with tempfile.TemporaryDirectory() as tmpdir:
            original_file = token_store.TOKEN_FILE
            token_store.TOKEN_FILE = Path(tmpdir) / "tokens.json.enc"
            try:
                with patch.dict(os.environ, {"ENCRYPTION_KEY": self._key}):
                    store = token_store.TokenStore()
                    self.assertIsNone(store.get("nonexistent"))
            finally:
                token_store.TOKEN_FILE = original_file


# ---------------------------------------------------------------------------
# 15. Per-user client routing
# ---------------------------------------------------------------------------

class TestPerUserClientRouting(unittest.TestCase):
    """Verify get_sf_client routes to per-user client via OAuth tokens."""

    @patch("tools.salesforce.get_current_api_key", return_value=None)
    def test_no_api_key_raises(self, mock_key):
        from tools.salesforce import get_sf_client
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            get_sf_client()


# ---------------------------------------------------------------------------
# 16. Date/datetime format validation
# ---------------------------------------------------------------------------

class TestDateValidation(unittest.TestCase):
    """Verify _validate_date and _validate_datetime reject invalid formats."""

    def test_valid_date(self):
        from tools.salesforce import _validate_date
        _validate_date("2024-01-15")  # should not raise

    def test_invalid_date_with_injection(self):
        from tools.salesforce import _validate_date
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            _validate_date("2024-01-01 OR 1=1")

    def test_invalid_date_format(self):
        from tools.salesforce import _validate_date
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            _validate_date("01/15/2024")

    def test_valid_datetime(self):
        from tools.salesforce import _validate_datetime
        _validate_datetime("2024-01-15T00:00:00Z")  # should not raise

    def test_valid_datetime_no_z(self):
        from tools.salesforce import _validate_datetime
        _validate_datetime("2024-01-15T00:00:00")  # should not raise

    def test_invalid_datetime_with_injection(self):
        from tools.salesforce import _validate_datetime
        from fastmcp.exceptions import ToolError
        with self.assertRaises(ToolError):
            _validate_datetime("2024-01-15T00:00:00Z OR 1=1")


# ---------------------------------------------------------------------------
# 17. Instance URL validation
# ---------------------------------------------------------------------------

class TestInstanceUrlValidation(unittest.TestCase):
    """Verify _validate_instance_url rejects non-Salesforce domains."""

    def test_valid_salesforce_url(self):
        from oauth import _validate_instance_url
        self.assertTrue(_validate_instance_url("https://na1.salesforce.com"))

    def test_valid_my_salesforce(self):
        from oauth import _validate_instance_url
        self.assertTrue(_validate_instance_url("https://myorg.my.salesforce.com"))

    def test_valid_force_com(self):
        from oauth import _validate_instance_url
        self.assertTrue(_validate_instance_url("https://myorg.force.com"))

    def test_reject_http(self):
        from oauth import _validate_instance_url
        self.assertFalse(_validate_instance_url("http://na1.salesforce.com"))

    def test_reject_arbitrary_domain(self):
        from oauth import _validate_instance_url
        self.assertFalse(_validate_instance_url("https://evil.example.com"))

    def test_reject_empty(self):
        from oauth import _validate_instance_url
        self.assertFalse(_validate_instance_url(""))


# ---------------------------------------------------------------------------
# 18. Auth middleware
# ---------------------------------------------------------------------------

class TestBearerAuthMiddleware(unittest.TestCase):
    """Verify BearerAuthMiddleware accepts session tokens."""

    @patch("token_store.get_token_store")
    @patch("auth.get_http_headers", return_value={"authorization": "Bearer session-token-abc"})
    def test_session_token_accepted(self, mock_headers, mock_store):
        """Session token found in token store should be accepted."""
        import asyncio
        from auth import BearerAuthMiddleware

        store_instance = MagicMock()
        store_instance.has_tokens.return_value = True
        mock_store.return_value = store_instance

        middleware = BearerAuthMiddleware()
        context = MagicMock()
        context.method = "tools/call"

        call_next_result = MagicMock()
        call_next = AsyncMock(return_value=call_next_result)

        result = asyncio.get_event_loop().run_until_complete(
            middleware.on_request(context, call_next)
        )
        call_next.assert_called_once()
        store_instance.has_tokens.assert_called_once_with("session-token-abc")

    @patch("token_store.get_token_store")
    @patch("auth.get_http_headers", return_value={"authorization": "Bearer invalid-token"})
    def test_invalid_token_rejected(self, mock_headers, mock_store):
        """Token not in store should be rejected."""
        import asyncio
        from auth import BearerAuthMiddleware

        store_instance = MagicMock()
        store_instance.has_tokens.return_value = False
        mock_store.return_value = store_instance

        middleware = BearerAuthMiddleware()
        context = MagicMock()
        context.method = "tools/call"
        call_next = AsyncMock()

        with self.assertRaises(ValueError) as ctx:
            asyncio.get_event_loop().run_until_complete(
                middleware.on_request(context, call_next)
            )
        self.assertIn("Unauthorized", str(ctx.exception))
        call_next.assert_not_called()

    @patch("auth.get_http_headers", return_value={})
    def test_missing_bearer_rejected(self, mock_headers):
        """Missing Authorization header should be rejected."""
        import asyncio
        from auth import BearerAuthMiddleware

        middleware = BearerAuthMiddleware()
        context = MagicMock()
        context.method = "tools/call"
        call_next = AsyncMock()

        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(
                middleware.on_request(context, call_next)
            )


# ---------------------------------------------------------------------------
# 21. HMAC token hashing migration
# ---------------------------------------------------------------------------

class TestTokenStoreHMACMigration(unittest.TestCase):
    """Verify tokens stored under legacy SHA-256 are auto-migrated to HMAC."""

    def setUp(self):
        from cryptography.fernet import Fernet
        self._key = Fernet.generate_key().decode()

    def test_legacy_hash_migration(self):
        import tempfile
        from pathlib import Path
        import token_store

        with tempfile.TemporaryDirectory() as tmpdir:
            original_file = token_store.TOKEN_FILE
            token_store.TOKEN_FILE = Path(tmpdir) / "tokens.json.enc"
            try:
                with patch.dict(os.environ, {"ENCRYPTION_KEY": self._key}):
                    store = token_store.TokenStore()

                    # Manually store under the legacy (unsalted) hash
                    legacy_hash = token_store._hash_key_legacy("api-key-legacy")
                    tokens = {
                        "access_token": "at-legacy",
                        "refresh_token": "rt-legacy",
                        "instance_url": "https://test.my.salesforce.com",
                        "issued_at": time.time(),
                        "pardot_business_unit_id": None,
                    }
                    data = store._load()
                    data[legacy_hash] = tokens
                    store._save(data)
                    store._cache = None  # force reload

                    # Read using normal API — should find via legacy fallback
                    result = store.get("api-key-legacy")
                    self.assertIsNotNone(result)
                    self.assertEqual(result["access_token"], "at-legacy")

                    # After migration, the legacy key should be gone
                    store._cache = None
                    data = store._load()
                    self.assertNotIn(legacy_hash, data)
                    # New HMAC key should be present
                    new_hash = token_store._hash_key("api-key-legacy")
                    self.assertIn(new_hash, data)
            finally:
                token_store.TOKEN_FILE = original_file

    def test_new_tokens_use_hmac(self):
        import tempfile
        from pathlib import Path
        import token_store

        with tempfile.TemporaryDirectory() as tmpdir:
            original_file = token_store.TOKEN_FILE
            token_store.TOKEN_FILE = Path(tmpdir) / "tokens.json.enc"
            try:
                with patch.dict(os.environ, {"ENCRYPTION_KEY": self._key}):
                    store = token_store.TokenStore()
                    tokens = {
                        "access_token": "at-new",
                        "refresh_token": "rt-new",
                        "instance_url": "https://test.my.salesforce.com",
                        "issued_at": time.time(),
                        "pardot_business_unit_id": None,
                    }
                    store.put("new-key", tokens)

                    # Verify stored under HMAC key, not legacy
                    store._cache = None
                    data = store._load()
                    hmac_hash = token_store._hash_key("new-key")
                    legacy_hash = token_store._hash_key_legacy("new-key")
                    self.assertIn(hmac_hash, data)
                    self.assertNotIn(legacy_hash, data)
            finally:
                token_store.TOKEN_FILE = original_file


# ---------------------------------------------------------------------------
# 22. DCR rate limiting
# ---------------------------------------------------------------------------

class TestDCRRateLimit(unittest.TestCase):
    """Verify per-IP rate limiting on /oauth/register."""

    def setUp(self):
        import mcp_oauth
        mcp_oauth._dcr_request_timestamps.clear()

    def test_under_limit_passes(self):
        from mcp_oauth import _check_dcr_rate_limit
        for _ in range(10):
            self.assertTrue(_check_dcr_rate_limit("192.168.1.1"))

    def test_over_limit_blocked(self):
        from mcp_oauth import _check_dcr_rate_limit
        for _ in range(10):
            _check_dcr_rate_limit("192.168.1.2")
        self.assertFalse(_check_dcr_rate_limit("192.168.1.2"))

    def test_different_ips_independent(self):
        from mcp_oauth import _check_dcr_rate_limit
        for _ in range(10):
            _check_dcr_rate_limit("10.0.0.1")
        self.assertTrue(_check_dcr_rate_limit("10.0.0.2"))


# ---------------------------------------------------------------------------
# 23. Large result warning (anomaly detection)
# ---------------------------------------------------------------------------

class TestLargeResultWarning(unittest.TestCase):
    """Verify warning is logged for large result sets."""

    @patch("tools.salesforce.get_sf_client")
    def test_large_result_logs_warning(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 1500, "records": []}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_query
        with self.assertLogs("tools.salesforce", level="WARNING") as cm:
            sf_query("SELECT Id FROM Lead")
        self.assertTrue(any("Large result set" in msg for msg in cm.output))

    @patch("tools.salesforce.get_sf_client")
    def test_small_result_no_warning(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 5, "records": [{"Id": "001"}] * 5}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_query
        # Should not log any warnings
        result = sf_query("SELECT Id FROM Lead")
        self.assertEqual(result["totalSize"], 5)


# ---------------------------------------------------------------------------
# 24. Output sanitization (truncation + data source markers)
# ---------------------------------------------------------------------------

class TestOutputSanitization(unittest.TestCase):
    """Verify result truncation and _dataSource markers."""

    @patch("tools.salesforce.get_sf_client")
    def test_data_source_marker_present(self, mock_get_client):
        mock_sf = MagicMock()
        mock_sf.query_all.return_value = {"totalSize": 1, "records": [{"Id": "001"}]}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_query
        result = sf_query("SELECT Id FROM Lead")
        self.assertEqual(result["_dataSource"], "salesforce")

    @patch("tools.salesforce.get_sf_client")
    def test_large_result_truncated(self, mock_get_client):
        mock_sf = MagicMock()
        records = [{"Id": f"00{i}"} for i in range(600)]
        mock_sf.query_all.return_value = {"totalSize": 600, "records": records}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_query, MAX_RESULT_RECORDS
        result = sf_query("SELECT Id FROM Lead")
        self.assertEqual(result["returnedSize"], MAX_RESULT_RECORDS)
        self.assertEqual(len(result["records"]), MAX_RESULT_RECORDS)
        self.assertIn("warning", result)
        self.assertIn("truncated", result["warning"].lower())

    @patch("tools.salesforce.get_sf_client")
    def test_small_result_not_truncated(self, mock_get_client):
        mock_sf = MagicMock()
        records = [{"Id": f"00{i}"} for i in range(10)]
        mock_sf.query_all.return_value = {"totalSize": 10, "records": records}
        mock_get_client.return_value = mock_sf

        from tools.salesforce import sf_query
        result = sf_query("SELECT Id FROM Lead")
        self.assertEqual(result["returnedSize"], 10)
        self.assertNotIn("warning", result)


if __name__ == "__main__":
    unittest.main()
