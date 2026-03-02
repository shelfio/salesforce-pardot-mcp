"""
Tests for self-service OAuth 2.0 flow.

Validates /login redirect, callback token generation, HTML response,
status checking, and token revocation.
"""

import os
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Set up env vars before importing oauth module
os.environ.setdefault("TEAM_API_KEYS", "test-key-1,test-key-2")
os.environ.setdefault("SF_OAUTH_CLIENT_ID", "test-client-id")
os.environ.setdefault("SF_OAUTH_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("SF_OAUTH_REDIRECT_URI", "http://localhost:8000/oauth/callback")
os.environ.setdefault("SF_OAUTH_LOGIN_URL", "https://login.salesforce.com")


class TestOAuthLogin(unittest.TestCase):
    """Verify /login endpoint redirects to Salesforce."""

    def test_login_returns_redirect(self):
        import asyncio
        from oauth import oauth_login
        request = MagicMock()
        result = asyncio.get_event_loop().run_until_complete(oauth_login(request))
        # Should be a redirect (302)
        self.assertEqual(result.status_code, 307)
        location = dict(result.headers).get("location", "")
        self.assertIn("login.salesforce.com", location)
        self.assertIn("response_type=code", location)
        self.assertIn("pardot_api", location)

    def test_login_no_auth_required(self):
        """Login should work without any Authorization header."""
        import asyncio
        from oauth import oauth_login
        request = MagicMock()
        request.headers = {}
        result = asyncio.get_event_loop().run_until_complete(oauth_login(request))
        self.assertEqual(result.status_code, 307)


class TestOAuthCallback(unittest.TestCase):
    """Verify /oauth/callback endpoint."""

    def test_missing_code_returns_400(self):
        import asyncio
        from oauth import oauth_callback
        request = MagicMock()
        request.query_params = {}
        result = asyncio.get_event_loop().run_until_complete(oauth_callback(request))
        self.assertEqual(result.status_code, 400)
        self.assertIn("Missing", result.body.decode())

    def test_invalid_state_returns_400(self):
        import asyncio
        from oauth import oauth_callback
        request = MagicMock()
        request.query_params = {"code": "auth-code-123", "state": "invalid-state"}
        result = asyncio.get_event_loop().run_until_complete(oauth_callback(request))
        self.assertEqual(result.status_code, 400)
        self.assertIn("Invalid", result.body.decode())

    @patch("oauth.get_token_store")
    @patch("oauth.httpx.AsyncClient")
    def test_successful_callback_returns_html_with_token(self, mock_client_cls, mock_store):
        import asyncio
        import time
        from oauth import oauth_callback, _pending_states

        # Set up a valid pending state
        state = "test-valid-state"
        _pending_states[state] = time.time()

        # Mock token store
        store_instance = MagicMock()
        mock_store.return_value = store_instance

        # Mock HTTP response from Salesforce
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "instance_url": "https://myorg.my.salesforce.com",
        }

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_http

        request = MagicMock()
        request.query_params = {"code": "auth-code-123", "state": state}
        request.url = MagicMock()
        request.url.scheme = "https"
        request.headers = {
            "host": "test-server.up.railway.app",
            "x-forwarded-host": "evil.example.com",
            "x-forwarded-proto": "https",
        }

        result = asyncio.get_event_loop().run_until_complete(oauth_callback(request))
        self.assertEqual(result.status_code, 200)

        # Should return HTML (not JSON)
        body = result.body.decode()
        self.assertIn("Connected to Salesforce", body)
        self.assertIn("Session Token", body)
        self.assertIn("myorg.my.salesforce.com", body)
        self.assertIn("Copy Token", body)

        # Server URL must come from SF_OAUTH_REDIRECT_URI, NOT spoofed headers
        self.assertNotIn("evil.example.com", body)

        # Token store should have been called with a session token
        store_instance.put.assert_called_once()
        call_args = store_instance.put.call_args
        session_token = call_args[0][0]
        # Session token should be a long random string
        self.assertGreater(len(session_token), 40)


class TestOAuthStatus(unittest.TestCase):
    """Verify /oauth/status endpoint."""

    def _make_request(self, auth_header=None):
        request = MagicMock()
        headers = {}
        if auth_header:
            headers["authorization"] = auth_header
        request.headers = headers
        return request

    def test_missing_auth_returns_401(self):
        import asyncio
        from oauth import oauth_status
        request = self._make_request()
        result = asyncio.get_event_loop().run_until_complete(oauth_status(request))
        self.assertEqual(result.status_code, 401)

    @patch("oauth.get_token_store", return_value=None)
    def test_no_store_returns_not_configured(self, mock_store):
        import asyncio
        import json
        from oauth import oauth_status
        request = self._make_request("Bearer test-session-token")
        result = asyncio.get_event_loop().run_until_complete(oauth_status(request))
        self.assertEqual(result.status_code, 200)
        body = json.loads(result.body)
        self.assertFalse(body["connected"])

    @patch("oauth.get_token_store")
    def test_valid_token_shows_connected(self, mock_store):
        import asyncio
        import json
        from oauth import oauth_status

        store_instance = MagicMock()
        store_instance.get.return_value = {
            "access_token": "tok",
            "instance_url": "https://myorg.my.salesforce.com",
        }
        mock_store.return_value = store_instance

        request = self._make_request("Bearer test-session-token")
        result = asyncio.get_event_loop().run_until_complete(oauth_status(request))
        self.assertEqual(result.status_code, 200)
        body = json.loads(result.body)
        self.assertTrue(body["connected"])
        self.assertEqual(body["instance_url"], "https://myorg.my.salesforce.com")


class TestOAuthRevoke(unittest.TestCase):
    """Verify /oauth/revoke endpoint."""

    def _make_request(self, auth_header=None):
        request = MagicMock()
        headers = {}
        if auth_header:
            headers["authorization"] = auth_header
        request.headers = headers
        return request

    def test_missing_auth_returns_401(self):
        import asyncio
        from oauth import oauth_revoke
        request = self._make_request()
        result = asyncio.get_event_loop().run_until_complete(oauth_revoke(request))
        self.assertEqual(result.status_code, 401)

    @patch("oauth.get_token_store")
    def test_revoke_clears_tokens(self, mock_store):
        import asyncio
        import json
        from oauth import oauth_revoke

        store_instance = MagicMock()
        store_instance.delete.return_value = True
        mock_store.return_value = store_instance

        request = self._make_request("Bearer my-session-token")
        result = asyncio.get_event_loop().run_until_complete(oauth_revoke(request))
        self.assertEqual(result.status_code, 200)
        body = json.loads(result.body)
        self.assertTrue(body["success"])
        self.assertTrue(body["was_connected"])
        store_instance.delete.assert_called_once_with("my-session-token")


if __name__ == "__main__":
    unittest.main()
