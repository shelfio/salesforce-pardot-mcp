"""
Tests for token_store: behaviour across ENCRYPTION_KEY rotation.

Run with: python -m pytest tests/test_token_store.py -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import token_store


def _tokens() -> token_store.UserTokens:
    import time
    return {
        "access_token": "at",
        "refresh_token": "rt",
        "instance_url": "https://example.my.salesforce.com",
        "issued_at": time.time(),
    }


class TestEncryptionKeyRotation(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.token_file = Path(self._tmp.name) / "tokens.json.enc"
        self.old_key = Fernet.generate_key().decode()
        self.new_key = Fernet.generate_key().decode()

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, key: str) -> token_store.TokenStore:
        with patch.dict(os.environ, {"ENCRYPTION_KEY": key}):
            return token_store.TokenStore()

    def test_get_after_rotation_returns_none(self):
        with patch.object(token_store, "TOKEN_FILE", self.token_file), \
             patch.dict(os.environ, {"ENCRYPTION_KEY": self.old_key}):
            self._store(self.old_key).put("user-key", _tokens())

        with patch.object(token_store, "TOKEN_FILE", self.token_file), \
             patch.dict(os.environ, {"ENCRYPTION_KEY": self.new_key}):
            self.assertIsNone(self._store(self.new_key).get("user-key"))

    def test_put_after_rotation_overwrites_unreadable_file(self):
        with patch.object(token_store, "TOKEN_FILE", self.token_file), \
             patch.dict(os.environ, {"ENCRYPTION_KEY": self.old_key}):
            self._store(self.old_key).put("old-user", _tokens())

        with patch.object(token_store, "TOKEN_FILE", self.token_file), \
             patch.dict(os.environ, {"ENCRYPTION_KEY": self.new_key}):
            self._store(self.new_key).put("new-user", _tokens())
            fresh = self._store(self.new_key)
            self.assertIsNotNone(fresh.get("new-user"))
            self.assertIsNone(fresh.get("old-user"))


if __name__ == "__main__":
    unittest.main()
