"""
Encrypted token storage for per-user Salesforce OAuth credentials.

Stores a mapping of API key -> {access_token, refresh_token, instance_url, ...}
encrypted at rest using Fernet symmetric encryption (cryptography library).

Storage file: data/tokens.json.enc
Encryption key: ENCRYPTION_KEY env var (Fernet key, 32 bytes URL-safe base64)

Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import hashlib
import hmac
import json
import os
import logging
import tempfile
import threading
from pathlib import Path
from typing import TypedDict

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

TOKEN_FILE = Path(__file__).parent / "data" / "tokens.json.enc"

# Session tokens expire after 24 hours (configurable via env var)
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", 86400))


class UserTokens(TypedDict):
    access_token: str
    refresh_token: str
    instance_url: str
    issued_at: float
    pardot_business_unit_id: str | None  # None = use shared env var


def _hash_key_legacy(api_key: str) -> str:
    """Legacy: unsalted SHA-256 hash (used for reading old tokens during migration)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _get_hmac_secret() -> bytes:
    """Derive an HMAC secret from the ENCRYPTION_KEY env var."""
    enc_key = os.environ.get("ENCRYPTION_KEY", "")
    return hashlib.sha256(f"hmac-salt:{enc_key}".encode()).digest()


def _hash_key(api_key: str) -> str:
    """HMAC-SHA256 keyed hash for use as dict key (prevents rainbow table attacks)."""
    return hmac.new(_get_hmac_secret(), api_key.encode(), hashlib.sha256).hexdigest()


class TokenStore:
    """Thread-safe encrypted token storage."""

    def __init__(self) -> None:
        key = os.environ.get("ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("ENCRYPTION_KEY env var is required for multi-tenant mode")
        self._fernet = Fernet(key.encode())
        self._lock = threading.Lock()
        self._cache: dict[str, UserTokens] | None = None

    def _ensure_dir(self) -> None:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(TOKEN_FILE.parent, 0o700)

    def _load(self) -> dict[str, UserTokens]:
        if self._cache is not None:
            return self._cache
        if not TOKEN_FILE.exists():
            self._cache = {}
            return self._cache
        encrypted = TOKEN_FILE.read_bytes()
        decrypted = self._fernet.decrypt(encrypted)
        self._cache = json.loads(decrypted)
        return self._cache

    def _save(self, data: dict[str, UserTokens]) -> None:
        self._ensure_dir()
        plaintext = json.dumps(data).encode()
        encrypted = self._fernet.encrypt(plaintext)
        # Atomic write: write to temp file then rename
        fd, tmp_path = tempfile.mkstemp(dir=TOKEN_FILE.parent)
        try:
            os.write(fd, encrypted)
            os.close(fd)
            fd = -1  # mark as closed
            os.replace(tmp_path, TOKEN_FILE)
            os.chmod(TOKEN_FILE, 0o600)
        except Exception:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        self._cache = data

    def get(self, api_key: str) -> UserTokens | None:
        """Get stored tokens for an API key, or None if not connected or expired."""
        hk = _hash_key(api_key)
        hk_legacy = _hash_key_legacy(api_key)
        with self._lock:
            data = self._load()
            tokens = data.get(hk)

            # Fallback: check legacy (unsalted) hash and auto-migrate
            if tokens is None and hk_legacy in data:
                tokens = data[hk_legacy]
                data[hk] = tokens
                del data[hk_legacy]
                self._save(data)
                logger.info("Migrated token store entry from legacy hash to HMAC hash")

            if tokens is None:
                return None
            # Check session TTL
            import time
            issued = tokens.get("issued_at", 0)
            if time.time() - issued > SESSION_TTL_SECONDS:
                logger.info("Session expired (TTL %ds) for key hash %s", SESSION_TTL_SECONDS, hk[:8])
                del data[hk]
                self._save(data)
                return None
            return tokens

    def put(self, api_key: str, tokens: UserTokens) -> None:
        """Store or update tokens for an API key."""
        hk = _hash_key(api_key)
        with self._lock:
            data = self._load()
            data[hk] = tokens
            self._save(data)

    def delete(self, api_key: str) -> bool:
        """Remove tokens for an API key. Returns True if found."""
        hk = _hash_key(api_key)
        hk_legacy = _hash_key_legacy(api_key)
        with self._lock:
            data = self._load()
            found = False
            if hk in data:
                del data[hk]
                found = True
            if hk_legacy in data:
                del data[hk_legacy]
                found = True
            if found:
                self._save(data)
            return found

    def has_tokens(self, api_key: str) -> bool:
        """Check if an API key has stored (non-expired) OAuth tokens."""
        return self.get(api_key) is not None


# Singleton (lazily initialized)
_store: TokenStore | None = None


def get_token_store() -> TokenStore | None:
    """Return the token store, or None if ENCRYPTION_KEY is not set (legacy mode)."""
    global _store
    if _store is None:
        if os.environ.get("ENCRYPTION_KEY"):
            _store = TokenStore()
        else:
            return None
    return _store
