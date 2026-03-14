"""Key management abstraction layer (M41 — HSM-Backed Key Handling).

Provides a unified KeyProvider interface with pluggable backends:
  - SoftwareKeyProvider: in-memory / filesystem keys (current default)
  - TPM2KeyProvider: TPM2-sealed keys via tpm2-tools
  - PKCS11KeyProvider: external HSM via PKCS#11 (stub for future)

The active backend is selected at startup based on keystore.yaml
configuration and available hardware.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("agent.keystore")

# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class KeyProvider(abc.ABC):
    """Abstract key management provider.

    All key operations go through this interface so the backing store
    (software, TPM2, PKCS#11 HSM) can be swapped without changing
    consuming code.
    """

    @abc.abstractmethod
    def sign(self, data: bytes, key_id: str = "default") -> bytes:
        """Sign *data* with the key identified by *key_id*.

        Returns the raw HMAC-SHA256 (or equivalent) signature bytes.
        """

    @abc.abstractmethod
    def verify(self, data: bytes, signature: bytes,
               key_id: str = "default") -> bool:
        """Verify *signature* over *data* using *key_id*."""

    @abc.abstractmethod
    def get_key(self, key_id: str = "default") -> bytes:
        """Return the raw key material (software) or a wrapped reference."""

    @abc.abstractmethod
    def rotate(self, key_id: str = "default") -> str:
        """Rotate the key identified by *key_id*.

        Returns a short status message.
        """

    @abc.abstractmethod
    def provider_name(self) -> str:
        """Human-readable name of this provider (e.g. 'software', 'tpm2')."""

    def derive(self, context: str, key_id: str = "default") -> bytes:
        """Derive a sub-key for *context* using HKDF-like construction.

        Default implementation uses HMAC(key, context).
        """
        key = self.get_key(key_id)
        return hmac.new(key, context.encode("utf-8"),
                        hashlib.sha256).digest()

    def status(self) -> dict[str, Any]:
        """Return provider status for health checks / audit."""
        return {
            "provider": self.provider_name(),
            "available": True,
        }


# ---------------------------------------------------------------------------
# Software provider (default — current pattern)
# ---------------------------------------------------------------------------


class SoftwareKeyProvider(KeyProvider):
    """Software-only key provider using filesystem-stored keys.

    Keys are stored as raw bytes in files under *key_dir*.  This is the
    baseline provider used when no HSM / TPM2 hardware is available.
    """

    def __init__(self, key_dir: str = "/run/secure-ai",
                 default_key_path: str | None = None):
        self._key_dir = key_dir
        self._default_key_path = default_key_path
        self._keys: dict[str, bytes] = {}

    def _key_path(self, key_id: str) -> str:
        if key_id == "default" and self._default_key_path:
            return self._default_key_path
        return os.path.join(self._key_dir, f"{key_id}.key")

    def _load_key(self, key_id: str) -> bytes:
        if key_id in self._keys:
            return self._keys[key_id]
        path = self._key_path(key_id)
        try:
            raw = Path(path).read_bytes()
            if len(raw) >= 32:
                self._keys[key_id] = raw[:64]
                log.info("loaded key '%s' from %s", key_id, path)
                return self._keys[key_id]
        except OSError:
            pass
        # Generate ephemeral key
        key = os.urandom(64)
        self._keys[key_id] = key
        log.warning("generated ephemeral key '%s' (no persistent key at %s)",
                    key_id, path)
        return key

    def sign(self, data: bytes, key_id: str = "default") -> bytes:
        key = self._load_key(key_id)
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes,
               key_id: str = "default") -> bool:
        expected = self.sign(data, key_id)
        return hmac.compare_digest(expected, signature)

    def get_key(self, key_id: str = "default") -> bytes:
        return self._load_key(key_id)

    def rotate(self, key_id: str = "default") -> str:
        new_key = os.urandom(64)
        path = self._key_path(key_id)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            Path(path).write_bytes(new_key)
            os.chmod(path, 0o600)
            self._keys[key_id] = new_key
            log.info("rotated key '%s' → %s", key_id, path)
            return f"rotated (software, {path})"
        except OSError as exc:
            # Fall back to in-memory rotation
            self._keys[key_id] = new_key
            log.warning("in-memory rotation for '%s': %s", key_id, exc)
            return f"rotated (memory-only: {exc})"

    def provider_name(self) -> str:
        return "software"


# ---------------------------------------------------------------------------
# TPM2 provider (extends current TPM2 vault sealing to general keys)
# ---------------------------------------------------------------------------


class TPM2KeyProvider(KeyProvider):
    """TPM2-backed key provider using tpm2-tools.

    Keys are sealed to the TPM2 chip with PCR policy binding.
    Unsealing requires the PCRs to match the expected state,
    tying key availability to a verified boot chain.
    """

    def __init__(
        self,
        key_dir: str = "/var/lib/secure-ai/keys/tpm2",
        pcr_list: str = "sha256:0,2,4,7",
    ):
        self._key_dir = key_dir
        self._pcr_list = pcr_list
        self._available = shutil.which("tpm2_createprimary") is not None
        self._keys: dict[str, bytes] = {}
        if not self._available:
            log.warning("tpm2-tools not found — TPM2 provider degraded")

    def _sealed_path(self, key_id: str) -> str:
        return os.path.join(self._key_dir, f"{key_id}.sealed")

    def _unseal(self, key_id: str) -> bytes:
        """Unseal a key from TPM2 NV storage."""
        if key_id in self._keys:
            return self._keys[key_id]

        sealed_path = self._sealed_path(key_id)
        if not os.path.isfile(sealed_path):
            raise FileNotFoundError(
                f"no sealed key at {sealed_path}")

        if not self._available:
            raise RuntimeError("tpm2-tools not available")

        try:
            ctx_path = os.path.join(self._key_dir, "primary.ctx")
            policy_path = os.path.join(self._key_dir, "pcr-policy.dat")

            result = subprocess.run(
                ["tpm2_unseal",
                 "-c", ctx_path,
                 "-p", f"pcr:{self._pcr_list}",
                 "-L", policy_path,
                 "-o", "/dev/stdout"],
                capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"tpm2_unseal failed: {result.stderr.decode()}")

            key = result.stdout
            self._keys[key_id] = key
            log.info("unsealed key '%s' from TPM2", key_id)
            return key

        except (subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError(f"TPM2 unseal failed: {exc}") from exc

    def sign(self, data: bytes, key_id: str = "default") -> bytes:
        key = self._unseal(key_id)
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes,
               key_id: str = "default") -> bool:
        expected = self.sign(data, key_id)
        return hmac.compare_digest(expected, signature)

    def get_key(self, key_id: str = "default") -> bytes:
        return self._unseal(key_id)

    def rotate(self, key_id: str = "default") -> str:
        if not self._available:
            return "skipped (tpm2-tools not available)"

        new_key = os.urandom(64)
        sealed_path = self._sealed_path(key_id)

        try:
            ctx_path = os.path.join(self._key_dir, "primary.ctx")
            policy_path = os.path.join(self._key_dir, "pcr-policy.dat")

            # Create new sealed object
            result = subprocess.run(
                ["tpm2_create",
                 "-C", ctx_path,
                 "-L", policy_path,
                 "-i", "/dev/stdin",
                 "-u", f"{sealed_path}.pub",
                 "-r", f"{sealed_path}.priv"],
                input=new_key,
                capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                return f"failed: {result.stderr.decode()[:100]}"

            self._keys[key_id] = new_key
            log.info("rotated key '%s' via TPM2 seal", key_id)
            return f"rotated (tpm2-sealed, {sealed_path})"

        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"failed: {exc}"

    def provider_name(self) -> str:
        return "tpm2"

    def status(self) -> dict[str, Any]:
        return {
            "provider": "tpm2",
            "available": self._available,
            "key_dir": self._key_dir,
            "pcr_list": self._pcr_list,
        }


# ---------------------------------------------------------------------------
# PKCS#11 provider (stub for external HSM integration)
# ---------------------------------------------------------------------------


class PKCS11KeyProvider(KeyProvider):
    """PKCS#11 HSM key provider (stub — requires external HSM hardware).

    This provider delegates key operations to an external HSM via
    the PKCS#11 interface.  When implemented, it will support:
    - HSM-resident key generation (keys never leave the HSM)
    - HSM-based HMAC and RSA/EC signing
    - Key rotation via HSM key versioning
    - Audit logging of all HSM operations

    To enable: install python3-pkcs11 and configure the PKCS#11
    module path and slot ID in keystore.yaml.
    """

    def __init__(
        self,
        module_path: str = "",
        slot_id: int = 0,
        pin: str = "",
    ):
        self._module_path = module_path
        self._slot_id = slot_id
        self._pin = pin
        self._available = False

        if module_path and os.path.isfile(module_path):
            try:
                import pkcs11  # type: ignore[import-not-found]
                self._available = True
                log.info("PKCS#11 module loaded: %s", module_path)
            except ImportError:
                log.warning("python3-pkcs11 not installed — "
                            "PKCS#11 provider unavailable")

    def sign(self, data: bytes, key_id: str = "default") -> bytes:
        raise NotImplementedError(
            "PKCS#11 signing requires HSM hardware and python3-pkcs11. "
            "Configure module_path in keystore.yaml."
        )

    def verify(self, data: bytes, signature: bytes,
               key_id: str = "default") -> bool:
        raise NotImplementedError("PKCS#11 verify requires HSM hardware")

    def get_key(self, key_id: str = "default") -> bytes:
        raise NotImplementedError(
            "HSM keys are non-extractable by design. "
            "Use sign/verify operations instead."
        )

    def rotate(self, key_id: str = "default") -> str:
        return "not implemented (requires HSM hardware)"

    def provider_name(self) -> str:
        return "pkcs11"

    def status(self) -> dict[str, Any]:
        return {
            "provider": "pkcs11",
            "available": self._available,
            "module_path": self._module_path,
            "slot_id": self._slot_id,
        }


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

_DEFAULT_KEYSTORE_CONFIG = "/etc/secure-ai/policy/keystore.yaml"


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load keystore configuration from YAML."""
    path = config_path or _DEFAULT_KEYSTORE_CONFIG
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        log.info("loaded keystore config from %s", path)
        return cfg
    except (OSError, yaml.YAMLError) as exc:
        log.info("no keystore config at %s (%s), using defaults", path, exc)
        return {}


def create_provider(config: dict[str, Any] | None = None) -> KeyProvider:
    """Create the appropriate KeyProvider based on configuration.

    Selection priority:
    1. PKCS#11 HSM (if configured and hardware available)
    2. TPM2 (if tpm2-tools installed and keys exist)
    3. Software (always available, default)
    """
    cfg = config or {}
    backend = cfg.get("backend", "auto")

    # Explicit PKCS#11
    if backend == "pkcs11":
        pkcs_cfg = cfg.get("pkcs11", {})
        provider = PKCS11KeyProvider(
            module_path=pkcs_cfg.get("module_path", ""),
            slot_id=pkcs_cfg.get("slot_id", 0),
            pin=pkcs_cfg.get("pin", ""),
        )
        if provider._available:
            log.info("using PKCS#11 key provider")
            return provider
        log.warning("PKCS#11 requested but not available, falling back")

    # Explicit or auto TPM2
    if backend in ("tpm2", "auto"):
        tpm_cfg = cfg.get("tpm2", {})
        key_dir = tpm_cfg.get("key_dir",
                              "/var/lib/secure-ai/keys/tpm2")
        pcr_list = tpm_cfg.get("pcr_list", "sha256:0,2,4,7")
        provider = TPM2KeyProvider(key_dir=key_dir, pcr_list=pcr_list)
        if provider._available and backend == "tpm2":
            log.info("using TPM2 key provider")
            return provider

    # Software fallback (always works)
    sw_cfg = cfg.get("software", {})
    key_dir = sw_cfg.get("key_dir", "/run/secure-ai")
    default_key = sw_cfg.get("default_key_path", "")
    log.info("using software key provider (key_dir=%s)", key_dir)
    return SoftwareKeyProvider(
        key_dir=key_dir,
        default_key_path=default_key or None,
    )
