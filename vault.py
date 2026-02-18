from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from crypto_utils import decrypt_text, derive_key, encrypt_text, generate_salt

VAULT_FILE = Path("vault.json")
VERIFIER_TEXT = "password-manager-verifier"


@dataclass
class VaultRecord:
    id: str
    site: str
    username: str
    encrypted_password: str
    notes: str
    created_at: str
    updated_at: str


class PasswordVault:
    def __init__(self, vault_path: Path = VAULT_FILE):
        self.vault_path = vault_path

    def vault_exists(self) -> bool:
        return self.vault_path.exists()

    def init_vault(self, master_password: str) -> None:
        if self.vault_exists():
            raise ValueError("Vault already exists.")

        salt = generate_salt()
        key = derive_key(master_password, salt)
        verifier = encrypt_text(VERIFIER_TEXT, key)

        payload = {
            "version": 1,
            "salt": salt,
            "verifier": verifier,
            "records": [],
        }
        self._write(payload)

    def unlock(self, master_password: str) -> tuple[dict[str, Any], bytes]:
        payload = self._read()
        if not payload:
            raise ValueError("Vault not found. Run `python main.py init` first.")

        salt = payload.get("salt")
        verifier = payload.get("verifier")
        if not salt or not verifier:
            raise ValueError("Vault format is invalid.")

        key = derive_key(master_password, salt)
        if decrypt_text(verifier, key) != VERIFIER_TEXT:
            raise ValueError("Invalid master password.")

        return payload, key

    def list_records(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        return payload.get("records", [])

    def add_record(
        self,
        payload: dict[str, Any],
        key: bytes,
        site: str,
        username: str,
        password: str,
        notes: str,
    ) -> dict[str, Any]:
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        record = VaultRecord(
            id=str(uuid4()),
            site=site.strip(),
            username=username.strip(),
            encrypted_password=encrypt_text(password, key),
            notes=notes.strip(),
            created_at=now,
            updated_at=now,
        )
        payload.setdefault("records", []).append(record.__dict__)
        self._write(payload)
        return record.__dict__

    def get_record(self, payload: dict[str, Any], record_id: str) -> dict[str, Any] | None:
        for rec in payload.get("records", []):
            if rec.get("id") == record_id:
                return rec
        return None

    def update_record(
        self,
        payload: dict[str, Any],
        key: bytes,
        record_id: str,
        site: str | None = None,
        username: str | None = None,
        password: str | None = None,
        notes: str | None = None,
    ) -> bool:
        record = self.get_record(payload, record_id)
        if not record:
            return False

        if site is not None:
            record["site"] = site.strip()
        if username is not None:
            record["username"] = username.strip()
        if notes is not None:
            record["notes"] = notes.strip()
        if password is not None:
            record["encrypted_password"] = encrypt_text(password, key)

        record["updated_at"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        self._write(payload)
        return True

    def delete_record(self, payload: dict[str, Any], record_id: str) -> bool:
        records = payload.get("records", [])
        filtered = [r for r in records if r.get("id") != record_id]
        if len(filtered) == len(records):
            return False
        payload["records"] = filtered
        self._write(payload)
        return True

    def decrypted_password(self, record: dict[str, Any], key: bytes) -> str:
        return decrypt_text(record["encrypted_password"], key)

    def _read(self) -> dict[str, Any]:
        if not self.vault_path.exists():
            return {}
        try:
            return json.loads(self.vault_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Vault file is corrupted JSON.") from exc

    def _write(self, payload: dict[str, Any]) -> None:
        self.vault_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
