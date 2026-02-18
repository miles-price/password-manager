from pathlib import Path

from vault import PasswordVault


def test_init_add_unlock_roundtrip(tmp_path: Path):
    vault_file = tmp_path / "vault.json"
    vault = PasswordVault(vault_file)

    vault.init_vault("strong-master-password")
    payload, key = vault.unlock("strong-master-password")

    rec = vault.add_record(
        payload,
        key,
        site="github.com",
        username="miles",
        password="super-secret",
        notes="personal",
    )

    payload2, key2 = vault.unlock("strong-master-password")
    found = vault.get_record(payload2, rec["id"])

    assert found is not None
    assert found["site"] == "github.com"
    assert vault.decrypted_password(found, key2) == "super-secret"


def test_unlock_with_wrong_password_fails(tmp_path: Path):
    vault_file = tmp_path / "vault.json"
    vault = PasswordVault(vault_file)
    vault.init_vault("correct-password")

    try:
        vault.unlock("wrong-password")
        assert False, "Expected unlock to fail"
    except ValueError:
        assert True


def test_update_and_delete_record(tmp_path: Path):
    vault_file = tmp_path / "vault.json"
    vault = PasswordVault(vault_file)
    vault.init_vault("correct-password")

    payload, key = vault.unlock("correct-password")
    rec = vault.add_record(payload, key, "gmail", "user1", "abc123", "")

    payload, key = vault.unlock("correct-password")
    updated = vault.update_record(payload, key, rec["id"], username="user2", password="newpass")
    assert updated is True

    payload, key = vault.unlock("correct-password")
    found = vault.get_record(payload, rec["id"])
    assert found is not None
    assert found["username"] == "user2"
    assert vault.decrypted_password(found, key) == "newpass"

    deleted = vault.delete_record(payload, rec["id"])
    assert deleted is True
