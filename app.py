from __future__ import annotations

import json
from pathlib import Path
import re
import secrets
import string

import streamlit as st

from vault import PasswordVault


st.set_page_config(page_title="Password Manager", layout="wide")
st.title("Password Manager")
st.caption("Encrypted vault demo built with Python + Streamlit.")

VAULT_CATALOG_FILE = Path(".vault_registry.json")


def generate_password(length: int) -> str:
    if length < 12:
        raise ValueError("Use at least 12 characters.")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def slugify_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip().lower()).strip("-")
    return cleaned or "vault"


def infer_vault_name(path: str) -> str:
    stem = Path(path).stem.replace(".vault", "")
    if not stem:
        return "Vault"
    return stem.replace("-", " ").replace("_", " ").title()


def load_vault_catalog() -> list[dict[str, str]]:
    catalog: list[dict[str, str]] = []
    if VAULT_CATALOG_FILE.exists():
        try:
            raw = json.loads(VAULT_CATALOG_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, dict) and item.get("path"):
                        vault_path = str(item["path"])
                        if Path(vault_path).exists():
                            catalog.append(
                                {
                                    "name": str(item.get("name") or infer_vault_name(vault_path)),
                                    "path": vault_path,
                                }
                            )
        except json.JSONDecodeError:
            pass

    discovered = sorted(Path(".").glob("*.vault.json")) + [Path("vault.json")]
    for path_obj in discovered:
        vault_path = str(path_obj)
        if path_obj.exists() and all(item["path"] != vault_path for item in catalog):
            catalog.append({"name": infer_vault_name(vault_path), "path": vault_path})

    if not catalog:
        catalog = [{"name": "Default Vault", "path": "vault.json"}]

    save_vault_catalog(catalog)
    return catalog


def save_vault_catalog(catalog: list[dict[str, str]]) -> None:
    VAULT_CATALOG_FILE.write_text(json.dumps(catalog, indent=2), encoding="utf-8")


def register_vault(name: str, path: str) -> None:
    catalog = load_vault_catalog()
    for item in catalog:
        if item["path"] == path:
            item["name"] = name.strip() or item["name"]
            save_vault_catalog(catalog)
            return
    catalog.append({"name": name.strip() or infer_vault_name(path), "path": path})
    save_vault_catalog(catalog)


def require_unlocked() -> tuple[PasswordVault, dict, bytes]:
    vault_path = Path(st.session_state.get("vault_path", "vault.json"))
    vault = PasswordVault(vault_path)
    payload = st.session_state.get("payload")
    key = st.session_state.get("key")

    if payload is None or key is None:
        raise RuntimeError("Vault is locked")

    return vault, payload, key


def lock_vault() -> None:
    st.session_state.pop("payload", None)
    st.session_state.pop("key", None)
    st.session_state.pop("revealed_record_id", None)


with st.sidebar:
    st.header("Vault Settings")
    catalog = load_vault_catalog()
    labels = [f"{item['name']} ({item['path']})" for item in catalog]
    paths = [item["path"] for item in catalog]

    selected_path = st.session_state.get("vault_path", paths[0])
    selected_index = paths.index(selected_path) if selected_path in paths else 0
    selected_label = st.selectbox("Choose vault", options=labels, index=selected_index)
    next_path = paths[labels.index(selected_label)]

    if next_path != st.session_state.get("vault_path"):
        st.session_state["vault_path"] = next_path
        lock_vault()
        st.rerun()

    vault_path = st.session_state.get("vault_path", next_path)

    if st.button("Lock Vault"):
        lock_vault()
        st.rerun()

    st.info("For demo use, deploy with a dedicated vault path. Never commit `vault.json`.")

vault = PasswordVault(Path(vault_path))

# Locked state UI
if "payload" not in st.session_state or "key" not in st.session_state:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Initialize Vault")
        if vault.vault_exists():
            st.caption("Vault already exists. Use unlock on the right.")
        with st.form("init_form"):
            vault_name = st.text_input("Vault name", placeholder="Personal Vault")
            init_master = st.text_input("Master password", type="password")
            init_master_confirm = st.text_input("Confirm master password", type="password")
            init_submit = st.form_submit_button("Create vault")

        if init_submit:
            if not vault_name.strip():
                st.error("Vault name is required.")
            elif len(init_master) < 8:
                st.error("Master password must be at least 8 characters.")
            elif init_master != init_master_confirm:
                st.error("Passwords do not match.")
            else:
                file_name = f"{slugify_name(vault_name)}.vault.json"
                target_vault = PasswordVault(Path(file_name))
                try:
                    target_vault.init_vault(init_master)
                    register_vault(vault_name, file_name)
                    st.session_state["vault_path"] = file_name
                    st.success(f"Vault '{vault_name}' created. Unlock it from the right panel.")
                except ValueError as exc:
                    st.error(str(exc))

    with col2:
        st.subheader("Unlock Vault")
        with st.form("unlock_form"):
            unlock_master = st.text_input("Master password", type="password", key="unlock_master")
            unlock_submit = st.form_submit_button("Unlock")

        if unlock_submit:
            try:
                payload, key = vault.unlock(unlock_master)
                st.session_state["payload"] = payload
                st.session_state["key"] = key
                st.success("Vault unlocked.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

    st.stop()

vault, payload, key = require_unlocked()

st.success("Vault unlocked")

add_tab, list_tab, manage_tab, gen_tab = st.tabs(["Add Entry", "Entries", "Manage Entry", "Generate Password"])

with add_tab:
    st.subheader("Add Entry")
    with st.form("add_entry_form", clear_on_submit=True):
        site = st.text_input("Site", placeholder="github.com")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        notes = st.text_area("Notes", placeholder="Optional")
        add_submit = st.form_submit_button("Save entry")

    if add_submit:
        if not site.strip() or not username.strip() or not password:
            st.error("Site, username, and password are required.")
        else:
            vault.add_record(payload, key, site, username, password, notes)
            st.success("Entry saved.")
            st.rerun()

with list_tab:
    st.subheader("Saved Entries")
    records = vault.list_records(payload)

    if not records:
        st.info("No entries yet.")
    else:
        display_rows = [
            {
                "id": rec["id"],
                "site": rec["site"],
                "username": rec["username"],
                "notes": rec.get("notes", ""),
                "updated_at": rec.get("updated_at", ""),
            }
            for rec in records
        ]
        st.dataframe(display_rows, use_container_width=True)

with manage_tab:
    st.subheader("View / Update / Delete")
    records = vault.list_records(payload)

    if not records:
        st.info("No entries to manage.")
    else:
        options = [f"{r['id']} | {r['site']} | {r['username']}" for r in records]
        selected = st.selectbox("Select record", options)
        selected_id = selected.split(" | ")[0]
        record = vault.get_record(payload, selected_id)

        if record:
            st.markdown(f"**Site:** {record['site']}")
            st.markdown(f"**Username:** {record['username']}")
            st.markdown(f"**Notes:** {record.get('notes', '') or '(none)'}")

            revealed = st.session_state.get("revealed_record_id") == selected_id

            if not revealed and st.button("Reveal password", key=f"reveal_{selected_id}"):
                st.session_state["revealed_record_id"] = selected_id
                st.rerun()

            if revealed:
                st.code(vault.decrypted_password(record, key))
                if st.button("Hide password", key=f"hide_{selected_id}"):
                    st.session_state.pop("revealed_record_id", None)
                    st.rerun()

            st.markdown("### Update Record")
            with st.form("update_form"):
                new_site = st.text_input("Site", value=record["site"])
                new_username = st.text_input("Username", value=record["username"])
                new_notes = st.text_area("Notes", value=record.get("notes", ""))
                new_password = st.text_input("New password (optional)", type="password")
                update_submit = st.form_submit_button("Update")

            if update_submit:
                updated = vault.update_record(
                    payload,
                    key,
                    selected_id,
                    site=new_site,
                    username=new_username,
                    notes=new_notes,
                    password=new_password if new_password else None,
                )
                if updated:
                    st.success("Record updated.")
                    st.rerun()
                else:
                    st.error("Record not found.")

            st.markdown("### Delete Record")
            confirm_delete = st.checkbox("I understand this cannot be undone")
            if st.button("Delete selected record", type="secondary", disabled=not confirm_delete):
                deleted = vault.delete_record(payload, selected_id)
                if deleted:
                    if st.session_state.get("revealed_record_id") == selected_id:
                        st.session_state.pop("revealed_record_id", None)
                    st.success("Record deleted.")
                    st.rerun()
                else:
                    st.error("Record not found.")

with gen_tab:
    st.subheader("Generate Strong Password")
    length = st.slider("Length", min_value=12, max_value=64, value=20)

    if st.button("Generate"):
        st.code(generate_password(length))
