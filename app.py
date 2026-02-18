from __future__ import annotations

from pathlib import Path
import secrets
import string

import streamlit as st

from vault import PasswordVault


st.set_page_config(page_title="Password Manager", layout="wide")
st.title("Password Manager")
st.caption("Encrypted vault demo built with Python + Streamlit.")


def generate_password(length: int) -> str:
    if length < 12:
        raise ValueError("Use at least 12 characters.")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


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


with st.sidebar:
    st.header("Vault Settings")
    vault_path = st.text_input("Vault file", value=st.session_state.get("vault_path", "vault.json"))
    st.session_state["vault_path"] = vault_path

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
            init_master = st.text_input("Master password", type="password")
            init_master_confirm = st.text_input("Confirm master password", type="password")
            init_submit = st.form_submit_button("Create vault")

        if init_submit:
            if vault.vault_exists():
                st.error("Vault already exists.")
            elif len(init_master) < 8:
                st.error("Master password must be at least 8 characters.")
            elif init_master != init_master_confirm:
                st.error("Passwords do not match.")
            else:
                try:
                    vault.init_vault(init_master)
                    st.success("Vault created. Unlock it from the right panel.")
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

            if st.button("Reveal password"):
                st.code(vault.decrypted_password(record, key))

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
                    st.success("Record deleted.")
                    st.rerun()
                else:
                    st.error("Record not found.")

with gen_tab:
    st.subheader("Generate Strong Password")
    length = st.slider("Length", min_value=12, max_value=64, value=20)

    if st.button("Generate"):
        st.code(generate_password(length))
