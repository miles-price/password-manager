from __future__ import annotations

import argparse
import getpass
import secrets
import string
from pathlib import Path

from vault import PasswordVault


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Encrypted local password manager")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize encrypted vault")

    add = sub.add_parser("add", help="Add a password entry")
    add.add_argument("--site", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--notes", default="")
    add.add_argument("--password", help="Optional plaintext password; prompts if omitted")

    sub.add_parser("list", help="List saved entries")

    show = sub.add_parser("show", help="Show a saved entry and decrypt password")
    show.add_argument("id", help="Record ID")

    upd = sub.add_parser("update", help="Update fields for an entry")
    upd.add_argument("id", help="Record ID")
    upd.add_argument("--site")
    upd.add_argument("--username")
    upd.add_argument("--notes")
    upd.add_argument("--password")
    upd.add_argument("--prompt-password", action="store_true")

    delete = sub.add_parser("delete", help="Delete an entry")
    delete.add_argument("id", help="Record ID")

    gen = sub.add_parser("generate", help="Generate a random strong password")
    gen.add_argument("--length", type=int, default=20)

    parser.add_argument("--vault", default="vault.json", help="Path to vault file")
    return parser


def _generate_password(length: int) -> str:
    if length < 12:
        raise ValueError("Use a length of at least 12.")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _prompt_master(confirm: bool = False) -> str:
    pw = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            raise ValueError("Passwords do not match.")
    if len(pw) < 8:
        raise ValueError("Master password must be at least 8 characters.")
    return pw


def main() -> None:
    args = _parser().parse_args()
    vault = PasswordVault(Path(args.vault))

    if args.command == "init":
        master = _prompt_master(confirm=True)
        vault.init_vault(master)
        print(f"Vault created at {args.vault}")
        return

    if args.command == "generate":
        print(_generate_password(args.length))
        return

    master = _prompt_master()
    payload, key = vault.unlock(master)

    if args.command == "add":
        password = args.password or getpass.getpass("Password to store: ")
        record = vault.add_record(payload, key, args.site, args.username, password, args.notes)
        print(f"Saved record: {record['id']}")

    elif args.command == "list":
        records = vault.list_records(payload)
        if not records:
            print("No records found.")
            return
        for rec in records:
            print(f"{rec['id']} | {rec['site']} | {rec['username']} | updated {rec['updated_at']}")

    elif args.command == "show":
        rec = vault.get_record(payload, args.id)
        if not rec:
            print("Record not found.")
            return
        print(f"ID: {rec['id']}")
        print(f"Site: {rec['site']}")
        print(f"Username: {rec['username']}")
        print(f"Password: {vault.decrypted_password(rec, key)}")
        print(f"Notes: {rec['notes']}")

    elif args.command == "update":
        password = args.password
        if args.prompt_password:
            password = getpass.getpass("New password: ")

        ok = vault.update_record(
            payload,
            key,
            args.id,
            site=args.site,
            username=args.username,
            notes=args.notes,
            password=password,
        )
        print("Updated." if ok else "Record not found.")

    elif args.command == "delete":
        ok = vault.delete_record(payload, args.id)
        print("Deleted." if ok else "Record not found.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)
