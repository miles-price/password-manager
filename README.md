# Password Manager

A secure, local-first password manager built with Python.

## Why I Built This

I built this project to demonstrate practical security-focused engineering: encryption, key derivation, secure credential storage, CLI product design, and testable backend logic.

## Features

- Master-password-protected encrypted vault
- Per-record credential storage (`site`, `username`, `password`, `notes`)
- AES-based authenticated encryption via `Fernet`
- PBKDF2 key derivation with per-vault random salt
- Two interfaces:
  - CLI (`main.py`) for terminal usage
  - Streamlit app (`app.py`) for live demo/web showcase
- CRUD operations: add, list, view, update, delete
- Random strong password generator
- Unit tests for core vault flows

## Tech Stack

- Python
- `cryptography`
- `streamlit`
- `argparse`
- `pytest`

## Quick Start

```bash
cd password-manager
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Web App (Demo)

```bash
streamlit run app.py
```

## Run CLI Version

Initialize your vault:

```bash
python main.py init
```

Add a password:

```bash
python main.py add --site github.com --username your_username
```

List records:

```bash
python main.py list
```

Show one record:

```bash
python main.py show <record_id>
```

Generate strong password:

```bash
python main.py generate --length 20
```

## Run Tests

```bash
pytest -q
```

## Deploy To Streamlit Community Cloud

1. Push this repo to GitHub.
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click `New app` and select:
   - Repository: `miles-price/password-manager`
   - Branch: `main`
   - Main file path: `app.py`
4. Click `Deploy`.

## Security Notes

- This project encrypts data at rest using a key derived from your master password.
- Losing your master password means vault data cannot be recovered.
- On hosted demos, use demo credentials only and avoid storing real sensitive passwords.
- This is a portfolio project and not a replacement for audited production password managers.
