# Security Policy

## Key Handling

### Ed25519 Keys

* **Never commit private key files** (`.priv`) to version control.  
  Add `*.priv` to your `.gitignore`.
* The key ceremony (`phoenix-scanner key-ceremony` / `perform_key_ceremony()`)
  writes the private key file with mode `0o600` and warns you immediately.
* For signing operations the toolkit reads the private key **exclusively from
  the environment variable `PHOENIX_PRIVATE_KEY_HEX`** — never from disk in
  automated pipelines.
* Store the private key offline (air-gapped storage, hardware security module,
  or encrypted secrets manager).

### Private Key env var

```bash
export PHOENIX_PRIVATE_KEY_HEX="$(xxd -p -c 32 signing_key.priv)"
phoenix-scanner scan manifest.jsonl          # ledger will be signed
unset PHOENIX_PRIVATE_KEY_HEX               # clear after use
```

## Gradio Apps

* Both `apps/anchor_app.py` and `apps/scan_app.py` default to `share=False`
  (no public Gradio tunnel).
* Enabling `--share` creates a temporary public URL — **do not** use this when
  processing confidential files.
* The UI displays an explicit warning about uploading sensitive files.

### Restricting the scan root (production deployments)

By default `scan_app.py` will scan any directory that the process user can
read.  In a shared or public deployment set `PHOENIX_SCAN_BASE_DIR` to
restrict scanning to a specific subtree:

```bash
export PHOENIX_SCAN_BASE_DIR="/safe/data/root"
python apps/scan_app.py
```

Any path the user enters that is not under `PHOENIX_SCAN_BASE_DIR` will be
rejected with an error message.

## Output Files

* `findings.jsonl` and `summary.json` may contain file paths and pattern
  matches from your drive.  Do not publish them without review.
* Use `--redact` / `Config(redact_matches=True)` to replace match text with
  `<REDACTED>` in the findings file.

## Dependency Supply Chain

* Keep dependencies minimal.  The core package requires only `cryptography`.
* Optional extras (`gradio`, `cudf-cu11`) are declared as extras in
  `pyproject.toml`.
* Pin dependencies in production deployments and verify hashes with
  `pip install --require-hashes`.

## Reporting Vulnerabilities

Please open a private GitHub security advisory rather than a public issue.
