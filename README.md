# Phoenix Scanner

A modular, composable cryptographic scanning toolkit.

## Features

| Module | What it does |
|---|---|
| `crawler` | Multi-process Drive / filesystem indexer; resumable JSONL manifest |
| `scanner` | Chunked regex scanning (CPU + optional GPU via cuDF) |
| `ledger` | Tamper-evident evidence package with optional Ed25519 signature |
| `anchoring` | SHA-256 + Bitcoin `OP_RETURN` payload generator |
| `keys` | Ed25519 key ceremony with safe storage defaults |
| `apps/anchor_app.py` | Gradio UI for hashing + anchoring |
| `apps/scan_app.py` | Gradio UI for crawl-and-scan |

## Quickstart

### Install

```bash
pip install -e .               # core (cryptography only)
pip install -e ".[dev]"        # + pytest, rich, requests
pip install -e ".[ui]"         # + gradio
pip install -e ".[gpu]"        # + cudf-cu11 (requires CUDA)
```

### CLI

```bash
# Crawl a directory tree → manifest.jsonl
phoenix-scanner crawl /path/to/drive --output manifest.jsonl

# Scan the manifest → findings.jsonl
phoenix-scanner scan manifest.jsonl --output findings.jsonl

# Crawl + scan in one step
phoenix-scanner crawl-scan /path/to/drive

# Hash text / file and get an OP_RETURN payload
phoenix-scanner anchor --text "Hello, world"
phoenix-scanner anchor --file important_document.pdf

# Generate an Ed25519 keypair (one-time ceremony)
phoenix-scanner key-ceremony --directory ./keys
```

### Python API

```python
from pathlib import Path
from phoenix_scanner.config import Config
from phoenix_scanner.crawler import crawl, write_manifest
from phoenix_scanner.scanner import scan, write_findings
from phoenix_scanner.ledger import write_ledger
from phoenix_scanner.anchoring import anchor

cfg = Config(root_dir=Path("/my/drive"), text_only=True)
entries = crawl(cfg)
write_manifest(entries, cfg.manifest_path)

findings = scan(entries, cfg)
write_findings(findings, cfg.findings_path)

write_ledger(cfg.findings_path, cfg.summary_path)
result = anchor(text="My document content")
print(result["op_return_payload"])
```

### Gradio Apps

```bash
python apps/anchor_app.py          # opens on http://localhost:7860
python apps/scan_app.py            # opens on http://localhost:7861
```

### Google Colab

Open `Copy_of_Phoenix_GPU_Cryptographic_Scanner2.ipynb` in Colab.  The first
cells install dependencies and mount Google Drive; subsequent cells import
directly from `phoenix_scanner`.

## Running Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Security

See [SECURITY.md](SECURITY.md) for key handling and safe defaults.
