"""Gradio web app for running a crawl+scan and viewing results.

Usage:
    python apps/scan_app.py               # local only (share=False)
    python apps/scan_app.py --share       # enable public Gradio link
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


def run_scan(root_dir: str, text_only: bool, redact: bool, keywords: str) -> str:
    """Crawl *root_dir* and scan, returning a summary string."""
    try:
        from phoenix_scanner.config import Config
        from phoenix_scanner.crawler import crawl, write_manifest
        from phoenix_scanner.scanner import scan, write_findings
    except ImportError as exc:
        return f"Import error: {exc}\nInstall with: pip install -e ."

    if not root_dir.strip():
        return "⚠️  Please enter a directory path."

    root = Path(root_dir.strip())
    if not root.exists():
        return f"⚠️  Directory does not exist: {root}"

    kw_list = [k.strip() for k in keywords.split(",") if k.strip()]

    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = Path(tmp) / "manifest.jsonl"
        findings_path = Path(tmp) / "findings.jsonl"

        cfg = Config(
            root_dir=root,
            text_only=text_only,
            redact_matches=redact,
            extra_keywords=kw_list,
            manifest_path=manifest_path,
            findings_path=findings_path,
        )

        try:
            entries = crawl(cfg, max_workers=2)
            write_manifest(entries, manifest_path)
            findings = scan(entries, cfg)
            write_findings(findings, findings_path)
        except Exception as exc:  # noqa: BLE001
            return f"Error during scan: {exc}"

        by_type: dict[str, list[str]] = {}
        for f in findings:
            by_type.setdefault(f.match_type, []).append(f.file_path)

        lines: list[str] = [
            f"Scanned {len(entries)} files, found {len(findings)} matches.\n"
        ]
        for mtype, paths in sorted(by_type.items()):
            lines.append(f"\n[{mtype}] — {len(paths)} match(es)")
            for p in sorted(set(paths))[:10]:
                lines.append(f"  {p}")
            if len(set(paths)) > 10:
                lines.append(f"  … and {len(set(paths)) - 10} more files")

        return "\n".join(lines)


def build_app(share: bool = False):  # type: ignore[no-untyped-def]
    try:
        import gradio as gr
    except ImportError:
        print("Gradio is not installed. Run: pip install gradio", file=sys.stderr)
        sys.exit(1)

    with gr.Blocks(title="Phoenix Scanner") as demo:
        gr.Markdown(
            "# Phoenix Scanner\n\n"
            "Crawl a directory and scan for cryptographic artefacts.\n\n"
            "⚠️ **Do not scan directories containing private keys or passwords "
            "unless you have enabled the redact option.**"
        )
        with gr.Row():
            root_in = gr.Textbox(
                label="Directory to scan",
                placeholder="/path/to/directory",
            )
        with gr.Row():
            text_only = gr.Checkbox(label="Text files only", value=True)
            redact = gr.Checkbox(label="Redact match text in output", value=False)
        keywords_in = gr.Textbox(
            label="Extra keywords (comma-separated, optional)",
            placeholder="verify_and_timestamp.sh, Master Proof Hash",
        )
        btn = gr.Button("Run Scan")
        output = gr.Textbox(label="Results", lines=20, interactive=False)

        btn.click(
            fn=run_scan,
            inputs=[root_in, text_only, redact, keywords_in],
            outputs=output,
        )

    return demo, share


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Phoenix Scanner Gradio app")
    parser.add_argument("--share", action="store_true", default=False)
    parser.add_argument("--port", type=int, default=7861)
    args = parser.parse_args(argv)

    demo, share = build_app(share=args.share)
    demo.launch(share=share, server_port=args.port)


if __name__ == "__main__":
    main()
