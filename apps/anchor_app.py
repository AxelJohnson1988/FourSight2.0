"""Gradio web app for hashing content and generating OP_RETURN payloads.

Usage:
    python apps/anchor_app.py              # local only (share=False)
    python apps/anchor_app.py --share      # enable public Gradio link
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path


def _read_uploaded_file(file_obj) -> bytes:  # type: ignore[type-arg]
    """Read bytes from a Gradio file object.

    Gradio 4.x passes an object whose ``.name`` attribute is a temporary file
    path managed by Gradio.  We validate it is a regular file inside the
    system temporary directory before opening.
    """
    if hasattr(file_obj, "read"):
        return file_obj.read()

    # file_obj is a path-like or string pointing to Gradio's temp file
    raw_path = getattr(file_obj, "name", file_obj)
    candidate = Path(str(raw_path)).resolve()

    # Restrict access to files inside the system temp directory
    tmp_root = Path(tempfile.gettempdir()).resolve()
    try:
        candidate.relative_to(tmp_root)
    except ValueError:
        raise ValueError("Uploaded file is not in the expected temporary directory.")
    if not candidate.is_file():
        raise ValueError("Uploaded path is not a regular file.")

    return candidate.read_bytes()


def process_payload(text_input: str, file_obj) -> str:  # type: ignore[type-arg]
    """Hash optional text + optional file and return the anchor result."""
    from phoenix_scanner.anchoring import build_op_return_payload

    payload = b""
    if text_input:
        payload += text_input.encode("utf-8")

    if file_obj is not None:
        try:
            payload += _read_uploaded_file(file_obj)
        except Exception as exc:  # noqa: BLE001
            return f"Error reading uploaded file: {type(exc).__name__}"

    if not payload:
        return "⚠️  Please provide text and/or upload a file."

    sha256_hex = hashlib.sha256(payload).hexdigest()
    op_return = build_op_return_payload(sha256_hex)

    return (
        f"SHA-256:           {sha256_hex}\n"
        f"OP_RETURN payload: {op_return}\n\n"
        f"Next steps:\n"
        f"  1. Copy the OP_RETURN payload above.\n"
        f"  2. Embed it in a Bitcoin transaction output (max 80 bytes).\n"
        f"  3. Record the transaction ID as your on-chain timestamp proof."
    )


def build_app(share: bool = False):  # type: ignore[no-untyped-def]
    try:
        import gradio as gr
    except ImportError:
        print("Gradio is not installed. Run: pip install gradio", file=sys.stderr)
        sys.exit(1)

    with gr.Blocks(title="ALEE Sovereign Anchor") as demo:
        gr.Markdown(
            "# ALEE Sovereign Anchor\n\n"
            "Hash your content and generate a Bitcoin `OP_RETURN` payload for "
            "on-chain timestamping.\n\n"
            "⚠️ **Do not upload documents containing private keys, passwords, "
            "or other sensitive secrets.**"
        )
        with gr.Row():
            text_in = gr.Textbox(
                label="Text payload (optional)",
                placeholder="Paste text here…",
                lines=5,
            )
            file_in = gr.File(label="File upload (optional)")

        btn = gr.Button("Generate Anchor")
        output = gr.Textbox(label="Result", lines=8, interactive=False)

        btn.click(fn=process_payload, inputs=[text_in, file_in], outputs=output)

    return demo, share


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="ALEE Anchor Gradio app")
    parser.add_argument(
        "--share",
        action="store_true",
        default=False,
        help="Enable public Gradio share link (default: False)",
    )
    parser.add_argument("--port", type=int, default=7860)
    args = parser.parse_args(argv)

    demo, share = build_app(share=args.share)
    demo.launch(share=share, server_port=args.port)


if __name__ == "__main__":
    main()
