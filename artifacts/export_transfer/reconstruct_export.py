"""Reconstruct and verify the Assignment 02 export from tracked Base64 chunks."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reconstruct(manifest_path: Path, output_path: Path | None = None) -> Path:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    directory = manifest_path.parent
    encoded_parts: list[str] = []
    for entry in manifest["ordered_chunks"]:
        chunk_path = directory / entry["filename"]
        raw = chunk_path.read_bytes()
        if len(raw) != entry["size_bytes"]:
            raise ValueError(f"chunk size mismatch: {chunk_path.name}")
        if sha256(raw) != entry["sha256"]:
            raise ValueError(f"chunk SHA-256 mismatch: {chunk_path.name}")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(f"chunk is not ASCII/UTF-8 text: {chunk_path.name}") from exc
        encoded_parts.append("".join(text.split()))

    compact = "".join(encoded_parts)
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("strict Base64 decoding failed") from exc
    if len(decoded) != manifest["original_size_bytes"]:
        raise ValueError("reconstructed ZIP size mismatch")
    if sha256(decoded) != manifest["original_sha256"]:
        raise ValueError("reconstructed ZIP SHA-256 mismatch")

    destination = output_path or directory / manifest["original_filename"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(decoded)
    temporary.replace(destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("manifest.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = reconstruct(args.manifest, args.output)
    print(f"Verified export written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
