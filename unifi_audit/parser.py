from __future__ import annotations

import gzip
import pathlib
from collections import defaultdict
from typing import Any, Iterable

from bson import BSON


class ParseError(RuntimeError):
    pass


def _find_db_file(root: pathlib.Path) -> pathlib.Path:
    candidates = list(root.rglob("db.gz")) + list(root.rglob("db"))
    if not candidates:
        raise ParseError("Could not find db.gz or db file in extracted backup.")
    return candidates[0]


def _load_db_bytes(db_file: pathlib.Path) -> bytes:
    if db_file.suffix == ".gz":
        return gzip.decompress(db_file.read_bytes())
    return db_file.read_bytes()


def _iter_bson_stream(raw: bytes, collection_prefilter: set[bytes] | None = None) -> Iterable[dict[str, Any]]:
    idx = 0
    total = len(raw)
    while idx + 4 <= total:
        size = int.from_bytes(raw[idx : idx + 4], "little", signed=True)
        if size < 5 or idx + size > total:
            # Some controller variants may embed BSON in larger binary payloads.
            # Resync by scanning forward one byte instead of aborting at first miss.
            idx += 1
            continue
        blob = raw[idx : idx + size]
        if collection_prefilter:
            # Fast path: skip full BSON decode when this blob clearly does not
            # mention any targeted collection names.
            blob_lower = blob.lower()
            if not any(token in blob_lower for token in collection_prefilter):
                idx += size
                continue
        try:
            yield BSON(blob).decode()
        except Exception:
            idx += 1
            continue
        idx += size


def _normalize_collections(
    docs: Iterable[dict[str, Any]], allowlist: set[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    collections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unmatched_docs: list[dict[str, Any]] = []
    seen_any = False
    allow = {x.lower() for x in allowlist} if allowlist else None

    def allowed(name: str) -> bool:
        return allow is None or name.lower() in allow

    for doc in docs:
        seen_any = True
        if "collection" in doc and isinstance(doc.get("documents"), list):
            name = str(doc["collection"])
            if allowed(name):
                collections[name].extend([d for d in doc["documents"] if isinstance(d, dict)])
            continue

        if "_id" in doc and isinstance(doc.get("value"), list) and isinstance(doc["_id"], str):
            name = doc["_id"]
            if allowed(name):
                collections[name].extend([d for d in doc["value"] if isinstance(d, dict)])
            continue

        if len(doc) == 1:
            name, value = next(iter(doc.items()))
            if isinstance(name, str) and isinstance(value, list):
                if allowed(name):
                    collections[name].extend([d for d in value if isinstance(d, dict)])
                continue

        if isinstance(doc, dict):
            unmatched_docs.append(doc)

    if not seen_any:
        raise ParseError("No BSON documents decoded from database stream.")
    if unmatched_docs:
        collections["__raw_docs"] = unmatched_docs
    return dict(collections)


def load_collections(
    extracted_root: pathlib.Path, allowlist: set[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    db_file = _find_db_file(extracted_root)
    raw = _load_db_bytes(db_file)
    prefilter = None
    if allowlist:
        prefilter = {name.lower().encode("utf-8") for name in allowlist if name}
    collections = _normalize_collections(_iter_bson_stream(raw, collection_prefilter=prefilter), allowlist=allowlist)

    # Compatibility fallback: if allowlisted + prefiltered parsing produced no usable
    # collections, retry full decode to support schema variants where collection hints
    # are not easily matched in raw BSON blobs.
    if allowlist and not collections:
        full = _normalize_collections(_iter_bson_stream(raw, collection_prefilter=None), allowlist=None)
        allow_l = {name.lower() for name in allowlist}
        filtered = {k: v for k, v in full.items() if k.lower() in allow_l}
        # If schema names don't match allowlist aliases (common across controller
        # versions/platforms), return full collections so downstream key-based
        # discovery can still evaluate rules.
        return filtered if filtered else full
    return collections


def find_db_file(extracted_root: pathlib.Path) -> pathlib.Path:
    return _find_db_file(extracted_root)


def decode_bson_stream(raw: bytes) -> list[dict[str, Any]]:
    docs = list(_iter_bson_stream(raw))
    if not docs:
        raise ParseError("No BSON documents decoded from database stream.")
    return docs


def encode_bson_stream(docs: list[dict[str, Any]]) -> bytes:
    encoded_parts: list[bytes] = []
    for doc in docs:
        if isinstance(doc, dict):
            encoded_parts.append(BSON.encode(doc))
    if not encoded_parts:
        raise ParseError("No BSON documents to encode.")
    return b"".join(encoded_parts)


def load_raw_docs(extracted_root: pathlib.Path) -> list[dict[str, Any]]:
    db_file = _find_db_file(extracted_root)
    raw = _load_db_bytes(db_file)
    return decode_bson_stream(raw)


def write_raw_docs(extracted_root: pathlib.Path, docs: list[dict[str, Any]]) -> pathlib.Path:
    db_file = _find_db_file(extracted_root)
    payload = encode_bson_stream(docs)
    if db_file.suffix == ".gz":
        db_file.write_bytes(gzip.compress(payload))
    else:
        db_file.write_bytes(payload)
    return db_file
