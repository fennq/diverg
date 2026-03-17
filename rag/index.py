"""
RAG index — build and hold chunks from content/ (exploit catalog, prevention docs, discovered exploits).
Used to ground findings with citations. No external embedding API required; uses token-overlap scoring.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CONTENT_DIR = Path(__file__).resolve().parent.parent / "content"
INDEX: list[dict[str, Any]] = []
_INDEX_BUILT = False


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alnum, drop short tokens."""
    return [t.lower() for t in re.split(r"\W+", (text or "")) if len(t) >= 2]


def _chunk_md_by_headers(path: Path, content: str) -> list[dict[str, Any]]:
    """Split markdown by ## or ###; each section is a chunk."""
    chunks = []
    current = []
    header = ""
    for line in content.splitlines():
        if line.startswith("## ") or line.startswith("### "):
            if current:
                chunks.append({
                    "id": f"{path.name}:{header[:50]}",
                    "text": "\n".join(current).strip(),
                    "source": str(path.name),
                    "chunk_type": "markdown_section",
                    "header": header.strip(),
                })
            header = line.lstrip("# ")
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append({
            "id": f"{path.name}:{header[:50]}",
            "text": "\n".join(current).strip(),
            "source": str(path.name),
            "chunk_type": "markdown_section",
            "header": header.strip(),
        })
    return chunks


def build_index(force: bool = False) -> list[dict[str, Any]]:
    """Build in-memory index from content/. Idempotent unless force=True."""
    global INDEX, _INDEX_BUILT
    if _INDEX_BUILT and not force:
        return INDEX
    INDEX = []
    # 1) exploit_catalog.json — each exploit = one chunk
    catalog_path = CONTENT_DIR / "exploit_catalog.json"
    if catalog_path.exists():
        try:
            data = json.loads(catalog_path.read_text(encoding="utf-8"))
            for ex in data.get("exploits", []):
                text = " ".join([
                    str(ex.get("name", "")),
                    str(ex.get("owasp", "")),
                    str(ex.get("cwe", "")),
                    str(ex.get("prevention", "")),
                    " ".join(ex.get("keywords_title", [])),
                    " ".join(ex.get("keywords_category", [])),
                ])
                INDEX.append({
                    "id": ex.get("id", ""),
                    "text": text,
                    "source": "exploit_catalog.json",
                    "chunk_type": "exploit",
                    "prevention": ex.get("prevention", ""),
                    "name": ex.get("name", ""),
                })
        except Exception:
            pass
    # 2) EXPLOITS_AND_PREVENTION.md — sections
    prev_path = CONTENT_DIR / "EXPLOITS_AND_PREVENTION.md"
    if prev_path.exists():
        try:
            content = prev_path.read_text(encoding="utf-8")
            INDEX.extend(_chunk_md_by_headers(prev_path, content))
        except Exception:
            pass
    # 3) DISCOVERED_EXPLOITS.md — sections and table blocks
    disc_path = CONTENT_DIR / "DISCOVERED_EXPLOITS.md"
    if disc_path.exists():
        try:
            content = disc_path.read_text(encoding="utf-8")
            INDEX.extend(_chunk_md_by_headers(disc_path, content))
        except Exception:
            pass
    # 4) blockchain-investigation-runbook.md — methodology
    runbook_path = CONTENT_DIR / "blockchain-investigation-runbook.md"
    if runbook_path.exists():
        try:
            content = runbook_path.read_text(encoding="utf-8")
            for c in _chunk_md_by_headers(runbook_path, content):
                if len(c["text"]) > 100:
                    INDEX.append(c)
        except Exception:
            pass
    # 5) ZERO_FALSE_POSITIVE_PILLARS.md — methodology
    pillars_path = CONTENT_DIR / "ZERO_FALSE_POSITIVE_PILLARS.md"
    if pillars_path.exists():
        try:
            content = pillars_path.read_text(encoding="utf-8")
            for c in _chunk_md_by_headers(pillars_path, content):
                if len(c["text"]) > 80:
                    INDEX.append(c)
        except Exception:
            pass
    # Optional: embed chunks when OPENAI_API_KEY is set (maximum RAG quality)
    _embed_index_if_available()
    _INDEX_BUILT = True
    return INDEX


def _embed_index_if_available() -> None:
    """Fill chunk['embedding'] for each index chunk when OpenAI API key is set."""
    import os
    key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
    if not key or not INDEX:
        return
    try:
        from openai import OpenAI
        client = OpenAI()
        model = "text-embedding-3-small"
        for chunk in INDEX:
            text = (chunk.get("text") or "")[:8000]
            if not text:
                continue
            r = client.embeddings.create(model=model, input=text)
            chunk["embedding"] = r.data[0].embedding
    except Exception:
        pass


def get_index() -> list[dict[str, Any]]:
    """Return index; build if not yet built."""
    if not _INDEX_BUILT:
        build_index()
    return INDEX
