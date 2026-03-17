"""
RAG retrieve — score chunks by token overlap or by embedding similarity (when OPENAI_API_KEY set).
Returns top-k citations for each finding. Optional: use best chunk to augment remediation.
"""

from __future__ import annotations

import math
import os
from collections import Counter
from typing import Any

from .index import get_index, _tokenize


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _score_chunk_embedding(query_embedding: list[float], chunk: dict[str, Any]) -> float:
    """Score chunk by embedding cosine similarity."""
    emb = chunk.get("embedding")
    if not emb or not query_embedding or len(emb) != len(query_embedding):
        return 0.0
    return _cosine_similarity(query_embedding, emb)


def _score_chunk(query_tokens: list[str], chunk: dict[str, Any]) -> float:
    """Token overlap score (TF-style). Chunk text is tokenized; score = sum of token counts in chunk for query tokens."""
    text = (chunk.get("text") or "")
    chunk_tokens = _tokenize(text)
    if not query_tokens or not chunk_tokens:
        return 0.0
    chunk_cnt = Counter(chunk_tokens)
    score = sum(chunk_cnt.get(t, 0) for t in query_tokens)
    # Normalize by query length so longer queries don't dominate
    return score / max(1, math.sqrt(len(query_tokens)))


def _get_query_embedding(query: str) -> list[float] | None:
    """Return query embedding when OpenAI is available."""
    if not os.environ.get("OPENAI_API_KEY") and not os.environ.get("OPENAI_KEY"):
        return None
    try:
        from openai import OpenAI
        client = OpenAI()
        r = client.embeddings.create(model="text-embedding-3-small", input=query[:8000])
        return r.data[0].embedding
    except Exception:
        return None


def retrieve(query: str, top_k: int = 3, min_score: float = 0.5) -> list[dict[str, Any]]:
    """Return top-k chunks most relevant to query. Uses embedding similarity when index has embeddings and OPENAI_API_KEY set; else token overlap."""
    index = get_index()
    if not index:
        return []
    scored = []
    use_embeddings = index and index[0].get("embedding") is not None
    if use_embeddings:
        query_emb = _get_query_embedding(query)
        if query_emb:
            for chunk in index:
                s = _score_chunk_embedding(query_emb, chunk)
                if s >= min_score * 0.3:  # embeddings: lower threshold
                    scored.append((s, chunk))
    if not scored:
        query_tokens = _tokenize(query)
        if not query_tokens:
            return []
        for chunk in index:
            s = _score_chunk(query_tokens, chunk)
            if s >= min_score:
                scored.append((s, chunk))
    scored.sort(key=lambda x: -x[0])
    out = []
    for s, c in scored[:top_k]:
        cite = {
            "source": c.get("source", ""),
            "chunk_id": c.get("id", ""),
            "score": round(s, 2),
            "snippet": (c.get("text") or "")[:400].strip(),
        }
        if c.get("prevention"):
            cite["prevention"] = c["prevention"]
        if c.get("name"):
            cite["name"] = c["name"]
        out.append(cite)
    return out


def retrieve_for_finding(finding: dict[str, Any], top_k: int = 3) -> list[dict[str, Any]]:
    """Build query from finding title + category + impact; return citations."""
    title = (finding.get("title") or "")
    category = (finding.get("category") or "")
    impact = (finding.get("impact") or "")
    evidence = (finding.get("evidence") or "")[:200]
    query = " ".join([title, category, impact, evidence])
    return retrieve(query, top_k=top_k, min_score=0.3)


def enrich_findings_with_citations(findings: list[dict[str, Any]], top_k: int = 3) -> list[dict[str, Any]]:
    """Attach citations to each finding. Mutates in place and returns same list."""
    from .index import get_index
    if not get_index():
        return findings
    for f in findings:
        citations = retrieve_for_finding(f, top_k=top_k)
        if citations:
            f["citations"] = citations
            best = citations[0]
            if best.get("prevention") and not (f.get("remediation") or "").strip():
                f["remediation"] = best["prevention"]
    return findings
