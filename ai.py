"""
Offline AI assistant, backed by a local Ollama instance.

Works with no internet access as long as Ollama is running locally and
the configured models have already been pulled (which itself requires a
one-time internet connection). A small local knowledge base of markdown
notes under `knowledge/` is embedded and searched (retrieval-augmented
generation) so the assistant has some grounded reference material to
draw on beyond the base model's own training, and can point to which
note it used.

Configurable via environment variables:
  OLLAMA_HOST     - default "http://127.0.0.1:11434"
  AI_CHAT_MODEL   - default "llama3.2:1b" (small enough for a Pi 4)
  AI_EMBED_MODEL  - default "all-minilm"
"""
import math
import os
import re
from pathlib import Path

import requests

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
CHAT_MODEL = os.environ.get("AI_CHAT_MODEL", "llama3.2:1b")
EMBED_MODEL = os.environ.get("AI_EMBED_MODEL", "all-minilm")
KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

CHAT_TIMEOUT = 120
EMBED_TIMEOUT = 30
STATUS_TIMEOUT = 3

SYSTEM_PROMPT = (
    "You are an offline security-research assistant embedded in Neo, a "
    "local OSINT dashboard. Answer concisely and factually. Use the "
    "reference notes provided below when they're relevant, and say "
    "plainly when something is outside your knowledge instead of "
    "guessing. Assume all use is for authorized security research, "
    "pentesting, or CTF work."
)

_index = None  # lazily built list of {"text", "source", "vector"}


def _chunk_markdown(text, max_chars=900):
    sections = re.split(r"\n(?=## )", text.strip())
    chunks = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        body = "\n".join(
            line for line in section.splitlines() if not line.lstrip().startswith("#")
        ).strip()
        if not body:
            continue  # heading-only section (e.g. a lone H1 title), no retrievable content
        if len(section) <= max_chars:
            chunks.append(section)
            continue
        buf = ""
        for para in section.split("\n\n"):
            if buf and len(buf) + len(para) + 2 > max_chars:
                chunks.append(buf.strip())
                buf = para
            else:
                buf = f"{buf}\n\n{para}" if buf else para
        if buf.strip():
            chunks.append(buf.strip())
    return chunks


def _load_chunks():
    chunks = []
    if not KNOWLEDGE_DIR.exists():
        return chunks
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        for chunk in _chunk_markdown(path.read_text(encoding="utf-8")):
            chunks.append((chunk, path.name))
    return chunks


def _embed(text):
    r = requests.post(
        f"{OLLAMA_HOST}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=EMBED_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["embedding"]


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _ensure_index():
    global _index
    if _index is not None:
        return _index
    chunks = _load_chunks()
    if not chunks:
        _index = []  # no knowledge files at all; nothing will change that at runtime
        return _index
    index = []
    for text, source in chunks:
        try:
            vector = _embed(text)
        except requests.RequestException:
            continue
        index.append({"text": text, "source": source, "vector": vector})
    if index:
        _index = index  # cache only once embedding actually succeeded for something
    return index


def retrieve(query, k=4, min_score=0.2):
    index = _ensure_index()
    if not index:
        return []
    try:
        qvec = _embed(query)
    except requests.RequestException:
        return []
    scored = sorted(
        ((_cosine(qvec, item["vector"]), item) for item in index),
        key=lambda pair: pair[0],
        reverse=True,
    )
    return [item for score, item in scored[:k] if score >= min_score]


def ollama_available():
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=STATUS_TIMEOUT)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _unavailable_error():
    return (
        f"Local AI service (Ollama) isn't reachable at {OLLAMA_HOST}. "
        f"Install Ollama, run `ollama pull {CHAT_MODEL}` and "
        f"`ollama pull {EMBED_MODEL}` once while online, then start "
        "Ollama and try again — after that it works fully offline."
    )


def chat(message, extra_context=None):
    if not ollama_available():
        return {"ok": False, "error": _unavailable_error(), "reply": None, "sources": []}

    sources = retrieve(message)
    user_content = message
    if extra_context:
        user_content = f"Context from a live lookup:\n{extra_context}\n\nQuestion: {message}"
    if sources:
        notes = "\n\n".join(f"[{s['source']}]\n{s['text']}" for s in sources)
        user_content = f"Reference notes:\n{notes}\n\n{user_content}"

    try:
        r = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": CHAT_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                "stream": False,
            },
            timeout=CHAT_TIMEOUT,
        )
        r.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, "error": f"Ollama request failed: {exc}", "reply": None, "sources": []}

    data = r.json()
    reply = (data.get("message") or {}).get("content", "").strip()
    if not reply:
        return {"ok": False, "error": "Ollama returned an empty response.", "reply": None, "sources": []}
    return {
        "ok": True,
        "error": None,
        "reply": reply,
        "sources": sorted({s["source"] for s in sources}),
    }
