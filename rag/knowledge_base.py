"""
Local RAG store (ChromaDB, on-disk - nothing leaves the box).

Three logical collections, kept separate so retrieval can be targeted:
  - playbooks   : your org's SOPs for handling alert types
  - cases       : closed historical alerts with analyst verdict + reasoning
  - lessons     : short, self-written notes distilled from analyst feedback
                  (this is the "self-improvement" memory - see agent/memory.py)

On first run this downloads a small local sentence-embedding model (one-time,
needs internet). Everything after that runs fully offline.
"""
from __future__ import annotations
import uuid
from typing import Any
import chromadb

from config import cfg

COLLECTIONS = ("playbooks", "cases", "lessons")


class KnowledgeBase:
    def __init__(self, path: str | None = None):
        self.client = chromadb.PersistentClient(path=path or cfg.CHROMA_DB_PATH)
        self._collections = {
            name: self.client.get_or_create_collection(name) for name in COLLECTIONS
        }

    # ------------------------------------------------------------------ #
    def add(self, collection: str, text: str, metadata: dict[str, Any], doc_id: str | None = None) -> str:
        assert collection in COLLECTIONS, f"unknown collection {collection}"
        doc_id = doc_id or str(uuid.uuid4())
        self._collections[collection].upsert(
            ids=[doc_id], documents=[text], metadatas=[metadata]
        )
        return doc_id

    def query(self, collection: str, text: str, n_results: int = 4,
              where: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        assert collection in COLLECTIONS, f"unknown collection {collection}"
        coll = self._collections[collection]
        if coll.count() == 0:
            return []
        n_results = min(n_results, coll.count())
        res = coll.query(query_texts=[text], n_results=n_results, where=where)
        out = []
        for doc, meta, dist, _id in zip(
            res["documents"][0], res["metadatas"][0], res["distances"][0], res["ids"][0]
        ):
            out.append({"id": _id, "text": doc, "metadata": meta, "distance": dist})
        return out

    def counts(self) -> dict[str, int]:
        return {name: c.count() for name, c in self._collections.items()}
