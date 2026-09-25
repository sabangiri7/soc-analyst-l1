# RAG tools for the AI SOC engineer: retrieval + local rule snapshots.
from tools.rag.retrieve import RetrieveWazuhDocs
from tools.rag.ingest import IngestWazuhRules

TOOLS = [RetrieveWazuhDocs, IngestWazuhRules]

__all__ = ["TOOLS", "RetrieveWazuhDocs", "IngestWazuhRules"]