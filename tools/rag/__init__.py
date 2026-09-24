# RAG retrieval tools for the AI SOC engineer.
from tools.rag.retrieve import RetrieveWazuhDocs

TOOLS = [RetrieveWazuhDocs]

__all__ = ["TOOLS", "RetrieveWazuhDocs"]