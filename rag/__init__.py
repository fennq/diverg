# RAG — retrieval-augmented generation for security/blockchain reports.
# Index: content/ (exploit catalog, prevention docs). Retrieve: per-finding citations.

from .index import build_index, get_index
from .retrieve import retrieve_for_finding, enrich_findings_with_citations

__all__ = ["build_index", "get_index", "retrieve_for_finding", "enrich_findings_with_citations"]
