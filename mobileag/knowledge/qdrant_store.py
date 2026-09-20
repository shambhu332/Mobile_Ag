"""
Qdrant vector store for pattern memory.
"""

import logging
from typing import List, Dict, Any, Optional

try:
    from qdrant_client import AsyncQdrantClient
    from qdrant_client.http import models
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False

from mobileag.reporting.finding import Finding

logger = logging.getLogger(__name__)

class PatternMemory:
    """Manages Qdrant vector store for historical findings and verdicts."""
    
    def __init__(self, host: str = "localhost", port: int = 6333, collection_name: str = "mobileag_findings"):
        self.host = host
        self.port = port
        self.collection_name = collection_name
        self.client = None
        self._connected = False
        
        if QDRANT_AVAILABLE:
            try:
                self.client = AsyncQdrantClient(host=host, port=port)
                self._connected = True
            except Exception as e:
                logger.warning(f"Failed to connect to Qdrant at {host}:{port}: {e}")
        else:
            logger.warning("qdrant-client not installed. Pattern memory will operate in degraded mode.")

    async def initialize(self) -> None:
        """Creates collection with 384-dim vectors (e.g., all-MiniLM-L6-v2)."""
        if not self._connected or not self.client:
            return

        try:
            collections = await self.client.get_collections()
            exists = any(c.name == self.collection_name for c in collections.collections)
            
            if not exists:
                await self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=models.VectorParams(
                        size=384,
                        distance=models.Distance.COSINE
                    )
                )
                logger.info(f"Created Qdrant collection: {self.collection_name}")
        except Exception as e:
            logger.warning(f"Error initializing Qdrant collection: {e}")
            self._connected = False

    async def store_finding(self, finding: Finding, embedding: List[float]) -> None:
        """Upserts a finding with its vector representation."""
        if not self._connected or not self.client:
            return
            
        import uuid
        point_id = str(uuid.uuid4())
        
        payload = {
            "finding_id": finding.id,
            "title": finding.title,
            "cwe": finding.cwe,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "verdict": "UNKNOWN",  # Will be updated by feedback loop
            "is_true_positive": None
        }

        try:
            await self.client.upsert(
                collection_name=self.collection_name,
                points=[
                    models.PointStruct(
                        id=point_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
        except Exception as e:
            logger.error(f"Failed to store finding in Qdrant: {e}")

    async def search_similar(self, embedding: List[float], limit: int = 5, score_threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Similarity search for past findings."""
        if not self._connected or not self.client:
            return []

        try:
            results = await self.client.search(
                collection_name=self.collection_name,
                query_vector=embedding,
                limit=limit,
                score_threshold=score_threshold
            )
            return [{"id": hit.id, "score": hit.score, "payload": hit.payload} for hit in results]
        except Exception as e:
            logger.error(f"Failed to search Qdrant: {e}")
            return []

    async def get_historical_verdicts(self, embedding: List[float]) -> Dict[str, Any]:
        """Returns TP/FP ratio from similar past findings."""
        similar = await self.search_similar(embedding, limit=10, score_threshold=0.8)
        
        tp_count = sum(1 for item in similar if item["payload"].get("is_true_positive") is True)
        fp_count = sum(1 for item in similar if item["payload"].get("is_true_positive") is False)
        
        total = tp_count + fp_count
        tp_rate = (tp_count / total) if total > 0 else 0.5
        
        return {
            "total_relevant": total,
            "true_positives": tp_count,
            "false_positives": fp_count,
            "tp_rate": tp_rate
        }

    async def mark_verdict(self, finding_id: str, is_true_positive: bool) -> None:
        """Update payload with user verdict for a specific finding."""
        if not self._connected or not self.client:
            return

        try:
            scroll_result = await self.client.scroll(
                collection_name=self.collection_name,
                scroll_filter=models.Filter(
                    must=[
                        models.FieldCondition(
                            key="finding_id",
                            match=models.MatchValue(value=finding_id)
                        )
                    ]
                ),
                limit=1
            )
            
            points, _ = scroll_result
            if points:
                point_id = points[0].id
                await self.client.set_payload(
                    collection_name=self.collection_name,
                    payload={"is_true_positive": is_true_positive, "verdict": "TP" if is_true_positive else "FP"},
                    points=[point_id]
                )
        except Exception as e:
            logger.error(f"Failed to mark verdict in Qdrant: {e}")
