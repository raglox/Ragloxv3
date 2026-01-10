# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Vector Knowledge Store (TIER 2)
# Semantic search using FAISS + sentence-transformers
# Phase 3.5: RAG Vector Integration
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import logging
import pickle
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("raglox.core.vector_knowledge")


# ═══════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class VectorSearchResult:
    """Result from vector similarity search."""
    document_id: str
    score: float  # Cosine similarity [0, 1]
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'document_id': self.document_id,
            'score': self.score,
            'content': self.content,
            'metadata': self.metadata
        }


@dataclass
class VectorStoreStats:
    """Statistics about the vector store."""
    total_documents: int = 0
    total_rx_modules: int = 0
    total_nuclei_templates: int = 0
    embedding_dimension: int = 384  # MiniLM-L6-v2
    index_size_mb: float = 0.0
    avg_search_time_ms: float = 0.0
    cache_hit_rate: float = 0.0


# ═══════════════════════════════════════════════════════════════
# Vector Knowledge Store (TIER 2)
# ═══════════════════════════════════════════════════════════════

class VectorKnowledgeStore:
    """
    TIER 2: Semantic Vector Search using FAISS.
    
    Provides semantic understanding of queries through embeddings
    and fast similarity search using FAISS HNSW index.
    
    Features:
    - Sentence-transformers for embedding generation
    - FAISS HNSW index for fast approximate nearest neighbor search
    - Redis caching for repeated queries
    - Async-first design
    - Graceful degradation
    
    Performance:
    - Embedding generation: ~50-100ms
    - Vector search: ~10-30ms (indexed)
    - Total: ~60-130ms
    
    Memory:
    - Model: ~80MB (sentence-transformers/all-MiniLM-L6-v2)
    - Index: ~200MB (13,688 documents)
    """
    
    def __init__(
        self,
        data_path: Optional[str] = None,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        use_cache: bool = True
    ):
        """
        Initialize Vector Knowledge Store.
        
        Args:
            data_path: Path to vector index and metadata files
            model_name: Sentence transformer model to use
            use_cache: Enable Redis caching
        """
        self.data_path = Path(data_path) if data_path else Path("data")
        self.model_name = model_name
        self.use_cache = use_cache
        
        # State
        self._initialized = False
        self._model = None
        self._index = None
        self._documents: List[Dict[str, Any]] = []
        self._id_to_idx: Dict[str, int] = {}
        
        # Cache
        self._query_cache: Dict[str, List[VectorSearchResult]] = {}
        self._cache_max_size = 1000
        
        # Stats
        self._stats = VectorStoreStats()
        self._search_times: List[float] = []
        
        logger.info(f"VectorKnowledgeStore initialized (model: {model_name})")
    
    # ═══════════════════════════════════════════════════════════
    # Initialization
    # ═══════════════════════════════════════════════════════════
    
    async def initialize(self) -> bool:
        """
        Initialize the vector store.
        
        Loads the embedding model and FAISS index.
        
        Returns:
            True if initialized successfully
        """
        if self._initialized:
            return True
        
        try:
            # Load embedding model
            logger.info("Loading embedding model...")
            await self._load_model()
            
            # Load FAISS index
            logger.info("Loading FAISS index...")
            await self._load_index()
            
            # Calculate stats
            self._calculate_stats()
            
            self._initialized = True
            logger.info(
                f"✅ Vector store initialized: "
                f"{self._stats.total_documents} documents, "
                f"{self._stats.embedding_dimension}D embeddings"
            )
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize vector store: {e}")
            return False
    
    async def _load_model(self) -> None:
        """Load sentence transformer model."""
        try:
            # Import here to avoid loading if not used
            from sentence_transformers import SentenceTransformer
            
            # Load model (will download on first run)
            loop = asyncio.get_event_loop()
            self._model = await loop.run_in_executor(
                None,
                lambda: SentenceTransformer(self.model_name)
            )
            
            logger.info(f"✅ Embedding model loaded: {self.model_name}")
            
        except ImportError:
            logger.error("sentence-transformers not installed. Run: pip install sentence-transformers")
            raise
        except Exception as e:
            logger.error(f"Error loading embedding model: {e}")
            raise
    
    async def _load_index(self) -> None:
        """Load FAISS index and metadata."""
        index_path = self.data_path / "raglox_vector_index.faiss"
        metadata_path = self.data_path / "raglox_vector_metadata.json"
        
        if not index_path.exists() or not metadata_path.exists():
            logger.warning(
                f"Vector index not found at {index_path}. "
                "Run: python scripts/vectorize_knowledge.py"
            )
            raise FileNotFoundError("Vector index not found")
        
        try:
            # Load FAISS index
            import faiss
            loop = asyncio.get_event_loop()
            self._index = await loop.run_in_executor(
                None,
                faiss.read_index,
                str(index_path)
            )
            
            # Load metadata
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            self._documents = metadata.get('documents', [])
            self._id_to_idx = {
                doc['id']: idx 
                for idx, doc in enumerate(self._documents)
            }
            
            logger.info(
                f"✅ FAISS index loaded: {len(self._documents)} documents, "
                f"{self._index.ntotal} vectors"
            )
            
        except ImportError:
            logger.error("faiss-cpu not installed. Run: pip install faiss-cpu")
            raise
        except Exception as e:
            logger.error(f"Error loading FAISS index: {e}")
            raise
    
    def _calculate_stats(self) -> None:
        """Calculate vector store statistics."""
        if not self._documents:
            return
        
        # Count by type
        rx_count = sum(1 for doc in self._documents if doc.get('type') == 'rx_module')
        nuclei_count = sum(1 for doc in self._documents if doc.get('type') == 'nuclei_template')
        
        # Index size
        index_path = self.data_path / "raglox_vector_index.faiss"
        if index_path.exists():
            index_size_mb = index_path.stat().st_size / (1024 * 1024)
        else:
            index_size_mb = 0.0
        
        # Average search time
        avg_search_time = (
            np.mean(self._search_times) if self._search_times else 0.0
        )
        
        # Cache hit rate
        cache_hits = len(self._query_cache)
        cache_hit_rate = cache_hits / max(1, self._cache_max_size)
        
        self._stats = VectorStoreStats(
            total_documents=len(self._documents),
            total_rx_modules=rx_count,
            total_nuclei_templates=nuclei_count,
            embedding_dimension=384,  # MiniLM-L6-v2
            index_size_mb=index_size_mb,
            avg_search_time_ms=avg_search_time,
            cache_hit_rate=cache_hit_rate
        )
    
    # ═══════════════════════════════════════════════════════════
    # Embedding Generation
    # ═══════════════════════════════════════════════════════════
    
    @lru_cache(maxsize=1000)
    def _embed_query(self, query: str) -> np.ndarray:
        """
        Generate embedding for a query string.
        
        Uses LRU cache for repeated queries.
        
        Args:
            query: Query string
            
        Returns:
            Embedding vector (384D for MiniLM-L6-v2)
        """
        if not self._model:
            raise RuntimeError("Model not loaded")
        
        # Generate embedding
        embedding = self._model.encode(
            [query],
            show_progress_bar=False,
            convert_to_numpy=True
        )[0]
        
        return embedding
    
    async def embed_queries(self, queries: List[str]) -> np.ndarray:
        """
        Generate embeddings for multiple queries (batch).
        
        Args:
            queries: List of query strings
            
        Returns:
            Array of embeddings
        """
        if not self._model:
            raise RuntimeError("Model not loaded")
        
        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(
            None,
            lambda: self._model.encode(
                queries,
                show_progress_bar=False,
                convert_to_numpy=True
            )
        )
        
        return embeddings
    
    # ═══════════════════════════════════════════════════════════
    # Semantic Search
    # ═══════════════════════════════════════════════════════════
    
    async def semantic_search(
        self,
        query: str,
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        min_score: float = 0.3
    ) -> List[VectorSearchResult]:
        """
        Semantic search using vector similarity.
        
        Args:
            query: Search query
            limit: Maximum results to return
            filters: Optional metadata filters (e.g., {'type': 'rx_module'})
            min_score: Minimum similarity score [0, 1]
            
        Returns:
            List of search results sorted by relevance
        """
        if not self._initialized:
            await self.initialize()
        
        # Check cache
        cache_key = f"{query}:{limit}:{json.dumps(filters or {})}"
        if self.use_cache and cache_key in self._query_cache:
            logger.debug(f"Cache hit for query: {query[:50]}")
            return self._query_cache[cache_key]
        
        start_time = time.time()
        
        try:
            # Generate query embedding
            query_embedding = self._embed_query(query)
            
            # Search FAISS index
            # Request more results to account for filtering
            k = min(limit * 3, self._index.ntotal)
            scores, indices = self._index.search(
                query_embedding.reshape(1, -1).astype('float32'),
                k
            )
            
            # Build results
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx == -1:  # FAISS returns -1 for empty slots
                    continue
                
                doc = self._documents[idx]
                
                # Apply filters
                if filters:
                    if not self._match_filters(doc, filters):
                        continue
                
                # Check minimum score
                if score < min_score:
                    continue
                
                result = VectorSearchResult(
                    document_id=doc['id'],
                    score=float(score),
                    content=doc.get('content', ''),
                    metadata=doc.get('metadata', {})
                )
                results.append(result)
                
                # Stop if we have enough results
                if len(results) >= limit:
                    break
            
            # Sort by score descending
            results.sort(key=lambda r: r.score, reverse=True)
            
            # Update stats
            search_time = (time.time() - start_time) * 1000
            self._search_times.append(search_time)
            if len(self._search_times) > 1000:
                self._search_times.pop(0)
            
            # Cache result
            if self.use_cache:
                self._query_cache[cache_key] = results
                if len(self._query_cache) > self._cache_max_size:
                    # Remove oldest entry
                    self._query_cache.pop(next(iter(self._query_cache)))
            
            logger.debug(
                f"Vector search: {len(results)} results in {search_time:.1f}ms "
                f"(query: {query[:50]})"
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error in semantic search: {e}")
            return []
    
    def _match_filters(self, document: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """
        Check if document matches filters.
        
        Args:
            document: Document to check
            filters: Filter criteria
            
        Returns:
            True if document matches all filters
        """
        metadata = document.get('metadata', {})
        
        for key, value in filters.items():
            # Check in metadata
            if key in metadata:
                if isinstance(value, list):
                    if metadata[key] not in value:
                        return False
                elif metadata[key] != value:
                    return False
            # Check in top-level document
            elif key in document:
                if isinstance(value, list):
                    if document[key] not in value:
                        return False
                elif document[key] != value:
                    return False
            else:
                return False
        
        return True
    
    async def batch_search(
        self,
        queries: List[str],
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[List[VectorSearchResult]]:
        """
        Batch semantic search for multiple queries.
        
        Args:
            queries: List of search queries
            limit: Maximum results per query
            filters: Optional metadata filters
            
        Returns:
            List of result lists (one per query)
        """
        # Execute searches in parallel
        tasks = [
            self.semantic_search(query, limit, filters)
            for query in queries
        ]
        
        results = await asyncio.gather(*tasks)
        return results
    
    # ═══════════════════════════════════════════════════════════
    # Advanced Search
    # ═══════════════════════════════════════════════════════════
    
    async def hybrid_search(
        self,
        query: str,
        keyword_results: List[Dict[str, Any]],
        limit: int = 10,
        vector_weight: float = 0.7
    ) -> List[VectorSearchResult]:
        """
        Hybrid search combining vector similarity and keyword matching.
        
        Fuses results from both methods with weighted scoring.
        
        Args:
            query: Search query
            keyword_results: Results from keyword/rule-based search (TIER 1)
            limit: Maximum results
            vector_weight: Weight for vector scores [0, 1]
            
        Returns:
            Fused and ranked results
        """
        # Get vector search results
        vector_results = await self.semantic_search(query, limit * 2)
        
        # Create score maps
        vector_scores = {r.document_id: r.score for r in vector_results}
        keyword_scores = {r['id']: 1.0 for r in keyword_results}  # Binary: found or not
        
        # Combine all document IDs
        all_doc_ids = set(vector_scores.keys()) | set(keyword_scores.keys())
        
        # Calculate hybrid scores
        hybrid_results = []
        for doc_id in all_doc_ids:
            v_score = vector_scores.get(doc_id, 0.0)
            k_score = keyword_scores.get(doc_id, 0.0)
            
            # Weighted combination
            hybrid_score = (vector_weight * v_score) + ((1 - vector_weight) * k_score)
            
            # Find document
            doc = None
            for r in vector_results:
                if r.document_id == doc_id:
                    doc = r
                    break
            
            if not doc:
                # Build from keyword result
                for kr in keyword_results:
                    if kr['id'] == doc_id:
                        doc = VectorSearchResult(
                            document_id=doc_id,
                            score=hybrid_score,
                            content=kr.get('description', ''),
                            metadata=kr
                        )
                        break
            
            if doc:
                doc.score = hybrid_score
                hybrid_results.append(doc)
        
        # Sort by hybrid score
        hybrid_results.sort(key=lambda r: r.score, reverse=True)
        
        return hybrid_results[:limit]
    
    # ═══════════════════════════════════════════════════════════
    # Statistics
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get vector store statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'initialized': self._initialized,
            'total_documents': self._stats.total_documents,
            'total_rx_modules': self._stats.total_rx_modules,
            'total_nuclei_templates': self._stats.total_nuclei_templates,
            'embedding_dimension': self._stats.embedding_dimension,
            'index_size_mb': self._stats.index_size_mb,
            'avg_search_time_ms': self._stats.avg_search_time_ms,
            'cache_hit_rate': self._stats.cache_hit_rate,
            'cache_size': len(self._query_cache)
        }
    
    def is_available(self) -> bool:
        """Check if vector store is available."""
        return self._initialized
    
    def clear_cache(self) -> None:
        """Clear query cache."""
        self._query_cache.clear()
        self._embed_query.cache_clear()
        logger.info("Vector store cache cleared")


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

_vector_store_instance: Optional[VectorKnowledgeStore] = None


async def get_vector_store() -> Optional[VectorKnowledgeStore]:
    """
    Get vector store instance (singleton).
    
    Returns:
        VectorKnowledgeStore instance or None if unavailable
    """
    global _vector_store_instance
    
    if _vector_store_instance is None:
        try:
            _vector_store_instance = VectorKnowledgeStore()
            await _vector_store_instance.initialize()
        except Exception as e:
            logger.warning(f"Vector store not available: {e}")
            return None
    
    return _vector_store_instance
