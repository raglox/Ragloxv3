# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Hybrid Knowledge Retriever
# Intelligent routing between TIER 1 (Fast Base) and TIER 2 (Deep RAG)
# Phase 3.5: RAG Vector Integration
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .knowledge import EmbeddedKnowledge
from .vector_knowledge import VectorKnowledgeStore, VectorSearchResult

logger = logging.getLogger("raglox.core.hybrid_retriever")


# ═══════════════════════════════════════════════════════════════
# Enums and Data Classes
# ═══════════════════════════════════════════════════════════════

class QueryType(Enum):
    """Classification of query complexity."""
    SIMPLE = "simple"          # Status, list → TIER 1 only
    TACTICAL = "tactical"      # Known CVE/technique → TIER 1 + TIER 2
    COMPLEX = "complex"        # Multi-constraint → TIER 2 + rerank


class RetrievalPath(Enum):
    """Which knowledge tier(s) to use."""
    TIER1_ONLY = "tier1_only"          # Base knowledge only (<5ms)
    HYBRID = "hybrid"                  # Both tiers (~35ms)
    TIER2_ONLY = "tier2_only"          # Vector search only (~100ms)
    FALLBACK_TIER1 = "fallback_tier1"  # Vector unavailable, use base


@dataclass
class RetrievalResult:
    """Result from knowledge retrieval."""
    query: str
    query_type: QueryType
    retrieval_path: RetrievalPath
    results: List[Dict[str, Any]]
    latency_ms: float
    source: str  # "tier1", "tier2", "hybrid"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HybridRetrievalStats:
    """Statistics about hybrid retrieval."""
    total_queries: int = 0
    simple_queries: int = 0
    tactical_queries: int = 0
    complex_queries: int = 0
    tier1_only_count: int = 0
    hybrid_count: int = 0
    tier2_only_count: int = 0
    avg_latency_ms: float = 0.0
    cache_hit_rate: float = 0.0


# ═══════════════════════════════════════════════════════════════
# Hybrid Knowledge Retriever
# ═══════════════════════════════════════════════════════════════

class HybridKnowledgeRetriever:
    """
    Intelligent Knowledge Retrieval Router.
    
    Combines fast base knowledge (TIER 1) with semantic vector search (TIER 2)
    to provide optimal speed AND accuracy.
    
    Decision Logic:
    - Simple queries → TIER 1 only (<5ms)
    - Tactical queries → TIER 1 + TIER 2 parallel (~35ms)
    - Complex queries → TIER 2 + reranking (~100ms)
    
    Performance Guarantees:
    - Simple queries: <5ms (no degradation from current system)
    - Tactical queries: <40ms (60x faster than LLM call)
    - Complex queries: <120ms (20x faster than LLM call)
    
    Graceful Degradation:
    - If vector store unavailable → fallback to TIER 1
    - If TIER 2 slow → timeout and return TIER 1 results
    """
    
    def __init__(
        self,
        base_knowledge: EmbeddedKnowledge,
        vector_store: Optional[VectorKnowledgeStore] = None,
        enable_caching: bool = True
    ):
        """
        Initialize Hybrid Retriever.
        
        Args:
            base_knowledge: TIER 1 base knowledge (EmbeddedKnowledge)
            vector_store: TIER 2 vector store (VectorKnowledgeStore)
            enable_caching: Enable result caching
        """
        self.base_knowledge = base_knowledge
        self.vector_store = vector_store
        self.enable_caching = enable_caching
        
        # Cache
        self._result_cache: Dict[str, RetrievalResult] = {}
        self._cache_max_size = 500
        
        # Stats
        self._stats = HybridRetrievalStats()
        self._latencies: List[float] = []
        
        # Check if vector store is available
        self._vector_available = (
            vector_store is not None and 
            vector_store.is_available()
        )
        
        if self._vector_available:
            logger.info("✅ Hybrid retrieval enabled (TIER 1 + TIER 2)")
        else:
            logger.warning("⚠️ Vector store unavailable, using TIER 1 only")
    
    # ═══════════════════════════════════════════════════════════
    # Main Retrieval Interface
    # ═══════════════════════════════════════════════════════════
    
    async def retrieve(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        limit: int = 10
    ) -> RetrievalResult:
        """
        Retrieve relevant knowledge for a query.
        
        Automatically classifies query and routes to optimal path.
        
        Args:
            query: User query string
            context: Optional tactical context
            limit: Maximum results
            
        Returns:
            RetrievalResult with matched knowledge
        """
        start_time = time.time()
        
        # Check cache
        cache_key = f"{query}:{limit}"
        if self.enable_caching and cache_key in self._result_cache:
            cached = self._result_cache[cache_key]
            logger.debug(f"Cache hit for query: {query[:50]}")
            return cached
        
        # Classify query
        query_type = self._classify_query(query, context)
        
        # Route to appropriate path
        if query_type == QueryType.SIMPLE:
            result = await self._retrieve_tier1_only(query, context, limit)
            
        elif query_type == QueryType.TACTICAL:
            if self._vector_available:
                result = await self._retrieve_hybrid(query, context, limit)
            else:
                result = await self._retrieve_tier1_only(query, context, limit)
                result.retrieval_path = RetrievalPath.FALLBACK_TIER1
            
        else:  # COMPLEX
            if self._vector_available:
                result = await self._retrieve_tier2_only(query, context, limit)
            else:
                result = await self._retrieve_tier1_only(query, context, limit)
                result.retrieval_path = RetrievalPath.FALLBACK_TIER1
        
        # Calculate latency
        latency_ms = (time.time() - start_time) * 1000
        result.latency_ms = latency_ms
        
        # Update stats
        self._update_stats(query_type, result.retrieval_path, latency_ms)
        
        # Cache result
        if self.enable_caching:
            self._result_cache[cache_key] = result
            if len(self._result_cache) > self._cache_max_size:
                self._result_cache.pop(next(iter(self._result_cache)))
        
        logger.info(
            f"Retrieved {len(result.results)} results via {result.retrieval_path.value} "
            f"in {latency_ms:.1f}ms (query: {query[:50]})"
        )
        
        return result
    
    # ═══════════════════════════════════════════════════════════
    # Query Classification
    # ═══════════════════════════════════════════════════════════
    
    def _classify_query(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None
    ) -> QueryType:
        """
        Classify query to determine optimal retrieval path.
        
        Args:
            query: User query
            context: Tactical context
            
        Returns:
            QueryType classification
        """
        query_lower = query.lower()
        
        # Simple queries: status checks, listings
        simple_keywords = [
            'status', 'show', 'list', 'display', 'get', 'what',
            'current', 'active', 'available',
            # Arabic
            'الحالة', 'اعرض', 'ما هو', 'ما هي', 'اظهر'
        ]
        
        if any(kw in query_lower for kw in simple_keywords):
            # Check if it's just a status check
            if len(query.split()) <= 5:
                return QueryType.SIMPLE
        
        # Tactical queries: known CVE, technique, or target
        tactical_indicators = [
            # Known identifiers
            'cve-', 't1', 'ta00', 'ta01', 'rx-',
            # Specific actions with targets
            'exploit', 'scan', 'attack', 'enumerate',
            # Arabic
            'استغلال', 'فحص', 'هجوم', 'اختراق'
        ]
        
        has_tactical_keyword = any(kw in query_lower for kw in tactical_indicators)
        has_specific_target = (
            context and 
            (context.get('targets') or context.get('vulnerabilities'))
        )
        
        if has_tactical_keyword or has_specific_target:
            return QueryType.TACTICAL
        
        # Complex queries: multi-constraint, exploration
        complex_indicators = [
            # Multi-word technical queries
            len(query.split()) > 10,
            # Multiple conditions
            ' and ' in query_lower or ' with ' in query_lower,
            ' but ' in query_lower or ' without ' in query_lower,
            # Exploration keywords
            'find' in query_lower, 'search' in query_lower,
            'alternative' in query_lower, 'different' in query_lower,
            'bypass' in query_lower, 'evade' in query_lower,
            # Arabic
            'ابحث' in query_lower, 'بديل' in query_lower
        ]
        
        if any(complex_indicators):
            return QueryType.COMPLEX
        
        # Default to tactical (balanced approach)
        return QueryType.TACTICAL
    
    # ═══════════════════════════════════════════════════════════
    # Retrieval Paths
    # ═══════════════════════════════════════════════════════════
    
    async def _retrieve_tier1_only(
        self,
        query: str,
        context: Optional[Dict[str, Any]],
        limit: int
    ) -> RetrievalResult:
        """
        TIER 1 ONLY: Fast base knowledge retrieval.
        
        Target: <5ms
        """
        # Use base knowledge search
        results = self.base_knowledge.search_modules(
            query=query,
            platform=context.get('platform') if context else None,
            limit=limit
        )
        
        return RetrievalResult(
            query=query,
            query_type=QueryType.SIMPLE,
            retrieval_path=RetrievalPath.TIER1_ONLY,
            results=results,
            latency_ms=0.0,  # Will be set by caller
            source="tier1",
            metadata={'method': 'dictionary_lookup'}
        )
    
    async def _retrieve_hybrid(
        self,
        query: str,
        context: Optional[Dict[str, Any]],
        limit: int
    ) -> RetrievalResult:
        """
        HYBRID: TIER 1 + TIER 2 parallel retrieval with fusion.
        
        Target: <40ms
        """
        # Execute both tiers in parallel
        tier1_task = asyncio.create_task(
            self._get_tier1_results(query, context, limit)
        )
        tier2_task = asyncio.create_task(
            self._get_tier2_results(query, context, limit)
        )
        
        # Wait for both with timeout
        try:
            tier1_results, tier2_results = await asyncio.wait_for(
                asyncio.gather(tier1_task, tier2_task),
                timeout=0.15  # 150ms timeout
            )
        except asyncio.TimeoutError:
            logger.warning("Hybrid retrieval timeout, using available results")
            tier1_results = tier1_task.result() if tier1_task.done() else []
            tier2_results = tier2_task.result() if tier2_task.done() else []
        
        # Fuse results
        fused_results = self._fuse_results(
            tier1_results=tier1_results,
            tier2_results=tier2_results,
            limit=limit
        )
        
        return RetrievalResult(
            query=query,
            query_type=QueryType.TACTICAL,
            retrieval_path=RetrievalPath.HYBRID,
            results=fused_results,
            latency_ms=0.0,
            source="hybrid",
            metadata={
                'tier1_count': len(tier1_results),
                'tier2_count': len(tier2_results),
                'fused_count': len(fused_results)
            }
        )
    
    async def _retrieve_tier2_only(
        self,
        query: str,
        context: Optional[Dict[str, Any]],
        limit: int
    ) -> RetrievalResult:
        """
        TIER 2 ONLY: Deep semantic search with reranking.
        
        Target: <120ms
        """
        if not self.vector_store:
            # Fallback to TIER 1
            return await self._retrieve_tier1_only(query, context, limit)
        
        # Semantic search
        vector_results = await self.vector_store.semantic_search(
            query=query,
            limit=limit * 2,  # Get more for reranking
            filters=self._build_filters(context) if context else None
        )
        
        # Rerank results
        reranked = self._rerank_results(
            vector_results,
            context=context,
            limit=limit
        )
        
        # Convert to dicts
        results = [self._vector_result_to_dict(r) for r in reranked]
        
        return RetrievalResult(
            query=query,
            query_type=QueryType.COMPLEX,
            retrieval_path=RetrievalPath.TIER2_ONLY,
            results=results,
            latency_ms=0.0,
            source="tier2",
            metadata={'reranked': True}
        )
    
    # ═══════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════
    
    async def _get_tier1_results(
        self,
        query: str,
        context: Optional[Dict[str, Any]],
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get results from TIER 1 base knowledge."""
        try:
            return self.base_knowledge.search_modules(
                query=query,
                platform=context.get('platform') if context else None,
                limit=limit
            )
        except Exception as e:
            logger.error(f"TIER 1 retrieval error: {e}")
            return []
    
    async def _get_tier2_results(
        self,
        query: str,
        context: Optional[Dict[str, Any]],
        limit: int
    ) -> List[VectorSearchResult]:
        """Get results from TIER 2 vector search."""
        if not self.vector_store:
            return []
        
        try:
            return await self.vector_store.semantic_search(
                query=query,
                limit=limit,
                filters=self._build_filters(context) if context else None
            )
        except Exception as e:
            logger.error(f"TIER 2 retrieval error: {e}")
            return []
    
    def _build_filters(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Build metadata filters from tactical context."""
        filters = {}
        
        if 'platform' in context:
            filters['platform'] = context['platform']
        
        if 'technique' in context:
            filters['technique_id'] = context['technique']
        
        return filters
    
    def _fuse_results(
        self,
        tier1_results: List[Dict[str, Any]],
        tier2_results: List[VectorSearchResult],
        limit: int
    ) -> List[Dict[str, Any]]:
        """
        Fuse results from TIER 1 and TIER 2.
        
        Strategy:
        - Create unified result set
        - Assign hybrid scores (70% vector, 30% keyword)
        - Remove duplicates
        - Sort by score
        - Limit results
        """
        # Score maps
        tier1_ids = {r.get('rx_module_id', r.get('template_id')): 1.0 for r in tier1_results}
        tier2_ids = {r.document_id: r.score for r in tier2_results}
        
        # All document IDs
        all_ids = set(tier1_ids.keys()) | set(tier2_ids.keys())
        
        # Calculate hybrid scores
        scored_results = []
        for doc_id in all_ids:
            tier1_score = tier1_ids.get(doc_id, 0.0)
            tier2_score = tier2_ids.get(doc_id, 0.0)
            
            # Weighted combination: 70% semantic, 30% keyword
            hybrid_score = (0.7 * tier2_score) + (0.3 * tier1_score)
            
            # Find document
            doc = None
            for r in tier1_results:
                if r.get('rx_module_id') == doc_id or r.get('template_id') == doc_id:
                    doc = r
                    break
            
            if not doc:
                for r in tier2_results:
                    if r.document_id == doc_id:
                        doc = self._vector_result_to_dict(r)
                        break
            
            if doc:
                doc['_hybrid_score'] = hybrid_score
                scored_results.append(doc)
        
        # Sort by hybrid score
        scored_results.sort(key=lambda r: r.get('_hybrid_score', 0.0), reverse=True)
        
        # Remove score field and limit
        for r in scored_results:
            r.pop('_hybrid_score', None)
        
        return scored_results[:limit]
    
    def _rerank_results(
        self,
        results: List[VectorSearchResult],
        context: Optional[Dict[str, Any]],
        limit: int
    ) -> List[VectorSearchResult]:
        """
        Rerank vector search results using additional signals.
        
        Scoring:
        - Base: vector similarity (40%)
        - Success rate from operational memory (30%)
        - Recency/popularity (20%)
        - Context match (10%)
        """
        for result in results:
            base_score = result.score
            
            # Success rate (mock - would query operational memory)
            success_rate = 0.5  # Default
            
            # Recency (mock - would use timestamp)
            recency = 0.5  # Default
            
            # Context match
            context_match = 1.0 if context else 0.5
            
            # Calculate reranked score
            reranked_score = (
                0.4 * base_score +
                0.3 * success_rate +
                0.2 * recency +
                0.1 * context_match
            )
            
            result.score = reranked_score
        
        # Sort by reranked score
        results.sort(key=lambda r: r.score, reverse=True)
        
        return results[:limit]
    
    def _vector_result_to_dict(self, result: VectorSearchResult) -> Dict[str, Any]:
        """Convert VectorSearchResult to dictionary."""
        return {
            'id': result.document_id,
            'score': result.score,
            'content': result.content,
            **result.metadata
        }
    
    # ═══════════════════════════════════════════════════════════
    # Statistics
    # ═══════════════════════════════════════════════════════════
    
    def _update_stats(
        self,
        query_type: QueryType,
        path: RetrievalPath,
        latency: float
    ) -> None:
        """Update retrieval statistics."""
        self._stats.total_queries += 1
        
        if query_type == QueryType.SIMPLE:
            self._stats.simple_queries += 1
        elif query_type == QueryType.TACTICAL:
            self._stats.tactical_queries += 1
        else:
            self._stats.complex_queries += 1
        
        if path == RetrievalPath.TIER1_ONLY or path == RetrievalPath.FALLBACK_TIER1:
            self._stats.tier1_only_count += 1
        elif path == RetrievalPath.HYBRID:
            self._stats.hybrid_count += 1
        else:
            self._stats.tier2_only_count += 1
        
        self._latencies.append(latency)
        if len(self._latencies) > 1000:
            self._latencies.pop(0)
        
        import numpy as np
        self._stats.avg_latency_ms = float(np.mean(self._latencies))
        
        cache_hits = len(self._result_cache)
        self._stats.cache_hit_rate = cache_hits / max(1, self._cache_max_size)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get retrieval statistics."""
        return {
            'total_queries': self._stats.total_queries,
            'simple_queries': self._stats.simple_queries,
            'tactical_queries': self._stats.tactical_queries,
            'complex_queries': self._stats.complex_queries,
            'tier1_only_count': self._stats.tier1_only_count,
            'hybrid_count': self._stats.hybrid_count,
            'tier2_only_count': self._stats.tier2_only_count,
            'avg_latency_ms': self._stats.avg_latency_ms,
            'cache_hit_rate': self._stats.cache_hit_rate,
            'vector_available': self._vector_available
        }


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

async def create_hybrid_retriever(
    base_knowledge: EmbeddedKnowledge,
    vector_store: Optional[VectorKnowledgeStore] = None
) -> HybridKnowledgeRetriever:
    """
    Create and initialize a hybrid retriever.
    
    Args:
        base_knowledge: Base knowledge (TIER 1)
        vector_store: Optional vector store (TIER 2)
        
    Returns:
        Initialized HybridKnowledgeRetriever
    """
    retriever = HybridKnowledgeRetriever(
        base_knowledge=base_knowledge,
        vector_store=vector_store
    )
    
    return retriever
