# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - REAL Vector Knowledge Store Tests
# NO MOCKS - Tests with actual FAISS index and embeddings
# Phase 2 RAG Testing: VectorKnowledgeStore (TIER 2)
# ═══════════════════════════════════════════════════════════════

import asyncio
import time
from pathlib import Path

import pytest

# Check dependencies
try:
    import faiss
    import numpy as np
    from sentence_transformers import SentenceTransformer
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False

# Skip all tests if dependencies not available
pytestmark = pytest.mark.skipif(
    not DEPENDENCIES_AVAILABLE,
    reason="faiss-cpu or sentence-transformers not installed"
)

from src.core.vector_knowledge import VectorKnowledgeStore, VectorSearchResult


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
async def real_vector_store():
    """
    Real vector store with actual FAISS index.
    NO MOCKS - uses production vector index.
    """
    data_path = Path(__file__).parent.parent.parent / "data"
    
    # Check if vector index exists
    index_path = data_path / "raglox_vector_index.faiss"
    metadata_path = data_path / "raglox_vector_metadata.json"
    
    if not index_path.exists() or not metadata_path.exists():
        pytest.skip(
            "Vector index not found. Run: python scripts/build_vector_index.py"
        )
    
    print(f"\n📂 Loading vector store from: {data_path}")
    
    # Initialize vector store
    store = VectorKnowledgeStore(data_path=str(data_path))
    initialized = await store.initialize()
    
    if not initialized:
        pytest.skip("Failed to initialize vector store")
    
    stats = store.get_stats()
    print(f"✅ Vector store initialized:")
    print(f"   Documents: {stats['total_documents']}")
    print(f"   Dimension: {stats['embedding_dimension']}D")
    print(f"   Index size: {stats['index_size_mb']:.2f} MB")
    
    return store


# ═══════════════════════════════════════════════════════════════
# Test: Initialization
# ═══════════════════════════════════════════════════════════════

class TestRealVectorStoreInitialization:
    """Test real vector store initialization."""
    
    @pytest.mark.asyncio
    async def test_vector_store_initializes(self, real_vector_store):
        """Vector store should initialize with real index."""
        assert real_vector_store.is_available() is True
        assert real_vector_store._initialized is True
        assert real_vector_store._model is not None
        assert real_vector_store._index is not None
        
        print("✅ Vector store fully initialized")
    
    @pytest.mark.asyncio
    async def test_documents_are_loaded(self, real_vector_store):
        """Documents should be loaded from metadata."""
        assert len(real_vector_store._documents) > 0
        
        # Check document structure
        doc = real_vector_store._documents[0]
        assert 'id' in doc
        assert 'content' in doc
        assert 'metadata' in doc or 'type' in doc
        
        print(f"✅ Loaded {len(real_vector_store._documents)} documents")
    
    @pytest.mark.asyncio
    async def test_statistics_are_available(self, real_vector_store):
        """Statistics should be calculated."""
        stats = real_vector_store.get_stats()
        
        assert stats['initialized'] is True
        assert stats['total_documents'] > 0
        assert stats['embedding_dimension'] == 384  # MiniLM-L6-v2
        
        print(f"\n📊 Vector Store Statistics:")
        print(f"   Documents: {stats['total_documents']}")
        print(f"   RX Modules: {stats['total_rx_modules']}")
        print(f"   Nuclei Templates: {stats['total_nuclei_templates']}")
        print(f"   Index size: {stats['index_size_mb']:.2f} MB")


# ═══════════════════════════════════════════════════════════════
# Test: Embedding Generation
# ═══════════════════════════════════════════════════════════════

class TestRealEmbeddingGeneration:
    """Test real embedding generation with sentence-transformers."""
    
    @pytest.mark.asyncio
    async def test_embed_single_query(self, real_vector_store):
        """Should generate embedding for a single query."""
        query = "credential dumping windows"
        
        embedding = real_vector_store._embed_query(query)
        
        assert embedding is not None
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (384,)  # MiniLM-L6-v2 dimension
        
        print(f"\n🔢 Embedding generated:")
        print(f"   Query: '{query}'")
        print(f"   Shape: {embedding.shape}")
        print(f"   Sample values: {embedding[:5]}")
    
    @pytest.mark.asyncio
    async def test_embed_batch_queries(self, real_vector_store):
        """Should generate embeddings for multiple queries."""
        queries = [
            "credential dumping",
            "privilege escalation",
            "network reconnaissance"
        ]
        
        embeddings = await real_vector_store.embed_queries(queries)
        
        assert embeddings is not None
        assert isinstance(embeddings, np.ndarray)
        assert embeddings.shape == (3, 384)
        
        print(f"\n🔢 Batch embeddings generated:")
        print(f"   Queries: {len(queries)}")
        print(f"   Shape: {embeddings.shape}")
    
    @pytest.mark.asyncio
    async def test_embedding_caching(self, real_vector_store):
        """Repeated queries should use cached embeddings."""
        query = "test caching"
        
        # First call
        start = time.time()
        emb1 = real_vector_store._embed_query(query)
        time1 = time.time() - start
        
        # Second call (should be cached)
        start = time.time()
        emb2 = real_vector_store._embed_query(query)
        time2 = time.time() - start
        
        # Should be same embedding
        assert np.array_equal(emb1, emb2)
        
        # Second call should be faster (cached)
        assert time2 < time1
        
        print(f"\n⚡ Caching Performance:")
        print(f"   First call: {time1*1000:.2f}ms")
        print(f"   Cached call: {time2*1000:.2f}ms")
        print(f"   Speedup: {time1/time2:.1f}x")


# ═══════════════════════════════════════════════════════════════
# Test: Semantic Search
# ═══════════════════════════════════════════════════════════════

class TestRealSemanticSearch:
    """Test real semantic search with FAISS."""
    
    @pytest.mark.asyncio
    async def test_semantic_search_basic(self, real_vector_store):
        """Should perform semantic search and return results."""
        query = "credential dumping windows"
        
        results = await real_vector_store.semantic_search(query, limit=5)
        
        assert isinstance(results, list)
        assert len(results) > 0
        assert len(results) <= 5
        
        # Check result structure
        result = results[0]
        assert isinstance(result, VectorSearchResult)
        assert result.document_id
        assert result.score > 0
        assert result.content
        
        print(f"\n🔍 Semantic Search Results:")
        print(f"   Query: '{query}'")
        print(f"   Found: {len(results)} results")
        for i, r in enumerate(results[:3], 1):
            print(f"   {i}. {r.document_id[:40]:<40} (score: {r.score:.3f})")
    
    @pytest.mark.asyncio
    async def test_semantic_search_with_filters(self, real_vector_store):
        """Should filter results by metadata."""
        query = "credential"
        
        # Search with filter for RX modules only
        results = await real_vector_store.semantic_search(
            query,
            limit=10,
            filters={'type': 'rx_module'}
        )
        
        assert isinstance(results, list)
        
        # Verify all results are RX modules
        for result in results:
            doc_type = result.metadata.get('type', '')
            assert doc_type == 'rx_module' or 'rx-' in result.document_id.lower()
        
        print(f"\n🔍 Filtered Search (RX modules):")
        print(f"   Results: {len(results)}")
    
    @pytest.mark.asyncio
    async def test_semantic_search_min_score(self, real_vector_store):
        """Should filter results by minimum score."""
        query = "test"
        
        # Search with high minimum score
        results = await real_vector_store.semantic_search(
            query,
            limit=10,
            min_score=0.7
        )
        
        # All results should have score >= 0.7
        for result in results:
            assert result.score >= 0.7
        
        print(f"\n🔍 High-confidence results (score >= 0.7):")
        print(f"   Found: {len(results)}")
    
    @pytest.mark.asyncio
    async def test_semantic_search_relevance(self, real_vector_store):
        """Search results should be relevant to query."""
        query = "credential dumping lsass memory"
        
        results = await real_vector_store.semantic_search(query, limit=10)
        
        # Check that top results are about credentials
        if len(results) > 0:
            top_result = results[0]
            content_lower = top_result.content.lower()
            
            # Should contain relevant keywords
            relevant = any(
                keyword in content_lower
                for keyword in ['credential', 'lsass', 'memory', 'dump', 'password']
            )
            
            assert relevant, f"Top result not relevant: {top_result.content[:100]}"
            
            print(f"\n✅ Top result is relevant:")
            print(f"   ID: {top_result.document_id}")
            print(f"   Score: {top_result.score:.3f}")
            print(f"   Content: {top_result.content[:100]}...")


# ═══════════════════════════════════════════════════════════════
# Test: Batch & Advanced Search
# ═══════════════════════════════════════════════════════════════

class TestRealAdvancedSearch:
    """Test advanced search features."""
    
    @pytest.mark.asyncio
    async def test_batch_search(self, real_vector_store):
        """Should search multiple queries in parallel."""
        queries = [
            "credential dumping",
            "privilege escalation",
            "network reconnaissance"
        ]
        
        start = time.time()
        results = await real_vector_store.batch_search(queries, limit=5)
        duration = time.time() - start
        
        assert len(results) == len(queries)
        
        # Each query should have results
        for i, query_results in enumerate(results):
            assert isinstance(query_results, list)
            print(f"\n   Query {i+1}: {len(query_results)} results")
        
        print(f"\n⚡ Batch search completed in {duration*1000:.1f}ms")
    
    @pytest.mark.asyncio
    async def test_search_caching(self, real_vector_store):
        """Repeated searches should use cache."""
        query = "test caching search"
        
        # First search
        start = time.time()
        results1 = await real_vector_store.semantic_search(query, limit=5)
        time1 = time.time() - start
        
        # Second search (should be cached)
        start = time.time()
        results2 = await real_vector_store.semantic_search(query, limit=5)
        time2 = time.time() - start
        
        # Should return same results
        assert len(results1) == len(results2)
        if len(results1) > 0:
            assert results1[0].document_id == results2[0].document_id
        
        # Second search should be faster
        print(f"\n⚡ Search Caching:")
        print(f"   First search: {time1*1000:.1f}ms")
        print(f"   Cached search: {time2*1000:.1f}ms")
        print(f"   Speedup: {time1/time2:.1f}x")


# ═══════════════════════════════════════════════════════════════
# Test: Performance
# ═══════════════════════════════════════════════════════════════

class TestRealVectorStorePerformance:
    """Test vector store performance."""
    
    @pytest.mark.asyncio
    async def test_search_performance(self, real_vector_store):
        """Search should be fast (<100ms)."""
        query = "credential dumping"
        
        # Warm up
        await real_vector_store.semantic_search(query, limit=5)
        
        # Measure
        durations = []
        for _ in range(10):
            start = time.time()
            await real_vector_store.semantic_search(query, limit=10)
            durations.append((time.time() - start) * 1000)
        
        avg_duration = sum(durations) / len(durations)
        
        print(f"\n⚡ Search Performance:")
        print(f"   Average: {avg_duration:.1f}ms")
        print(f"   Min: {min(durations):.1f}ms")
        print(f"   Max: {max(durations):.1f}ms")
        
        # Should be reasonably fast
        assert avg_duration < 100, f"Too slow: {avg_duration:.1f}ms"
    
    @pytest.mark.asyncio
    async def test_embedding_performance(self, real_vector_store):
        """Embedding generation should be fast."""
        query = "test performance"
        
        start = time.time()
        for _ in range(100):
            real_vector_store._embed_query(f"{query} {_}")
        duration = (time.time() - start) * 1000 / 100
        
        print(f"\n⚡ Embedding Performance: {duration:.2f}ms avg")
        
        assert duration < 50, f"Too slow: {duration:.2f}ms"


# ═══════════════════════════════════════════════════════════════
# Test: Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestRealVectorStoreEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_search_with_empty_query(self, real_vector_store):
        """Should handle empty query gracefully."""
        results = await real_vector_store.semantic_search("", limit=5)
        
        # Should return results (embedding of empty string)
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_search_with_large_limit(self, real_vector_store):
        """Should handle large limit."""
        results = await real_vector_store.semantic_search(
            "test",
            limit=1000
        )
        
        # Should not exceed total documents
        stats = real_vector_store.get_stats()
        assert len(results) <= stats['total_documents']
    
    @pytest.mark.asyncio
    async def test_search_with_no_matches(self, real_vector_store):
        """Should handle case with very high min_score."""
        results = await real_vector_store.semantic_search(
            "test",
            limit=10,
            min_score=0.99  # Very high threshold
        )
        
        # Might return no results
        assert isinstance(results, list)
        print(f"\n   High threshold results: {len(results)}")
    
    @pytest.mark.asyncio
    async def test_cache_clearing(self, real_vector_store):
        """Should be able to clear cache."""
        # Populate cache
        await real_vector_store.semantic_search("test1", limit=5)
        await real_vector_store.semantic_search("test2", limit=5)
        
        stats_before = real_vector_store.get_stats()
        cache_size_before = stats_before['cache_size']
        
        # Clear cache
        real_vector_store.clear_cache()
        
        stats_after = real_vector_store.get_stats()
        cache_size_after = stats_after['cache_size']
        
        assert cache_size_after == 0
        print(f"\n🗑️  Cache cleared: {cache_size_before} → {cache_size_after}")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
