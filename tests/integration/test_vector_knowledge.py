# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - VectorKnowledgeStore Integration Tests
# Phase 2.8: Testing - VectorKnowledgeStore
# Target: 100% success, 85%+ coverage
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import numpy as np
import pytest

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False

# Skip all tests if dependencies not available
pytestmark = pytest.mark.skipif(
    not DEPENDENCIES_AVAILABLE,
    reason="sentence-transformers or faiss-cpu not installed"
)


class TestVectorKnowledgeStore:
    """
    Integration tests for VectorKnowledgeStore (TIER 2).
    
    Coverage:
    - Initialization and model loading
    - Embedding generation
    - Vector search
    - Caching
    - Graceful degradation
    """
    
    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory with mock index."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        
        # Create FAISS index
        import faiss
        dim = 384
        index = faiss.IndexFlatL2(dim)
        
        # Add some dummy vectors
        dummy_vectors = np.random.rand(10, dim).astype('float32')
        index.add(dummy_vectors)
        
        index_path = data_dir / "raglox_vector_index.faiss"
        faiss.write_index(index, str(index_path))
        
        # Create metadata
        metadata = {
            'version': '1.0',
            'model': 'sentence-transformers/all-MiniLM-L6-v2',
            'embedding_dimension': 384,
            'total_documents': 10,
            'documents': [
                {
                    'id': f'rx-t1003-{i:03d}',
                    'type': 'rx_module',
                    'content': f'Test module {i} for credential dumping',
                    'metadata': {
                        'technique_id': 'T1003',
                        'platforms': ['windows'],
                        'executor': 'powershell'
                    }
                }
                for i in range(10)
            ]
        }
        
        metadata_path = data_dir / "raglox_vector_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        
        return data_dir
    
    @pytest.mark.asyncio
    async def test_initialization_success(self, temp_data_dir):
        """Test successful initialization."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        result = await store.initialize()
        
        assert result is True
        assert store.is_available() is True
        assert store._index is not None
        assert len(store._documents) == 10
    
    @pytest.mark.asyncio
    async def test_initialization_missing_index(self, tmp_path):
        """Test initialization with missing index file."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        store = VectorKnowledgeStore(data_path=str(empty_dir))
        result = await store.initialize()
        
        # Should return False but not raise error (graceful degradation)
        assert result is False
        assert store.is_available() is False
    
    @pytest.mark.asyncio
    async def test_embedding_generation(self, temp_data_dir):
        """Test embedding generation."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Generate embedding through semantic search (it will use _embed_query internally)
        query = "How to dump credentials from Windows?"
        results = await store.semantic_search(query, limit=1)
        
        # If we got results, embedding was successfully generated
        assert results is not None
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_semantic_search(self, temp_data_dir):
        """Test semantic search."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Perform search
        query = "credential dumping technique"
        results = await store.semantic_search(query, limit=5)
        
        assert isinstance(results, list)
        assert len(results) <= 5
        
        for result in results:
            assert hasattr(result, 'document_id')
            assert hasattr(result, 'content')
            assert hasattr(result, 'score')
            assert hasattr(result, 'metadata')
            # Score is distance, not similarity (lower is better)
            assert result.score >= 0
    
    @pytest.mark.asyncio
    async def test_semantic_search_with_filters(self, temp_data_dir):
        """Test semantic search with metadata filters."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Search with platform filter
        query = "credential dumping"
        filters = {'platforms': ['windows']}
        results = await store.semantic_search(query, limit=5, filters=filters)
        
        assert isinstance(results, list)
        for result in results:
            # All results should have 'windows' in platforms
            assert 'windows' in result.metadata.get('platforms', [])
    
    @pytest.mark.asyncio
    async def test_batch_search(self, temp_data_dir):
        """Test batch search."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Batch search
        queries = [
            "credential dumping",
            "password extraction",
            "Windows authentication"
        ]
        results = await store.batch_search(queries, limit=3)
        
        assert isinstance(results, list)
        assert len(results) == len(queries)
        
        for query_results in results:
            assert isinstance(query_results, list)
            assert len(query_results) <= 3
    
    @pytest.mark.asyncio
    async def test_hybrid_search(self, temp_data_dir):
        """Test hybrid search (semantic + keyword)."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Hybrid search requires keyword_results from TIER 1
        keyword_results = [
            {'id': 'rx-t1003-001', 'content': 'Test module 1'},
            {'id': 'rx-t1003-002', 'content': 'Test module 2'}
        ]
        
        query = "credential dumping T1003"
        results = await store.hybrid_search(
            query,
            keyword_results=keyword_results,
            limit=5,
            vector_weight=0.7
        )
        
        assert isinstance(results, list)
        assert len(results) <= 5
    
    @pytest.mark.asyncio
    async def test_search_unavailable(self):
        """Test search when store is not available."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        # Create store without initialization
        store = VectorKnowledgeStore(data_path="/nonexistent")
        
        # Search should return empty list
        results = await store.semantic_search("test query")
        assert results == []
    
    @pytest.mark.asyncio
    async def test_get_stats(self, temp_data_dir):
        """Test statistics retrieval."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        stats = store.get_stats()
        
        assert isinstance(stats, dict)
        assert 'initialized' in stats
        assert 'total_documents' in stats
        assert 'embedding_dimension' in stats
        assert 'index_size_mb' in stats
        
        assert stats['initialized'] is True
        assert stats['total_documents'] == 10
        assert stats['embedding_dimension'] == 384
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_on_error(self, temp_data_dir):
        """Test graceful degradation when errors occur."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Test that store works even after reset
        original_init_state = store._initialized
        store._initialized = False
        
        # Search should reinitialize automatically
        results = await store.semantic_search("test query", limit=5)
        assert isinstance(results, list)
        
        # Stats should reflect current state
        stats = store.get_stats()
        assert 'initialized' in stats
        # After reinitialize during search, it should be True again
        assert stats['initialized'] is True
    
    def test_vector_search_result_dataclass(self):
        """Test VectorSearchResult dataclass."""
        from src.core.vector_knowledge import VectorSearchResult
        
        result = VectorSearchResult(
            document_id='rx-t1003-001',
            content='Test content',
            score=0.85,
            metadata={'technique_id': 'T1003'}
        )
        
        assert result.document_id == 'rx-t1003-001'
        assert result.content == 'Test content'
        assert result.score == 0.85
        assert result.metadata == {'technique_id': 'T1003'}
    
    @pytest.mark.asyncio
    async def test_model_lazy_loading(self, temp_data_dir):
        """Test that model is lazily loaded."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        
        # Model should not be loaded yet
        assert store._model is None
        
        # Initialize
        await store.initialize()
        
        # Model should still not be loaded (lazy loading)
        # It will be loaded on first search/embedding generation
        
        # Perform search (this will load the model)
        await store.semantic_search("test", limit=1)
        
        # Now model should be loaded
        assert store._model is not None
    
    @pytest.mark.asyncio
    async def test_cache_integration(self, temp_data_dir):
        """Test Redis cache integration (if available)."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        # This test will work even without Redis (graceful degradation)
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Perform search twice
        query = "credential dumping"
        results1 = await store.semantic_search(query, limit=3)
        results2 = await store.semantic_search(query, limit=3)
        
        # Results should be identical
        assert len(results1) == len(results2)
        if results1:
            assert results1[0].document_id == results2[0].document_id
    
    @pytest.mark.asyncio
    async def test_different_top_k_values(self, temp_data_dir):
        """Test search with different top_k values."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        query = "test query"
        
        # Test different limit values
        for k in [1, 3, 5, 10]:
            results = await store.semantic_search(query, limit=k)
            assert isinstance(results, list)
            assert len(results) <= min(k, 10)  # Limited by k or total documents
    
    @pytest.mark.asyncio
    async def test_empty_query(self, temp_data_dir):
        """Test search with empty query."""
        from src.core.vector_knowledge import VectorKnowledgeStore
        
        store = VectorKnowledgeStore(data_path=str(temp_data_dir))
        await store.initialize()
        
        # Empty query will still generate an embedding and return results
        # So we just check that it doesn't crash
        results = await store.semantic_search("", limit=5)
        assert isinstance(results, list)
        # Empty query embedding is still valid, so we may get results
        assert len(results) <= 5
