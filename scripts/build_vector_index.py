#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Build Vector Index for Testing
# Creates FAISS index from Knowledge Base for real testing
# ═══════════════════════════════════════════════════════════════

import json
import sys
import time
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.knowledge import EmbeddedKnowledge


def build_vector_index(
    data_path: str = "data",
    output_path: str = "data",
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    max_documents: int = 1000
):
    """
    Build vector index from knowledge base.
    
    Args:
        data_path: Path to knowledge base data
        output_path: Path to save vector index
        model_name: Sentence transformer model
        max_documents: Maximum documents to index (for testing)
    """
    print("=" * 70)
    print("🚀 RAGLOX Vector Index Builder")
    print("=" * 70)
    
    # Load knowledge base
    print(f"\n📚 Loading knowledge base from: {data_path}")
    knowledge = EmbeddedKnowledge(data_path=data_path)
    loaded = knowledge.load()
    
    if not loaded:
        print("❌ Failed to load knowledge base")
        return False
    
    stats = knowledge.get_statistics()
    print(f"✅ Loaded:")
    print(f"   - RX Modules: {stats['total_rx_modules']}")
    print(f"   - Nuclei Templates: {stats['total_nuclei_templates']}")
    print(f"   - Techniques: {stats['total_techniques']}")
    
    # Prepare documents
    print(f"\n📝 Preparing documents...")
    documents = []
    
    # Add RX Modules (sample for testing)
    modules, total = knowledge.list_modules(limit=max_documents // 2)
    for module in modules:
        doc_id = module['rx_module_id']
        content = f"{module['technique_name']}: {module['description']}"
        
        documents.append({
            'id': doc_id,
            'type': 'rx_module',
            'content': content,
            'metadata': {
                'technique_id': module['technique_id'],
                'platforms': module['execution']['platforms'],
                'executor': module['execution']['executor_type']
            }
        })
    
    # Add Nuclei Templates (sample for testing)
    templates, total = knowledge.list_nuclei_templates(limit=max_documents // 2)
    for template in templates:
        doc_id = template['template_id']
        content = f"{template['name']}: {template.get('description', '')}"
        
        documents.append({
            'id': doc_id,
            'type': 'nuclei_template',
            'content': content,
            'metadata': {
                'severity': template['severity'],
                'tags': template.get('tags', []),
                'cve_id': template.get('cve_id', [])
            }
        })
    
    print(f"✅ Prepared {len(documents)} documents")
    
    # Load embedding model
    print(f"\n🤖 Loading embedding model: {model_name}")
    print("   (This may take a minute on first run...)")
    start = time.time()
    model = SentenceTransformer(model_name)
    print(f"✅ Model loaded in {time.time() - start:.1f}s")
    
    # Generate embeddings
    print(f"\n🔢 Generating embeddings...")
    texts = [doc['content'] for doc in documents]
    
    start = time.time()
    embeddings = model.encode(
        texts,
        show_progress_bar=True,
        convert_to_numpy=True,
        batch_size=32
    )
    duration = time.time() - start
    
    print(f"✅ Generated {len(embeddings)} embeddings in {duration:.1f}s")
    print(f"   Dimension: {embeddings.shape[1]}D")
    print(f"   Speed: {len(embeddings) / duration:.1f} docs/sec")
    
    # Build FAISS index
    print(f"\n🗂️  Building FAISS index...")
    dimension = embeddings.shape[1]
    
    # Use HNSW index for fast approximate search
    index = faiss.IndexHNSWFlat(dimension, 32)  # 32 = M parameter
    index.hnsw.efConstruction = 40  # Construction time quality
    index.hnsw.efSearch = 16  # Search time quality
    
    # Add vectors to index
    start = time.time()
    index.add(embeddings.astype('float32'))
    print(f"✅ Index built in {time.time() - start:.1f}s")
    print(f"   Total vectors: {index.ntotal}")
    
    # Save index
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    index_path = output_dir / "raglox_vector_index.faiss"
    metadata_path = output_dir / "raglox_vector_metadata.json"
    
    print(f"\n💾 Saving index...")
    faiss.write_index(index, str(index_path))
    
    # Save metadata
    metadata = {
        'version': '1.0',
        'model': model_name,
        'embedding_dimension': dimension,
        'total_documents': len(documents),
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'documents': documents
    }
    
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    # Calculate sizes
    index_size_mb = index_path.stat().st_size / (1024 * 1024)
    metadata_size_mb = metadata_path.stat().st_size / (1024 * 1024)
    
    print(f"✅ Saved:")
    print(f"   Index: {index_path} ({index_size_mb:.2f} MB)")
    print(f"   Metadata: {metadata_path} ({metadata_size_mb:.2f} MB)")
    
    # Test search
    print(f"\n🔍 Testing search...")
    test_query = "credential dumping windows"
    query_embedding = model.encode([test_query], convert_to_numpy=True)
    
    k = 5
    distances, indices = index.search(query_embedding.astype('float32'), k)
    
    print(f"   Query: '{test_query}'")
    print(f"   Top {k} results:")
    for i, (dist, idx) in enumerate(zip(distances[0], indices[0]), 1):
        if idx < len(documents):
            doc = documents[idx]
            score = 1.0 / (1.0 + dist)  # Convert distance to similarity
            print(f"   {i}. {doc['id'][:30]:<30} (score: {score:.3f})")
    
    print("\n" + "=" * 70)
    print("✅ Vector index built successfully!")
    print("=" * 70)
    
    return True


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Build vector index for testing")
    parser.add_argument(
        "--data-path",
        default="data",
        help="Path to knowledge base data"
    )
    parser.add_argument(
        "--output-path",
        default="data",
        help="Path to save vector index"
    )
    parser.add_argument(
        "--max-docs",
        type=int,
        default=1000,
        help="Maximum documents to index (default: 1000)"
    )
    
    args = parser.parse_args()
    
    success = build_vector_index(
        data_path=args.data_path,
        output_path=args.output_path,
        max_documents=args.max_docs
    )
    
    sys.exit(0 if success else 1)
