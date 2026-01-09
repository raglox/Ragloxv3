#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Knowledge Vectorization Script
# One-time setup to create FAISS index from base knowledge
# Phase 3.5: RAG Vector Integration
# ═══════════════════════════════════════════════════════════════

"""
Knowledge Vectorization Script

This script converts the RAGLOX base knowledge (RX Modules + Nuclei Templates)
into vector embeddings and builds a FAISS index for semantic search.

Usage:
    python scripts/vectorize_knowledge.py

Output:
    - data/raglox_vector_index.faiss (FAISS HNSW index)
    - data/raglox_vector_metadata.json (Document metadata)

Runtime: ~5-10 minutes
Index Size: ~200MB
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np
from tqdm import tqdm

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.knowledge import EmbeddedKnowledge, get_knowledge

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class KnowledgeVectorizer:
    """
    Vectorizes base knowledge for semantic search.
    
    Process:
    1. Load RX Modules and Nuclei Templates
    2. Convert to text documents
    3. Generate embeddings
    4. Build FAISS index
    5. Save to disk
    """
    
    def __init__(self, data_path: str = "data"):
        self.data_path = Path(data_path)
        self.knowledge: EmbeddedKnowledge = None
        self.model = None
        self.documents: List[Dict] = []
        self.embeddings: np.ndarray = None
        self.index = None
    
    async def run(self):
        """Run the full vectorization pipeline."""
        try:
            logger.info("🚀 Starting knowledge vectorization...")
            
            # 1. Load knowledge
            await self.load_knowledge()
            
            # 2. Load embedding model
            await self.load_model()
            
            # 3. Convert knowledge to documents
            await self.create_documents()
            
            # 4. Generate embeddings
            await self.generate_embeddings()
            
            # 5. Build FAISS index
            await self.build_index()
            
            # 6. Save to disk
            await self.save()
            
            logger.info("✅ Vectorization complete!")
            self.print_stats()
            
        except Exception as e:
            logger.error(f"❌ Vectorization failed: {e}", exc_info=True)
            sys.exit(1)
    
    async def load_knowledge(self):
        """Load base knowledge."""
        logger.info("📚 Loading base knowledge...")
        self.knowledge = get_knowledge()
        
        if not self.knowledge.is_loaded():
            logger.error("Knowledge base not loaded")
            raise RuntimeError("Knowledge base not loaded")
        
        stats = self.knowledge.get_statistics()
        logger.info(
            f"✅ Knowledge loaded: "
            f"{stats['total_rx_modules']} RX modules, "
            f"{stats['total_nuclei_templates']} Nuclei templates"
        )
    
    async def load_model(self):
        """Load sentence transformer model."""
        logger.info("🧠 Loading embedding model...")
        
        try:
            from sentence_transformers import SentenceTransformer
            
            # Use MiniLM-L6-v2: good balance of speed and quality
            # Embedding dimension: 384
            self.model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
            
            logger.info("✅ Embedding model loaded (384D)")
            
        except ImportError:
            logger.error("sentence-transformers not installed. Run: pip install sentence-transformers")
            raise
    
    async def create_documents(self):
        """Convert knowledge to text documents."""
        logger.info("📄 Creating documents...")
        
        # Process RX Modules
        rx_modules, _ = self.knowledge.list_modules(limit=10000)
        
        for module in tqdm(rx_modules, desc="Processing RX modules"):
            # Create searchable text from module
            text = self._rx_module_to_text(module)
            
            self.documents.append({
                'id': module['rx_module_id'],
                'type': 'rx_module',
                'content': text,
                'metadata': {
                    'rx_module_id': module['rx_module_id'],
                    'technique_id': module['technique_id'],
                    'technique_name': module['technique_name'],
                    'platforms': module['execution']['platforms'],
                    'executor': module['execution']['executor_type'],
                    'elevation_required': module['execution']['elevation_required']
                }
            })
        
        # Process Nuclei Templates
        nuclei_templates, _ = self.knowledge.list_nuclei_templates(limit=20000)
        
        for template in tqdm(nuclei_templates, desc="Processing Nuclei templates"):
            # Create searchable text from template
            text = self._nuclei_template_to_text(template)
            
            self.documents.append({
                'id': template['template_id'],
                'type': 'nuclei_template',
                'content': text,
                'metadata': {
                    'template_id': template['template_id'],
                    'name': template['name'],
                    'severity': template['severity'],
                    'cve_id': template.get('cve_id', []),
                    'tags': template.get('tags', []),
                    'protocol': template.get('protocol', [])
                }
            })
        
        logger.info(f"✅ Created {len(self.documents)} documents")
    
    def _rx_module_to_text(self, module: Dict) -> str:
        """Convert RX Module to searchable text."""
        parts = [
            f"Technique: {module['technique_name']}",
            f"ID: {module['technique_id']}",
            f"Description: {module['description']}",
            f"Platforms: {', '.join(module['execution']['platforms'])}",
            f"Executor: {module['execution']['executor_type']}"
        ]
        
        if module['execution']['elevation_required']:
            parts.append("Requires elevation: yes")
        
        # Add variables if any
        if module.get('variables'):
            var_names = [v['name'] for v in module['variables']]
            parts.append(f"Variables: {', '.join(var_names)}")
        
        return " | ".join(parts)
    
    def _nuclei_template_to_text(self, template: Dict) -> str:
        """Convert Nuclei Template to searchable text."""
        parts = [
            f"Template: {template['name']}",
            f"Severity: {template['severity']}",
            f"Description: {template.get('description', '')}"
        ]
        
        # Add CVE IDs
        cve_ids = template.get('cve_id', [])
        if cve_ids:
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            parts.append(f"CVE: {', '.join(cve_ids)}")
        
        # Add tags
        tags = template.get('tags', [])
        if tags:
            parts.append(f"Tags: {', '.join(tags[:5])}")  # Limit tags
        
        # Add protocol
        protocol = template.get('protocol', [])
        if protocol:
            parts.append(f"Protocol: {', '.join(protocol)}")
        
        return " | ".join(parts)
    
    async def generate_embeddings(self):
        """Generate embeddings for all documents."""
        logger.info("🔢 Generating embeddings...")
        
        if not self.documents:
            raise RuntimeError("No documents to embed")
        
        # Extract text content
        texts = [doc['content'] for doc in self.documents]
        
        # Generate embeddings in batches
        batch_size = 32
        all_embeddings = []
        
        for i in tqdm(range(0, len(texts), batch_size), desc="Generating embeddings"):
            batch = texts[i:i + batch_size]
            embeddings = self.model.encode(
                batch,
                show_progress_bar=False,
                convert_to_numpy=True
            )
            all_embeddings.append(embeddings)
        
        # Concatenate all embeddings
        self.embeddings = np.vstack(all_embeddings).astype('float32')
        
        logger.info(
            f"✅ Generated {self.embeddings.shape[0]} embeddings "
            f"({self.embeddings.shape[1]}D)"
        )
    
    async def build_index(self):
        """Build FAISS index."""
        logger.info("🏗️  Building FAISS index...")
        
        try:
            import faiss
            
            # Get embedding dimension
            dim = self.embeddings.shape[1]
            
            # Build HNSW index for fast approximate nearest neighbor search
            # HNSW is very fast for high-dimensional data
            self.index = faiss.IndexHNSWFlat(dim, 32)  # 32 neighbors
            
            # Add vectors to index
            self.index.add(self.embeddings)
            
            logger.info(
                f"✅ FAISS index built: {self.index.ntotal} vectors, "
                f"HNSW with M=32"
            )
            
        except ImportError:
            logger.error("faiss-cpu not installed. Run: pip install faiss-cpu")
            raise
    
    async def save(self):
        """Save index and metadata to disk."""
        logger.info("💾 Saving to disk...")
        
        # Ensure data directory exists
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        # Save FAISS index
        index_path = self.data_path / "raglox_vector_index.faiss"
        
        try:
            import faiss
            faiss.write_index(self.index, str(index_path))
            logger.info(f"✅ Index saved: {index_path}")
        except Exception as e:
            logger.error(f"Failed to save FAISS index: {e}")
            raise
        
        # Save metadata
        metadata_path = self.data_path / "raglox_vector_metadata.json"
        
        metadata = {
            'version': '1.0',
            'created_at': '2026-01-09',
            'model': 'sentence-transformers/all-MiniLM-L6-v2',
            'embedding_dimension': self.embeddings.shape[1],
            'total_documents': len(self.documents),
            'document_types': {
                'rx_module': sum(1 for d in self.documents if d['type'] == 'rx_module'),
                'nuclei_template': sum(1 for d in self.documents if d['type'] == 'nuclei_template')
            },
            'documents': self.documents
        }
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ Metadata saved: {metadata_path}")
        
        # Calculate sizes
        index_size_mb = index_path.stat().st_size / (1024 * 1024)
        metadata_size_mb = metadata_path.stat().st_size / (1024 * 1024)
        
        logger.info(
            f"📊 File sizes: "
            f"Index={index_size_mb:.1f}MB, "
            f"Metadata={metadata_size_mb:.1f}MB, "
            f"Total={index_size_mb + metadata_size_mb:.1f}MB"
        )
    
    def print_stats(self):
        """Print final statistics."""
        stats = self.knowledge.get_statistics()
        
        print("\n" + "=" * 60)
        print("✅ VECTORIZATION COMPLETE")
        print("=" * 60)
        print(f"📊 Total documents:        {len(self.documents):,}")
        print(f"   - RX Modules:          {stats['total_rx_modules']:,}")
        print(f"   - Nuclei Templates:    {stats['total_nuclei_templates']:,}")
        print(f"🔢 Embedding dimension:    {self.embeddings.shape[1]}D")
        print(f"📁 Output files:")
        print(f"   - {self.data_path}/raglox_vector_index.faiss")
        print(f"   - {self.data_path}/raglox_vector_metadata.json")
        print("=" * 60)
        print("\n✅ You can now use hybrid knowledge retrieval (TIER 1 + TIER 2)")
        print("   The vector store will be automatically loaded on startup.\n")


async def main():
    """Main entry point."""
    vectorizer = KnowledgeVectorizer()
    await vectorizer.run()


if __name__ == "__main__":
    asyncio.run(main())
