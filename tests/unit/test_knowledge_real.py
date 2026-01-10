# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - REAL Knowledge Base Tests
# NO MOCKS - Tests with actual data files
# Phase 2 RAG Testing: EmbeddedKnowledge (TIER 1)
# ═══════════════════════════════════════════════════════════════

import pytest
import time
from pathlib import Path
from typing import Dict, Any, List

from src.core.knowledge import (
    EmbeddedKnowledge,
    init_knowledge,
    get_knowledge,
    RXModule,
    Technique,
    Tactic,
    KnowledgeStats,
    NucleiTemplate,
)


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def real_knowledge():
    """
    Real knowledge base loaded from actual data files.
    NO MOCKS - uses production data.
    """
    # Reset singleton
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()
    
    # Use production data path
    data_path = Path(__file__).parent.parent.parent / "data"
    
    print(f"\n📂 Loading knowledge from: {data_path}")
    print(f"   Files expected:")
    print(f"   - raglox_executable_modules.json")
    print(f"   - raglox_threat_library.json")
    print(f"   - raglox_nuclei_templates.json")
    
    # Initialize knowledge base
    knowledge = EmbeddedKnowledge(data_path=str(data_path))
    loaded = knowledge.load()
    
    if not loaded:
        pytest.skip("Knowledge base data files not available")
    
    print(f"✅ Knowledge loaded successfully")
    
    yield knowledge
    
    # Cleanup
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()


# ═══════════════════════════════════════════════════════════════
# Test: Initialization & Data Loading
# ═══════════════════════════════════════════════════════════════

class TestRealKnowledgeInitialization:
    """Test real knowledge base initialization and data loading."""
    
    def test_knowledge_base_loads_successfully(self, real_knowledge):
        """Knowledge base should load from real files."""
        assert real_knowledge.is_loaded() is True
        print(f"✅ Knowledge base loaded: {real_knowledge.is_loaded()}")
    
    def test_statistics_are_calculated(self, real_knowledge):
        """Statistics should be calculated from real data."""
        stats = real_knowledge.get_statistics()
        
        assert stats is not None
        assert isinstance(stats, dict)
        
        # Check required fields
        assert 'total_techniques' in stats
        assert 'total_tactics' in stats
        assert 'total_rx_modules' in stats
        assert 'total_nuclei_templates' in stats
        
        print(f"\n📊 Knowledge Base Statistics:")
        print(f"   Techniques: {stats['total_techniques']}")
        print(f"   Tactics: {stats['total_tactics']}")
        print(f"   RX Modules: {stats['total_rx_modules']}")
        print(f"   Nuclei Templates: {stats['total_nuclei_templates']}")
        print(f"   Memory: {stats.get('memory_size_mb', 0):.2f} MB")
        
        # Verify we have real data (not empty)
        assert stats['total_techniques'] > 0, "Should have loaded techniques"
        assert stats['total_rx_modules'] > 0, "Should have loaded RX modules"
    
    def test_platforms_are_indexed(self, real_knowledge):
        """Platforms should be indexed from real data."""
        stats = real_knowledge.get_statistics()
        platforms = stats.get('platforms', [])
        
        assert len(platforms) > 0, "Should have platform data"
        print(f"\n🖥️  Platforms: {platforms}")
        
        # Common platforms should exist
        platform_names_lower = [p.lower() for p in platforms]
        assert any('windows' in p for p in platform_names_lower)
        assert any('linux' in p for p in platform_names_lower)


# ═══════════════════════════════════════════════════════════════
# Test: RX Modules (Atomic Red Team Tests)
# ═══════════════════════════════════════════════════════════════

class TestRealRXModules:
    """Test real RX Module queries and retrieval."""
    
    def test_get_module_by_id(self, real_knowledge):
        """Should retrieve specific RX module by ID."""
        stats = real_knowledge.get_statistics()
        total_modules = stats['total_rx_modules']
        
        if total_modules == 0:
            pytest.skip("No RX modules available")
        
        # Get first module from list
        modules, total = real_knowledge.list_modules(limit=1)
        assert len(modules) > 0, "Should have at least one module"
        
        module_id = modules[0]['rx_module_id']
        module = real_knowledge.get_module(module_id)
        
        assert module is not None
        assert module['rx_module_id'] == module_id
        assert 'technique_id' in module
        assert 'execution' in module
        
        print(f"\n🔬 Retrieved Module: {module_id}")
        print(f"   Technique: {module['technique_id']}")
        print(f"   Platforms: {module['execution']['platforms']}")
    
    def test_get_modules_for_technique(self, real_knowledge):
        """Should retrieve all modules for a specific technique."""
        # T1003 = OS Credential Dumping (common technique)
        technique_id = "T1003"
        modules = real_knowledge.get_modules_for_technique(technique_id)
        
        assert isinstance(modules, list)
        
        if len(modules) > 0:
            print(f"\n🎯 Modules for {technique_id}: {len(modules)}")
            # Check first module
            module = modules[0]
            assert module['technique_id'] == technique_id
            assert 'rx_module_id' in module
            assert 'execution' in module
    
    def test_get_modules_by_platform(self, real_knowledge):
        """Should filter modules by platform."""
        # Test Windows platform
        modules = real_knowledge.get_modules_for_platform("windows", limit=10)
        
        assert isinstance(modules, list)
        assert len(modules) > 0, "Should have Windows modules"
        
        # Verify all modules are for Windows
        for module in modules:
            platforms = [p.lower() for p in module['execution']['platforms']]
            assert 'windows' in platforms
        
        print(f"\n🪟 Windows Modules: {len(modules)}")
    
    def test_search_modules_by_keyword(self, real_knowledge):
        """Should search modules by keyword."""
        query = "credential"
        modules = real_knowledge.search_modules(query, limit=10)
        
        assert isinstance(modules, list)
        
        if len(modules) > 0:
            print(f"\n🔍 Search '{query}': {len(modules)} results")
            # Verify results contain keyword
            first_module = modules[0]
            content = (
                first_module.get('technique_name', '') + ' ' +
                first_module.get('description', '')
            ).lower()
            assert 'credential' in content or 'cred' in content
    
    def test_module_scoring_and_selection(self, real_knowledge):
        """Should select best module based on criteria."""
        module = real_knowledge.get_module_for_task(
            technique="T1003",
            platform="windows",
            executor_type="powershell"
        )
        
        if module:
            print(f"\n⭐ Best Module for T1003/Windows/PowerShell:")
            print(f"   ID: {module['rx_module_id']}")
            print(f"   Name: {module['technique_name']}")
            
            assert module['technique_id'] == "T1003"
            assert 'windows' in [p.lower() for p in module['execution']['platforms']]


# ═══════════════════════════════════════════════════════════════
# Test: MITRE ATT&CK Techniques & Tactics
# ═══════════════════════════════════════════════════════════════

class TestRealTechniquesAndTactics:
    """Test MITRE ATT&CK techniques and tactics from real data."""
    
    def test_get_technique_by_id(self, real_knowledge):
        """Should retrieve technique information."""
        # T1003 = OS Credential Dumping
        technique = real_knowledge.get_technique("T1003")
        
        if technique:
            assert technique['id'] == "T1003"
            assert 'name' in technique
            assert 'platforms' in technique
            
            print(f"\n📖 Technique T1003:")
            print(f"   Name: {technique['name']}")
            print(f"   Platforms: {technique['platforms']}")
            print(f"   Test Count: {technique.get('test_count', 0)}")
    
    def test_list_all_techniques(self, real_knowledge):
        """Should list all techniques with pagination."""
        techniques, total = real_knowledge.list_techniques(limit=10)
        
        assert isinstance(techniques, list)
        assert isinstance(total, int)
        assert total > 0, "Should have techniques"
        assert len(techniques) <= 10, "Should respect limit"
        
        print(f"\n📚 Total Techniques: {total}")
        print(f"   Retrieved: {len(techniques)}")
    
    def test_list_all_tactics(self, real_knowledge):
        """Should list all MITRE tactics."""
        tactics = real_knowledge.list_tactics()
        
        assert isinstance(tactics, list)
        assert len(tactics) > 0, "Should have tactics"
        
        print(f"\n🎯 Total Tactics: {len(tactics)}")
        
        # Check structure
        if tactics:
            tactic = tactics[0]
            assert 'id' in tactic
            assert 'name' in tactic
            assert 'technique_count' in tactic
    
    def test_get_techniques_for_tactic(self, real_knowledge):
        """Should retrieve techniques for a specific tactic."""
        # TA0006 = Credential Access
        techniques = real_knowledge.get_techniques_for_tactic("TA0006")
        
        assert isinstance(techniques, list)
        
        if len(techniques) > 0:
            print(f"\n🔑 Credential Access (TA0006) Techniques: {len(techniques)}")
            # Verify structure
            tech = techniques[0]
            assert 'id' in tech
            assert 'name' in tech


# ═══════════════════════════════════════════════════════════════
# Test: Specialist Module Queries
# ═══════════════════════════════════════════════════════════════

class TestRealSpecialistQueries:
    """Test specialized module queries for specialists."""
    
    def test_get_recon_modules(self, real_knowledge):
        """Should retrieve reconnaissance modules."""
        modules = real_knowledge.get_recon_modules(platform="windows")
        
        assert isinstance(modules, list)
        
        if len(modules) > 0:
            print(f"\n🔍 Recon Modules (Windows): {len(modules)}")
            # Check first module
            module = modules[0]
            assert 'technique_id' in module
            # Recon techniques start with T10xx, T18xx
            assert module['technique_id'].startswith('T1')
    
    def test_get_credential_modules(self, real_knowledge):
        """Should retrieve credential harvesting modules."""
        modules = real_knowledge.get_credential_modules(platform="windows")
        
        assert isinstance(modules, list)
        
        if len(modules) > 0:
            print(f"\n🔑 Credential Modules (Windows): {len(modules)}")
            # T1003, T1555, T1552 are credential techniques
            tech_ids = [m['technique_id'] for m in modules]
            assert any(tid.startswith('T1003') or tid.startswith('T1555') for tid in tech_ids)
    
    def test_get_exploit_modules(self, real_knowledge):
        """Should retrieve exploitation modules."""
        modules = real_knowledge.get_exploit_modules(vuln_type="eternalblue")
        
        assert isinstance(modules, list)
        
        if len(modules) > 0:
            print(f"\n💥 Exploit Modules (EternalBlue): {len(modules)}")
    
    def test_get_privesc_modules(self, real_knowledge):
        """Should retrieve privilege escalation modules."""
        modules = real_knowledge.get_privesc_modules(platform="windows")
        
        assert isinstance(modules, list)
        
        if len(modules) > 0:
            print(f"\n⬆️  PrivEsc Modules (Windows): {len(modules)}")


# ═══════════════════════════════════════════════════════════════
# Test: Nuclei Templates
# ═══════════════════════════════════════════════════════════════

class TestRealNucleiTemplates:
    """Test Nuclei vulnerability scanning templates."""
    
    def test_nuclei_templates_loaded(self, real_knowledge):
        """Nuclei templates should be loaded."""
        stats = real_knowledge.get_statistics()
        total_nuclei = stats.get('total_nuclei_templates', 0)
        
        print(f"\n🔬 Nuclei Templates: {total_nuclei}")
        
        if total_nuclei == 0:
            pytest.skip("No Nuclei templates available")
        
        assert total_nuclei > 0
    
    def test_get_critical_nuclei_templates(self, real_knowledge):
        """Should retrieve critical severity templates."""
        templates = real_knowledge.get_nuclei_critical_templates(limit=10)
        
        assert isinstance(templates, list)
        
        if len(templates) > 0:
            print(f"\n🚨 Critical Templates: {len(templates)}")
            # Verify severity
            for template in templates:
                assert template['severity'].lower() == 'critical'
    
    def test_get_nuclei_templates_by_tag(self, real_knowledge):
        """Should filter templates by tag."""
        templates = real_knowledge.get_nuclei_templates_by_tag("rce", limit=10)
        
        assert isinstance(templates, list)
        
        if len(templates) > 0:
            print(f"\n💣 RCE Templates: {len(templates)}")
            # Verify tag exists
            for template in templates:
                tags_lower = [t.lower() for t in template.get('tags', [])]
                assert 'rce' in tags_lower
    
    def test_search_nuclei_templates(self, real_knowledge):
        """Should search templates by keyword."""
        results = real_knowledge.search_nuclei_templates("log4j", limit=10)
        
        assert isinstance(results, list)
        
        if len(results) > 0:
            print(f"\n🔍 Log4j Templates: {len(results)}")
    
    def test_get_nuclei_template_by_cve(self, real_knowledge):
        """Should retrieve template by CVE ID."""
        # Try to find a template with CVE
        templates, _ = real_knowledge.list_nuclei_templates(limit=100)
        
        cve_template = None
        for t in templates:
            if t.get('cve_id'):
                cve_template = t
                break
        
        if cve_template:
            cve_id = cve_template['cve_id'][0] if isinstance(cve_template['cve_id'], list) else cve_template['cve_id']
            result = real_knowledge.get_nuclei_template_by_cve(cve_id)
            
            if result:
                print(f"\n🔍 Template for {cve_id}:")
                print(f"   ID: {result['template_id']}")
                print(f"   Severity: {result['severity']}")


# ═══════════════════════════════════════════════════════════════
# Test: Performance & Optimization
# ═══════════════════════════════════════════════════════════════

class TestRealKnowledgePerformance:
    """Test knowledge base performance with real data."""
    
    def test_module_retrieval_performance(self, real_knowledge):
        """Module retrieval should be fast (< 10ms)."""
        # Get a valid module ID
        modules, _ = real_knowledge.list_modules(limit=1)
        if not modules:
            pytest.skip("No modules available")
        
        module_id = modules[0]['rx_module_id']
        
        # Measure retrieval time
        start = time.time()
        for _ in range(100):
            real_knowledge.get_module(module_id)
        duration_ms = (time.time() - start) * 1000 / 100
        
        print(f"\n⚡ Module Retrieval: {duration_ms:.2f}ms avg")
        assert duration_ms < 10, f"Too slow: {duration_ms:.2f}ms"
    
    def test_search_performance(self, real_knowledge):
        """Search should be reasonably fast (< 100ms)."""
        start = time.time()
        results = real_knowledge.search_modules("credential", limit=20)
        duration_ms = (time.time() - start) * 1000
        
        print(f"\n⚡ Search Performance: {duration_ms:.2f}ms")
        assert duration_ms < 100, f"Too slow: {duration_ms:.2f}ms"
    
    def test_list_techniques_pagination(self, real_knowledge):
        """Pagination should work efficiently."""
        # Get first page
        page1, total = real_knowledge.list_techniques(limit=10, offset=0)
        
        # Get second page
        page2, _ = real_knowledge.list_techniques(limit=10, offset=10)
        
        # Should be different pages
        if len(page1) > 0 and len(page2) > 0:
            assert page1[0]['id'] != page2[0]['id']
        
        print(f"\n📄 Pagination: Total={total}, Page1={len(page1)}, Page2={len(page2)}")


# ═══════════════════════════════════════════════════════════════
# Test: Singleton & Caching
# ═══════════════════════════════════════════════════════════════

class TestRealKnowledgeSingleton:
    """Test singleton pattern and caching."""
    
    def test_get_knowledge_returns_cached_instance(self):
        """get_knowledge() should return cached instance."""
        EmbeddedKnowledge.reset()
        get_knowledge.cache_clear()
        
        # First call
        kb1 = get_knowledge()
        
        # Second call should return same instance
        kb2 = get_knowledge()
        
        assert kb1 is kb2
        assert kb1.is_loaded()
        
        print(f"\n✅ Singleton working: {kb1 is kb2}")
        
        EmbeddedKnowledge.reset()
        get_knowledge.cache_clear()
    
    def test_reload_refreshes_data(self, real_knowledge):
        """Reload should refresh the knowledge base."""
        # Get initial stats
        stats_before = real_knowledge.get_statistics()
        
        # Reload
        result = real_knowledge.reload()
        
        assert result is True
        assert real_knowledge.is_loaded()
        
        # Stats should still be available
        stats_after = real_knowledge.get_statistics()
        assert stats_after['total_techniques'] == stats_before['total_techniques']
        
        print(f"\n🔄 Reload successful")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
