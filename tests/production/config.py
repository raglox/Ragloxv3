"""
Production Test Configuration
Manages configuration for production-like testing environment
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv

# Load test environment variables
load_dotenv('.env.test')


@dataclass
class ProductionTestConfig:
    """Configuration for production-like testing"""
    
    # ==========================================
    # Database Configuration
    # ==========================================
    db_host: str = field(default_factory=lambda: os.getenv("DATABASE_HOST", "localhost"))
    db_port: int = field(default_factory=lambda: int(os.getenv("DATABASE_PORT", "5433")))
    db_name: str = field(default_factory=lambda: os.getenv("DATABASE_NAME", "raglox_test_production"))
    db_user: str = field(default_factory=lambda: os.getenv("DATABASE_USER", "raglox_test"))
    db_password: str = field(default_factory=lambda: os.getenv("DATABASE_PASSWORD", "test_password_secure_123"))
    
    @property
    def database_url(self) -> str:
        """Get database connection URL"""
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
    
    # ==========================================
    # Redis Configuration
    # ==========================================
    redis_host: str = field(default_factory=lambda: os.getenv("REDIS_HOST", "localhost"))
    redis_port: int = field(default_factory=lambda: int(os.getenv("REDIS_PORT", "6380")))
    redis_db: int = field(default_factory=lambda: int(os.getenv("REDIS_DB", "0")))
    redis_password: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_PASSWORD"))
    
    @property
    def redis_url(self) -> str:
        """Get Redis connection URL"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"
    
    # ==========================================
    # API Configuration
    # ==========================================
    api_host: str = field(default_factory=lambda: os.getenv("API_HOST", "localhost"))
    api_port: int = field(default_factory=lambda: int(os.getenv("API_PORT", "8001")))
    api_timeout: int = field(default_factory=lambda: int(os.getenv("API_TIMEOUT", "60")))
    
    @property
    def api_base_url(self) -> str:
        """Get API base URL"""
        return f"http://{self.api_host}:{self.api_port}"
    
    # ==========================================
    # LLM Configuration (for real testing)
    # ==========================================
    llm_enabled: bool = field(default_factory=lambda: os.getenv("LLM_ENABLED", "true").lower() == "true")
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "openai"))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "gpt-3.5-turbo"))
    llm_api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    llm_temperature: float = field(default_factory=lambda: float(os.getenv("LLM_TEMPERATURE", "0.7")))
    llm_max_tokens: int = field(default_factory=lambda: int(os.getenv("LLM_MAX_TOKENS", "2000")))
    
    # ==========================================
    # Test Target Configuration
    # ==========================================
    test_target_network: str = field(default_factory=lambda: os.getenv("TEST_TARGET_NETWORK", "192.168.100.0/24"))
    test_target_dvwa: str = field(default_factory=lambda: os.getenv("TEST_TARGET_DVWA", "192.168.100.10"))
    test_target_webgoat: str = field(default_factory=lambda: os.getenv("TEST_TARGET_WEBGOAT", "192.168.100.11"))
    test_target_juiceshop: str = field(default_factory=lambda: os.getenv("TEST_TARGET_JUICESHOP", "192.168.100.12"))
    test_target_nginx: str = field(default_factory=lambda: os.getenv("TEST_TARGET_NGINX", "192.168.100.13"))
    
    @property
    def test_target_hosts(self) -> List[str]:
        """Get list of all test target hosts"""
        return [
            self.test_target_dvwa,
            self.test_target_webgoat,
            self.test_target_juiceshop,
            self.test_target_nginx,
        ]
    
    # ==========================================
    # Security Configuration
    # ==========================================
    exploit_disabled: bool = field(default_factory=lambda: os.getenv("EXPLOIT_DISABLED", "true").lower() == "true")
    exploit_require_approval: bool = field(default_factory=lambda: os.getenv("EXPLOIT_REQUIRE_APPROVAL", "true").lower() == "true")
    
    # ==========================================
    # Mission Limits
    # ==========================================
    max_concurrent_missions: int = field(default_factory=lambda: int(os.getenv("MAX_CONCURRENT_MISSIONS", "10")))
    max_missions_per_month: int = field(default_factory=lambda: int(os.getenv("MAX_MISSIONS_PER_MONTH", "1000")))
    max_targets_per_mission: int = field(default_factory=lambda: int(os.getenv("MAX_TARGETS_PER_MISSION", "100")))
    
    # ==========================================
    # Test Execution Settings
    # ==========================================
    test_timeout: int = field(default_factory=lambda: int(os.getenv("TEST_TIMEOUT", "300")))
    test_data_cleanup: bool = field(default_factory=lambda: os.getenv("TEST_DATA_CLEANUP", "true").lower() == "true")
    
    # ==========================================
    # Polling Settings
    # ==========================================
    poll_interval: int = 5  # seconds
    max_wait_time: int = 300  # seconds (5 minutes)
    
    def __post_init__(self):
        """Validate configuration after initialization"""
        # Validate required fields
        if self.llm_enabled and not self.llm_api_key:
            raise ValueError("LLM is enabled but OPENAI_API_KEY is not set")
        
        # Validate network configuration
        if not self.test_target_network:
            raise ValueError("TEST_TARGET_NETWORK is required")
    
    def get_target_url(self, target: str, port: int = 80, path: str = "") -> str:
        """Get full URL for a test target"""
        return f"http://{target}:{port}{path}"
    
    def is_docker_environment(self) -> bool:
        """Check if running inside Docker"""
        return os.path.exists('/.dockerenv')
    
    def to_dict(self) -> dict:
        """Convert config to dictionary"""
        return {
            "database_url": self.database_url,
            "redis_url": self.redis_url,
            "api_base_url": self.api_base_url,
            "llm_enabled": self.llm_enabled,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "test_targets": self.test_target_hosts,
            "exploit_disabled": self.exploit_disabled,
            "max_concurrent_missions": self.max_concurrent_missions,
        }
    
    def __repr__(self) -> str:
        """String representation (hide sensitive data)"""
        return (
            f"ProductionTestConfig(\n"
            f"  api_base_url='{self.api_base_url}',\n"
            f"  database='{self.db_host}:{self.db_port}/{self.db_name}',\n"
            f"  redis='{self.redis_host}:{self.redis_port}/{self.redis_db}',\n"
            f"  llm_enabled={self.llm_enabled},\n"
            f"  llm_model='{self.llm_model}',\n"
            f"  test_targets={len(self.test_target_hosts)},\n"
            f"  exploit_disabled={self.exploit_disabled}\n"
            f")"
        )


# Global instance for convenience
_config: Optional[ProductionTestConfig] = None


def get_config() -> ProductionTestConfig:
    """Get or create global configuration instance"""
    global _config
    if _config is None:
        _config = ProductionTestConfig()
    return _config


def reload_config() -> ProductionTestConfig:
    """Reload configuration from environment"""
    global _config
    load_dotenv('.env.test', override=True)
    _config = ProductionTestConfig()
    return _config
