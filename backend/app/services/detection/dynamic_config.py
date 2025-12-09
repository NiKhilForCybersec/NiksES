"""
NiksES Dynamic Detection Configuration

Allows runtime configuration of detection parameters without code changes:
- Custom suspicious TLDs
- Custom spam/phishing keywords
- Whitelisted domains/senders
- Risk thresholds
- High-risk countries

Configuration is stored in SQLite and loaded at runtime.
"""

import json
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from pathlib import Path

from app.models.settings import DynamicDetectionConfig
from app.utils.constants import (
    SUSPICIOUS_TLDS,
    ROMANCE_SPAM_KEYWORDS,
    SPAM_DOMAIN_PATTERNS,
    FREEMAIL_DOMAINS,
)

logger = logging.getLogger(__name__)


class DynamicConfigManager:
    """
    Manages dynamic detection configuration.
    
    Merges default constants with user-defined custom values.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "data/config.json"
        self._config: Optional[DynamicDetectionConfig] = None
        self._last_loaded: Optional[datetime] = None
        self._cache_ttl_seconds = 60  # Reload every minute
        
        # Ensure data directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
    
    def get_config(self) -> DynamicDetectionConfig:
        """Get current configuration, loading from disk if needed."""
        now = datetime.utcnow()
        
        # Check if cache is stale
        if self._config is None or self._last_loaded is None:
            self._load_config()
        elif (now - self._last_loaded).total_seconds() > self._cache_ttl_seconds:
            self._load_config()
        
        return self._config or DynamicDetectionConfig()
    
    def _load_config(self):
        """Load configuration from disk."""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    self._config = DynamicDetectionConfig(**data)
            else:
                self._config = DynamicDetectionConfig()
            
            self._last_loaded = datetime.utcnow()
            logger.debug(f"Loaded dynamic config from {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self._config = DynamicDetectionConfig()
            self._last_loaded = datetime.utcnow()
    
    def save_config(self, config: DynamicDetectionConfig) -> bool:
        """Save configuration to disk."""
        try:
            with open(self.db_path, 'w') as f:
                json.dump(config.model_dump(), f, indent=2)
            
            self._config = config
            self._last_loaded = datetime.utcnow()
            logger.info(f"Saved dynamic config to {self.db_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def update_config(self, updates: Dict[str, Any]) -> DynamicDetectionConfig:
        """Update specific config fields."""
        config = self.get_config()
        config_dict = config.model_dump()
        config_dict.update(updates)
        new_config = DynamicDetectionConfig(**config_dict)
        self.save_config(new_config)
        return new_config
    
    # ============================================================
    # Merged Getters - Combine defaults with custom values
    # ============================================================
    
    def get_suspicious_tlds(self) -> Set[str]:
        """Get all suspicious TLDs (default + custom)."""
        config = self.get_config()
        all_tlds = set(SUSPICIOUS_TLDS)
        all_tlds.update(config.custom_suspicious_tlds)
        return all_tlds
    
    def get_spam_keywords(self) -> Set[str]:
        """Get all spam keywords (default + custom)."""
        config = self.get_config()
        all_keywords = set(ROMANCE_SPAM_KEYWORDS)
        all_keywords.update(config.custom_spam_keywords)
        all_keywords.update(config.custom_romance_keywords)
        return all_keywords
    
    def get_freemail_domains(self) -> Set[str]:
        """Get all freemail domains (default + custom)."""
        config = self.get_config()
        all_domains = set(FREEMAIL_DOMAINS)
        all_domains.update(config.custom_freemail_domains)
        return all_domains
    
    def get_whitelisted_domains(self) -> Set[str]:
        """Get whitelisted domains."""
        config = self.get_config()
        return set(config.whitelisted_domains)
    
    def get_whitelisted_senders(self) -> Set[str]:
        """Get whitelisted sender emails."""
        config = self.get_config()
        return set(config.whitelisted_senders)
    
    def get_financial_domains(self) -> Set[str]:
        """Get all legitimate financial domains (default + custom)."""
        from app.utils.constants import LEGITIMATE_FINANCIAL_DOMAINS
        config = self.get_config()
        all_domains = set(LEGITIMATE_FINANCIAL_DOMAINS)
        all_domains.update(config.custom_financial_domains)
        return all_domains
    
    def is_financial_domain(self, domain: str) -> bool:
        """Check if domain is a legitimate financial institution."""
        domain = domain.lower()
        return any(fin_domain in domain for fin_domain in self.get_financial_domains())
    
    def get_high_risk_countries(self) -> Set[str]:
        """Get high-risk country codes."""
        config = self.get_config()
        return set(config.high_risk_countries)
    
    def is_domain_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted."""
        return domain.lower() in self.get_whitelisted_domains()
    
    def is_sender_whitelisted(self, email: str) -> bool:
        """Check if sender email is whitelisted."""
        return email.lower() in self.get_whitelisted_senders()
    
    def is_tld_suspicious(self, tld: str) -> bool:
        """Check if TLD is suspicious."""
        # Normalize TLD (ensure it starts with dot)
        if not tld.startswith('.'):
            tld = '.' + tld
        return tld.lower() in self.get_suspicious_tlds()
    
    def is_country_high_risk(self, country_code: str) -> bool:
        """Check if country is high risk."""
        return country_code.upper() in self.get_high_risk_countries()


# Singleton instance
_config_manager: Optional[DynamicConfigManager] = None


def get_config_manager() -> DynamicConfigManager:
    """Get the configuration manager singleton."""
    global _config_manager
    if _config_manager is None:
        _config_manager = DynamicConfigManager()
    return _config_manager


def get_dynamic_config() -> DynamicDetectionConfig:
    """Convenience function to get current config."""
    return get_config_manager().get_config()


# ============================================================
# Helper functions for rules to use
# ============================================================

def get_all_suspicious_tlds() -> Set[str]:
    """Get all suspicious TLDs for detection rules."""
    return get_config_manager().get_suspicious_tlds()


def get_all_spam_keywords() -> Set[str]:
    """Get all spam keywords for detection rules."""
    return get_config_manager().get_spam_keywords()


def check_domain_whitelist(domain: str) -> bool:
    """Check if domain is whitelisted."""
    return get_config_manager().is_domain_whitelisted(domain)


def check_sender_whitelist(email: str) -> bool:
    """Check if sender is whitelisted."""
    return get_config_manager().is_sender_whitelisted(email)


def check_country_risk(country_code: str) -> bool:
    """Check if country is high risk."""
    return get_config_manager().is_country_high_risk(country_code)
