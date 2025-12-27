"""
NiksES AI Copilot

Main AI triage logic - coordinates LLM calls and parses responses.
"""

import logging
import json
from typing import Optional, Dict, Any, Literal
from datetime import datetime
from enum import Enum

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import DetectionResults
from app.models.analysis import AITriageResult, RecommendedAction
from app.utils.exceptions import AIError, AIProviderError
from app.utils.constants import (
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_TEMPERATURE,
)

from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .prompts import SYSTEM_PROMPT, format_analysis_prompt

logger = logging.getLogger(__name__)


class AIProvider(str, Enum):
    """Supported AI providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class AICopilot:
    """
    AI Triage Copilot - provides AI-powered analysis.
    
    Supports multiple LLM providers (OpenAI, Anthropic).
    """
    
    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        preferred_provider: AIProvider = AIProvider.OPENAI,
        model: Optional[str] = None,
        max_tokens: int = DEFAULT_LLM_MAX_TOKENS,
        temperature: float = DEFAULT_LLM_TEMPERATURE,
    ):
        """
        Initialize copilot with API keys.
        
        Args:
            openai_api_key: OpenAI API key
            anthropic_api_key: Anthropic API key
            preferred_provider: Which provider to use first
            model: Optional model override
            max_tokens: Max response tokens
            temperature: Response temperature
        """
        self.openai_provider = None
        self.anthropic_provider = None
        self.preferred_provider = preferred_provider
        self.max_tokens = max_tokens
        self.temperature = temperature
        
        # Initialize providers
        if openai_api_key:
            self.openai_provider = OpenAIProvider(
                api_key=openai_api_key,
                model=model or DEFAULT_LLM_MODEL,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        
        if anthropic_api_key:
            from .anthropic_provider import DEFAULT_ANTHROPIC_MODEL
            self.anthropic_provider = AnthropicProvider(
                api_key=anthropic_api_key,
                model=model or DEFAULT_ANTHROPIC_MODEL,
                max_tokens=max_tokens,
                temperature=temperature,
            )
    
    @property
    def is_configured(self) -> bool:
        """Check if at least one AI provider is configured."""
        return (
            (self.openai_provider and self.openai_provider.is_configured) or
            (self.anthropic_provider and self.anthropic_provider.is_configured)
        )
    
    def get_active_provider(self):
        """Get the active provider based on preference and availability."""
        if self.preferred_provider == AIProvider.OPENAI:
            if self.openai_provider and self.openai_provider.is_configured:
                return self.openai_provider
            if self.anthropic_provider and self.anthropic_provider.is_configured:
                return self.anthropic_provider
        else:
            if self.anthropic_provider and self.anthropic_provider.is_configured:
                return self.anthropic_provider
            if self.openai_provider and self.openai_provider.is_configured:
                return self.openai_provider
        
        return None
    
    async def analyze(
        self,
        email: ParsedEmail,
        enrichment: EnrichmentResults,
        detection: DetectionResults
    ) -> Optional[AITriageResult]:
        """
        Run AI triage analysis.
        
        Args:
            email: Parsed email
            enrichment: Enrichment results
            detection: Detection results
            
        Returns:
            AITriageResult or None if AI unavailable/failed
        """
        provider = self.get_active_provider()
        if not provider:
            logger.warning("No AI provider configured - skipping AI triage")
            return None
        
        try:
            # Build prompt
            user_prompt = format_analysis_prompt(email, enrichment, detection)
            
            logger.info(f"Running AI triage with {provider.provider_name}")
            logger.debug(f"Prompt length: {len(user_prompt)} chars")
            
            # Call provider
            response = await provider.generate_triage(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            
            # Parse response
            content = response["content"]
            parsed = provider.parse_json_response(content)
            
            # Build result
            result = provider.build_triage_result(
                parsed=parsed,
                model=response["model"],
                tokens=response["tokens_used"],
            )
            
            logger.info(f"AI triage complete: {response['tokens_used']} tokens used")
            
            return result
            
        except AIProviderError as e:
            logger.error(f"AI provider error: {e}")
            # Try fallback provider
            return await self._try_fallback(email, enrichment, detection, provider)
        except Exception as e:
            logger.error(f"Unexpected AI error: {e}")
            return None
    
    async def _try_fallback(
        self,
        email: ParsedEmail,
        enrichment: EnrichmentResults,
        detection: DetectionResults,
        failed_provider,
    ) -> Optional[AITriageResult]:
        """Try fallback provider if primary fails."""
        fallback = None
        
        if failed_provider == self.openai_provider:
            if self.anthropic_provider and self.anthropic_provider.is_configured:
                fallback = self.anthropic_provider
        else:
            if self.openai_provider and self.openai_provider.is_configured:
                fallback = self.openai_provider
        
        if not fallback:
            logger.warning("No fallback AI provider available")
            return None
        
        try:
            logger.info(f"Trying fallback provider: {fallback.provider_name}")
            
            user_prompt = format_analysis_prompt(email, enrichment, detection)
            
            response = await fallback.generate_triage(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            
            content = response["content"]
            parsed = fallback.parse_json_response(content)
            
            return fallback.build_triage_result(
                parsed=parsed,
                model=response["model"],
                tokens=response["tokens_used"],
            )
            
        except Exception as e:
            logger.error(f"Fallback provider also failed: {e}")
            return None
    
    async def ask_question(
        self,
        question: str,
        email: ParsedEmail,
        enrichment: EnrichmentResults,
        detection: DetectionResults,
        previous_triage: Optional[AITriageResult] = None,
    ) -> Optional[str]:
        """
        Ask a follow-up question about the analysis.
        
        Args:
            question: User's question
            email: Parsed email
            enrichment: Enrichment results
            detection: Detection results
            previous_triage: Previous triage result for context
            
        Returns:
            Answer string or None
        """
        provider = self.get_active_provider()
        if not provider:
            return None
        
        try:
            from .prompts import format_question_prompt
            
            # Build context from previous analysis
            context = ""
            if previous_triage:
                context = previous_triage.summary + "\n" + previous_triage.detailed_analysis
            else:
                context = f"Risk Score: {detection.risk_score}/100, Classification: {detection.primary_classification.value}"
            
            user_prompt = format_question_prompt(question, context)
            
            response = await provider.generate_triage(
                system_prompt="You are an expert SOC analyst. Answer questions about email security analysis concisely and accurately.",
                user_prompt=user_prompt,
            )
            
            return response["content"]
            
        except Exception as e:
            logger.error(f"Question answering failed: {e}")
            return None
    
    async def test_connection(self) -> Dict[str, bool]:
        """Test connection to all configured providers."""
        results = {}
        
        if self.openai_provider:
            results["openai"] = await self.openai_provider.test_connection()
        
        if self.anthropic_provider:
            results["anthropic"] = await self.anthropic_provider.test_connection()
        
        return results
    
    def get_provider_status(self) -> Dict[str, Any]:
        """Get status of all providers."""
        return {
            "openai": {
                "configured": self.openai_provider is not None and self.openai_provider.is_configured,
                "model": self.openai_provider.model if self.openai_provider else None,
            },
            "anthropic": {
                "configured": self.anthropic_provider is not None and self.anthropic_provider.is_configured,
                "model": self.anthropic_provider.model if self.anthropic_provider else None,
            },
            "preferred_provider": self.preferred_provider.value,
            "active_provider": self.get_active_provider().provider_name if self.get_active_provider() else None,
        }


# Singleton instance
_ai_copilot: Optional[AICopilot] = None


def init_ai_copilot(
    openai_api_key: Optional[str] = None,
    anthropic_api_key: Optional[str] = None,
    **kwargs
) -> AICopilot:
    """Initialize the AI copilot singleton."""
    global _ai_copilot
    _ai_copilot = AICopilot(
        openai_api_key=openai_api_key,
        anthropic_api_key=anthropic_api_key,
        **kwargs
    )
    return _ai_copilot


def get_ai_copilot() -> Optional[AICopilot]:
    """Get the AI copilot singleton."""
    return _ai_copilot


async def analyze_with_ai(
    email: ParsedEmail,
    enrichment: EnrichmentResults,
    detection: DetectionResults,
    openai_api_key: Optional[str] = None,
    anthropic_api_key: Optional[str] = None,
) -> Optional[AITriageResult]:
    """
    Convenience function for AI analysis.
    
    Args:
        email: Parsed email
        enrichment: Enrichment results
        detection: Detection results
        openai_api_key: OpenAI API key (uses singleton if not provided)
        anthropic_api_key: Anthropic API key
        
    Returns:
        AITriageResult or None
    """
    # Use existing singleton or create temporary instance
    copilot = _ai_copilot
    
    if openai_api_key or anthropic_api_key:
        copilot = AICopilot(
            openai_api_key=openai_api_key,
            anthropic_api_key=anthropic_api_key,
        )
    
    if not copilot or not copilot.is_configured:
        logger.warning("AI not configured - skipping AI triage")
        return None
    
    return await copilot.analyze(email, enrichment, detection)
