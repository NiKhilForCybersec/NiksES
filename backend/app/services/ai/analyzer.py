"""
NiksES AI Analyzer

Main AI analysis orchestrator that coordinates providers and prompts.
"""

import logging
from typing import Optional, Dict, Any, List, Type
from datetime import datetime

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import DetectionResults
from app.models.analysis import AITriageResult, RecommendedAction

from .base import BaseAIProvider, AIProviderError, AIConfigurationError
from .anthropic_provider import AnthropicProvider
from .openai_provider import OpenAIProvider
from .context import AnalysisContext, build_context
from .prompts import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
    build_summary_prompt,
    build_recommendation_prompt,
)

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI-powered email analysis orchestrator.
    
    Manages AI providers and generates analysis using LLMs.
    """
    
    def __init__(
        self,
        anthropic_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        preferred_provider: str = "anthropic",
        fallback_enabled: bool = True,
    ):
        """
        Initialize AI analyzer.
        
        Args:
            anthropic_api_key: Anthropic API key
            openai_api_key: OpenAI API key
            preferred_provider: Preferred provider ("anthropic" or "openai")
            fallback_enabled: Enable fallback to secondary provider
        """
        self.providers: Dict[str, BaseAIProvider] = {}
        self.preferred_provider = preferred_provider
        self.fallback_enabled = fallback_enabled
        
        # Initialize providers
        if anthropic_api_key:
            self.providers["anthropic"] = AnthropicProvider(api_key=anthropic_api_key)
        
        if openai_api_key:
            self.providers["openai"] = OpenAIProvider(api_key=openai_api_key)
        
        self.logger = logging.getLogger(__name__)
    
    def is_configured(self) -> bool:
        """Check if any provider is configured."""
        return any(p.is_configured() for p in self.providers.values())
    
    def get_configured_providers(self) -> List[str]:
        """Get list of configured provider names."""
        return [name for name, provider in self.providers.items() if provider.is_configured()]
    
    def get_provider(self, name: Optional[str] = None) -> Optional[BaseAIProvider]:
        """
        Get a provider by name or return preferred provider.
        
        Args:
            name: Provider name or None for preferred
            
        Returns:
            Provider instance or None
        """
        if name and name in self.providers:
            return self.providers[name]
        
        # Try preferred provider
        if self.preferred_provider in self.providers:
            provider = self.providers[self.preferred_provider]
            if provider.is_configured():
                return provider
        
        # Fall back to any configured provider
        for provider in self.providers.values():
            if provider.is_configured():
                return provider
        
        return None
    
    async def analyze(
        self,
        context: AnalysisContext,
        provider_name: Optional[str] = None,
    ) -> AITriageResult:
        """
        Perform full AI analysis.
        
        Args:
            context: Analysis context with email, enrichment, and detection
            provider_name: Optional specific provider to use
            
        Returns:
            AITriageResult with AI analysis
        """
        provider = self.get_provider(provider_name)
        
        if not provider:
            raise AIConfigurationError("No AI provider configured")
        
        # Build prompt
        email_dict = context.to_email_dict()
        enrichment_dict = context.to_enrichment_dict()
        detection_dict = context.to_detection_dict()
        
        user_prompt = build_analysis_prompt(email_dict, enrichment_dict, detection_dict)
        
        # Generate analysis
        try:
            result = await provider.generate_triage(
                analysis_context=context.to_full_dict(),
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
            return result
        
        except AIProviderError as e:
            self.logger.error(f"Primary provider failed: {e}")
            
            # Try fallback
            if self.fallback_enabled:
                fallback = self._get_fallback_provider(provider)
                if fallback:
                    self.logger.info(f"Falling back to {fallback.provider_name}")
                    return await fallback.generate_triage(
                        analysis_context=context.to_full_dict(),
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                    )
            
            raise
    
    async def generate_summary(
        self,
        context: AnalysisContext,
        provider_name: Optional[str] = None,
    ) -> str:
        """
        Generate a short summary of the analysis.
        
        Args:
            context: Analysis context
            provider_name: Optional specific provider
            
        Returns:
            Summary string
        """
        provider = self.get_provider(provider_name)
        
        if not provider:
            # Return fallback summary without AI
            return self._generate_fallback_summary(context)
        
        email_dict = context.to_email_dict()
        detection_dict = context.to_detection_dict()
        
        prompt = build_summary_prompt(email_dict, detection_dict)
        
        try:
            response = await provider.generate(
                prompt=prompt,
                system_prompt="You are a concise security analyst. Provide brief, factual summaries.",
                temperature=0.3,
                max_tokens=200,
            )
            return response.content.strip()
        
        except AIProviderError:
            return self._generate_fallback_summary(context)
    
    async def get_recommendations(
        self,
        context: AnalysisContext,
        provider_name: Optional[str] = None,
    ) -> List[RecommendedAction]:
        """
        Get AI-generated recommendations.
        
        Args:
            context: Analysis context
            provider_name: Optional specific provider
            
        Returns:
            List of RecommendedAction objects
        """
        provider = self.get_provider(provider_name)
        
        if not provider:
            return self._generate_fallback_recommendations(context)
        
        email_dict = context.to_email_dict()
        detection_dict = context.to_detection_dict()
        enrichment_dict = context.to_enrichment_dict()
        
        prompt = build_recommendation_prompt(email_dict, detection_dict, enrichment_dict)
        
        try:
            response = await provider.generate(
                prompt=prompt,
                system_prompt="You are a security analyst providing actionable recommendations.",
                temperature=0.3,
                max_tokens=500,
            )
            
            # Parse recommendations from response
            return self._parse_recommendations(response.content)
        
        except AIProviderError:
            return self._generate_fallback_recommendations(context)
    
    async def explain_verdict(
        self,
        context: AnalysisContext,
        audience: str = "technical",
        provider_name: Optional[str] = None,
    ) -> str:
        """
        Generate explanation of the verdict.
        
        Args:
            context: Analysis context
            audience: "technical", "executive", or "end_user"
            provider_name: Optional specific provider
            
        Returns:
            Explanation string
        """
        provider = self.get_provider(provider_name)
        
        if not provider:
            return self._generate_fallback_explanation(context)
        
        detection_dict = context.to_detection_dict()
        
        classification = detection_dict.get('primary_classification', 'unknown')
        risk_score = detection_dict.get('risk_score', 0)
        
        # Build detection summary
        triggered = detection_dict.get('rules_triggered', [])
        rule_names = [r.get('rule_name', '') for r in triggered[:5]]
        
        prompt = f"""Explain why this email was classified as {classification} with a risk score of {risk_score}/100.

Key indicators:
{chr(10).join('- ' + name for name in rule_names)}

Provide a clear explanation for a {audience} audience. Keep it concise (2-3 paragraphs max)."""

        try:
            response = await provider.generate(
                prompt=prompt,
                system_prompt="You explain security findings clearly and accurately.",
                temperature=0.3,
                max_tokens=400,
            )
            return response.content.strip()
        
        except AIProviderError:
            return self._generate_fallback_explanation(context)
    
    def _get_fallback_provider(self, primary: BaseAIProvider) -> Optional[BaseAIProvider]:
        """Get fallback provider different from primary."""
        for name, provider in self.providers.items():
            if provider != primary and provider.is_configured():
                return provider
        return None
    
    def _generate_fallback_summary(self, context: AnalysisContext) -> str:
        """Generate summary without AI."""
        if not context.detection:
            return "Email analyzed. No detection results available."
        
        det = context.detection
        classification = det.primary_classification.value if hasattr(det.primary_classification, 'value') else str(det.primary_classification)
        
        return f"Email classified as {classification} with risk score {det.risk_score}/100. {len(det.rules_triggered)} detection rules triggered."
    
    def _generate_fallback_recommendations(self, context: AnalysisContext) -> List[RecommendedAction]:
        """Generate recommendations without AI."""
        recommendations = []
        
        if not context.detection:
            return recommendations
        
        det = context.detection
        
        if det.risk_score >= 60:
            recommendations.append(RecommendedAction(
                action="Block Sender",
                priority=1,
                description="Block the sender domain/address to prevent further emails",
                automated=True,
            ))
            recommendations.append(RecommendedAction(
                action="Quarantine Email",
                priority=1,
                description="Move email to quarantine for investigation",
                automated=True,
            ))
        
        if det.risk_score >= 40:
            recommendations.append(RecommendedAction(
                action="Investigate",
                priority=2,
                description="Perform manual investigation of email contents and sender",
                automated=False,
            ))
        
        if len(context.email.urls) > 0:
            recommendations.append(RecommendedAction(
                action="Block URLs",
                priority=2,
                description="Add malicious URLs to blocklist",
                automated=True,
            ))
        
        return recommendations
    
    def _generate_fallback_explanation(self, context: AnalysisContext) -> str:
        """Generate explanation without AI."""
        if not context.detection:
            return "Unable to explain verdict - no detection results available."
        
        det = context.detection
        classification = det.primary_classification.value if hasattr(det.primary_classification, 'value') else str(det.primary_classification)
        
        triggered = [r.rule_name for r in det.rules_triggered[:3]]
        
        return f"This email was classified as {classification} based on {len(det.rules_triggered)} detection rules, including: {', '.join(triggered)}. The risk score of {det.risk_score}/100 reflects the severity of these findings."
    
    def _parse_recommendations(self, content: str) -> List[RecommendedAction]:
        """Parse recommendations from AI response."""
        recommendations = []
        
        # Split by numbered items
        lines = content.strip().split('\n')
        current_item = None
        priority = 1
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check if new numbered item
            if line[0].isdigit() and (line[1] == '.' or line[1] == ')'):
                if current_item:
                    recommendations.append(current_item)
                
                # Extract text after number
                text = line[2:].strip().lstrip('.-) ')
                
                # Determine if automated
                automated = any(kw in text.lower() for kw in ['block', 'quarantine', 'alert', 'notify'])
                
                current_item = RecommendedAction(
                    action=text[:50],
                    priority=priority,
                    description=text,
                    automated=automated,
                )
                priority += 1
            elif current_item:
                # Append to current item description
                current_item.description += ' ' + line
        
        if current_item:
            recommendations.append(current_item)
        
        return recommendations[:5]  # Max 5 recommendations
    
    async def close(self):
        """Close all provider sessions."""
        for provider in self.providers.values():
            if hasattr(provider, 'close'):
                await provider.close()


# Singleton instance
_ai_analyzer: Optional[AIAnalyzer] = None


def init_ai_analyzer(
    anthropic_api_key: Optional[str] = None,
    openai_api_key: Optional[str] = None,
    preferred_provider: str = "anthropic",
) -> AIAnalyzer:
    """Initialize the global AI analyzer."""
    global _ai_analyzer
    _ai_analyzer = AIAnalyzer(
        anthropic_api_key=anthropic_api_key,
        openai_api_key=openai_api_key,
        preferred_provider=preferred_provider,
    )
    return _ai_analyzer


def get_ai_analyzer() -> Optional[AIAnalyzer]:
    """Get the global AI analyzer instance."""
    return _ai_analyzer


async def analyze_email_with_ai(
    email: ParsedEmail,
    enrichment: Optional[EnrichmentResults] = None,
    detection: Optional[DetectionResults] = None,
) -> Optional[AITriageResult]:
    """
    Convenience function for AI analysis.
    
    Args:
        email: Parsed email
        enrichment: Optional enrichment results
        detection: Optional detection results
        
    Returns:
        AITriageResult or None if AI not configured
    """
    analyzer = get_ai_analyzer()
    
    if not analyzer or not analyzer.is_configured():
        return None
    
    context = build_context(email, enrichment, detection)
    
    try:
        return await analyzer.analyze(context)
    except AIProviderError as e:
        logger.error(f"AI analysis failed: {e}")
        return None
