"""
NiksES AI Provider Base Class

Abstract base class for LLM providers.
"""

import logging
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from app.models.analysis import AITriageResult, RecommendedAction

logger = logging.getLogger(__name__)


@dataclass
class AIResponse:
    """Response from AI provider."""
    content: str
    model: str
    tokens_used: int
    finish_reason: str
    raw_response: Optional[Dict[str, Any]] = None


class AIProviderError(Exception):
    """Base exception for AI provider errors."""
    pass


class AIConfigurationError(AIProviderError):
    """API key or configuration missing."""
    pass


class AIRateLimitError(AIProviderError):
    """Rate limit exceeded."""
    pass


class AITimeoutError(AIProviderError):
    """Request timed out."""
    pass


class AIResponseParseError(AIProviderError):
    """Failed to parse AI response."""
    pass


class BaseAIProvider(ABC):
    """
    Abstract base class for AI providers.
    
    Defines the interface that all AI providers must implement.
    """
    
    provider_name: str = "base"
    default_model: str = ""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 3,
    ):
        """
        Initialize provider.
        
        Args:
            api_key: API key for provider
            model: Model to use (defaults to provider default)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.api_key = api_key
        self.model = model or self.default_model
        self.timeout = timeout
        self.max_retries = max_retries
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> AIResponse:
        """
        Generate text from prompt.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens in response
            
        Returns:
            AIResponse with generated content
        """
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """Test if provider is configured and working."""
        pass
    
    async def generate_triage(
        self,
        analysis_context: Dict[str, Any],
        system_prompt: str,
        user_prompt: str,
    ) -> AITriageResult:
        """
        Generate AI triage from analysis context.
        
        Args:
            analysis_context: Dictionary with email analysis data
            system_prompt: System prompt for AI
            user_prompt: User prompt with context
            
        Returns:
            AITriageResult with AI-generated analysis
        """
        from datetime import datetime
        
        response = await self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.3,
            max_tokens=3000,  # Increased for comprehensive analysis
        )
        
        # Parse JSON from response
        try:
            parsed = self._parse_json_response(response.content)
        except AIResponseParseError as e:
            self.logger.error(f"Failed to parse AI response: {e}")
            # Return minimal result with extracted content
            parsed = {
                'summary': response.content[:500],
                'detailed_analysis': response.content,
                'key_findings': self._extract_findings_from_text(response.content),
            }
        
        # Build recommended actions
        actions = []
        for action_data in parsed.get('recommended_actions', []):
            if isinstance(action_data, dict):
                actions.append(RecommendedAction(
                    action=action_data.get('action', 'Review'),
                    priority=action_data.get('priority', 1),
                    description=action_data.get('description', ''),
                    automated=action_data.get('automated', False),
                ))
        
        # Extract key findings
        key_findings = parsed.get('key_findings', [])
        if not key_findings:
            # Try to generate findings from detailed analysis
            key_findings = self._extract_findings_from_text(
                parsed.get('detailed_analysis', '') + ' ' + parsed.get('classification_reasoning', '')
            )
        
        # Parse MITRE techniques (handle both string and dict formats)
        mitre_techniques = []
        for tech in parsed.get('mitre_techniques', []):
            if isinstance(tech, dict):
                mitre_techniques.append(tech.get('id', str(tech)))
            else:
                mitre_techniques.append(str(tech))
        
        return AITriageResult(
            summary=parsed.get('summary', '')[:500],
            detailed_analysis=parsed.get('detailed_analysis', '')[:3000],
            classification_reasoning=parsed.get('classification_reasoning', ''),
            risk_reasoning=parsed.get('risk_reasoning', ''),
            key_findings=key_findings[:10],  # Max 10 findings
            recommended_actions=actions,
            mitre_tactics=parsed.get('mitre_tactics', []),
            mitre_techniques=mitre_techniques,
            model_used=response.model,
            tokens_used=response.tokens_used,
            analysis_timestamp=datetime.utcnow(),
        )
    
    def _extract_findings_from_text(self, text: str) -> List[str]:
        """
        Extract key findings from unstructured text.
        
        Args:
            text: Text to extract findings from
            
        Returns:
            List of extracted findings
        """
        findings = []
        
        # Look for bullet points, numbered items, or sentences with indicators
        import re
        
        # Pattern for bullet points or numbered items
        bullet_pattern = r'[-•*]\s*([^-•*\n]+)'
        numbered_pattern = r'\d+[.)]\s*([^\n]+)'
        
        for match in re.findall(bullet_pattern, text):
            if len(match.strip()) > 20:  # Skip very short items
                findings.append(match.strip()[:200])
        
        for match in re.findall(numbered_pattern, text):
            if len(match.strip()) > 20:
                findings.append(match.strip()[:200])
        
        # If no structured findings, extract key sentences
        if not findings:
            sentences = text.split('.')
            indicator_words = ['suspicious', 'malicious', 'indicates', 'suggests', 'evidence', 
                             'phishing', 'fraudulent', 'impersonation', 'spoofed', 'threat']
            for sentence in sentences:
                if any(word in sentence.lower() for word in indicator_words):
                    clean = sentence.strip()
                    if len(clean) > 20:
                        findings.append(clean[:200] + '.')
        
        return findings[:5]  # Return max 5 extracted findings
    
    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """
        Parse JSON from AI response.
        
        Handles responses with markdown code blocks.
        """
        content = content.strip()
        
        # Try to extract JSON from markdown code block
        if '```json' in content:
            start = content.find('```json') + 7
            end = content.find('```', start)
            if end > start:
                content = content[start:end].strip()
        elif '```' in content:
            start = content.find('```') + 3
            end = content.find('```', start)
            if end > start:
                content = content[start:end].strip()
        
        # Try to find JSON object
        if not content.startswith('{'):
            start = content.find('{')
            if start >= 0:
                # Find matching closing brace
                depth = 0
                for i, c in enumerate(content[start:], start):
                    if c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            content = content[start:i+1]
                            break
        
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise AIResponseParseError(f"Invalid JSON: {e}")
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get provider information."""
        return {
            'name': self.provider_name,
            'model': self.model,
            'configured': self.is_configured(),
        }
