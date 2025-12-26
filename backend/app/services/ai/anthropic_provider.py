"""
NiksES Anthropic Claude Provider

Integration with Anthropic's Claude API for AI-powered email analysis.
"""

import logging
import asyncio
from typing import Optional, Dict, Any

import aiohttp

from .base import (
    BaseAIProvider,
    AIResponse,
    AIProviderError,
    AIConfigurationError,
    AIRateLimitError,
    AITimeoutError,
)

logger = logging.getLogger(__name__)


class AnthropicProvider(BaseAIProvider):
    """
    Anthropic Claude API provider.
    
    Supports Claude 3.5 Sonnet, Claude 3 Haiku, etc.
    """
    
    provider_name = "anthropic"
    default_model = "claude-3-5-sonnet-20241022"
    
    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 3,
    ):
        super().__init__(api_key, model, timeout, max_retries)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers."""
        return {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
        }
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2000,
    ) -> AIResponse:
        """
        Generate text using Claude.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens in response
            
        Returns:
            AIResponse with generated content
        """
        if not self.is_configured():
            raise AIConfigurationError("Anthropic API key not configured")
        
        # Build request
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        # Make request with retries
        last_error = None
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        self.API_URL,
                        headers=self._get_headers(),
                        json=payload,
                    ) as response:
                        data = await response.json()
                        
                        if response.status == 200:
                            # Extract content
                            content = ""
                            for block in data.get("content", []):
                                if block.get("type") == "text":
                                    content += block.get("text", "")
                            
                            # Calculate tokens
                            usage = data.get("usage", {})
                            tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                            
                            return AIResponse(
                                content=content,
                                model=data.get("model", self.model),
                                tokens_used=tokens,
                                finish_reason=data.get("stop_reason", "unknown"),
                                raw_response=data,
                            )
                        
                        elif response.status == 429:
                            # Rate limited - wait and retry
                            wait_time = 2 ** attempt
                            self.logger.warning(f"Rate limited, waiting {wait_time}s")
                            await asyncio.sleep(wait_time)
                            last_error = AIRateLimitError("Rate limit exceeded")
                            continue
                        
                        elif response.status == 401:
                            raise AIConfigurationError("Invalid API key")
                        
                        else:
                            error_msg = data.get("error", {}).get("message", str(data))
                            raise AIProviderError(f"API error ({response.status}): {error_msg}")
            
            except asyncio.TimeoutError:
                last_error = AITimeoutError(f"Request timed out after {self.timeout}s")
                continue
            
            except aiohttp.ClientError as e:
                last_error = AIProviderError(f"Connection error: {e}")
                await asyncio.sleep(2 ** attempt)
                continue
        
        raise last_error or AIProviderError("Max retries exceeded")
    
    async def test_connection(self) -> bool:
        """Test if provider is configured and working."""
        if not self.is_configured():
            return False
        
        try:
            response = await self.generate(
                prompt="Reply with just 'OK'",
                max_tokens=10,
            )
            return "ok" in response.content.lower()
        except Exception as e:
            self.logger.warning(f"Connection test failed: {e}")
            return False
    
    async def count_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        
        Uses approximation: ~4 characters per token for English.
        """
        # Anthropic doesn't have a public tokenizer, use approximation
        return len(text) // 4


class AnthropicHaikuProvider(AnthropicProvider):
    """Anthropic Claude 3 Haiku - faster, cheaper model."""
    
    default_model = "claude-3-haiku-20240307"
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key, model=self.default_model, **kwargs)


class AnthropicSonnetProvider(AnthropicProvider):
    """Anthropic Claude 3.5 Sonnet - balanced model."""
    
    default_model = "claude-3-5-sonnet-20241022"
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key, model=self.default_model, **kwargs)
