"""
NiksES AI Module

AI-powered email security analysis using LLMs.
"""

from .base import (
    BaseAIProvider,
    AIResponse,
    AIProviderError,
    AIConfigurationError,
    AIRateLimitError,
    AITimeoutError,
    AIResponseParseError,
)

from .anthropic_provider import (
    AnthropicProvider,
    AnthropicHaikuProvider,
    AnthropicSonnetProvider,
)

from .openai_provider import (
    OpenAIProvider,
    GPT4OProvider,
    GPT4OMiniProvider,
)

from .context import (
    AnalysisContext,
    build_context,
)

from .analyzer import (
    AIAnalyzer,
    init_ai_analyzer,
    get_ai_analyzer,
    analyze_email_with_ai,
)

from .prompts import (
    SYSTEM_PROMPT,
    OUTPUT_SCHEMA,
    build_analysis_prompt,
    build_summary_prompt,
    build_recommendation_prompt,
)

from .se_analyzer import (
    SocialEngineeringAnalyzer,
    SEAnalysisResult,
    SEIntent,
    PersuasionTechnique,
    get_se_analyzer,
)

from .content_analyzer import (
    ContentAnalyzer,
    ContentAnalysisResult,
    AttackIntent,
    RequestedAction,
    TargetData,
    BusinessProcess,
    get_content_analyzer,
)

__all__ = [
    # Base
    'BaseAIProvider',
    'AIResponse',
    'AIProviderError',
    'AIConfigurationError',
    'AIRateLimitError',
    'AITimeoutError',
    'AIResponseParseError',
    
    # Anthropic
    'AnthropicProvider',
    'AnthropicHaikuProvider',
    'AnthropicSonnetProvider',
    
    # OpenAI
    'OpenAIProvider',
    'GPT4OProvider',
    'GPT4OMiniProvider',
    
    # Context
    'AnalysisContext',
    'build_context',
    
    # Analyzer
    'AIAnalyzer',
    'init_ai_analyzer',
    'get_ai_analyzer',
    'analyze_email_with_ai',
    
    # Prompts
    'SYSTEM_PROMPT',
    'OUTPUT_SCHEMA',
    'build_analysis_prompt',
    'build_summary_prompt',
    'build_recommendation_prompt',
    
    # Social Engineering Analyzer
    'SocialEngineeringAnalyzer',
    'SEAnalysisResult',
    'SEIntent',
    'PersuasionTechnique',
    'get_se_analyzer',
    
    # Content Analyzer
    'ContentAnalyzer',
    'ContentAnalysisResult',
    'AttackIntent',
    'RequestedAction',
    'TargetData',
    'BusinessProcess',
    'get_content_analyzer',
]
