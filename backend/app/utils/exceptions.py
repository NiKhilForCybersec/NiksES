"""
NiksES Custom Exceptions

Centralized exception classes for error handling.
"""


class NiksESBaseException(Exception):
    """Base exception for all NiksES errors."""
    def __init__(self, message: str = "An error occurred"):
        self.message = message
        super().__init__(self.message)


# ============================================================================
# Parsing Exceptions
# ============================================================================

class ParsingError(NiksESBaseException):
    """Error parsing email content."""
    pass


class InvalidEmailFormatError(ParsingError):
    """Email format is invalid or unrecognized."""
    pass


class AttachmentProcessingError(ParsingError):
    """Error processing email attachment."""
    pass


class QRCodeDecodingError(ParsingError):
    """Error decoding QR code from image."""
    pass


class HeaderParsingError(ParsingError):
    """Error parsing email headers."""
    pass


# ============================================================================
# Validation Exceptions
# ============================================================================

class ValidationError(NiksESBaseException):
    """Input validation failed."""
    pass


class FileTooLargeError(ValidationError):
    """File exceeds maximum size limit."""
    pass


class InvalidFileTypeError(ValidationError):
    """File type is not allowed."""
    pass


class InvalidURLError(ValidationError):
    """URL format is invalid."""
    pass


class InvalidIPAddressError(ValidationError):
    """IP address format is invalid."""
    pass


class InvalidDomainError(ValidationError):
    """Domain format is invalid."""
    pass


class InvalidHashError(ValidationError):
    """Hash format is invalid."""
    pass


# ============================================================================
# Enrichment Exceptions
# ============================================================================

class EnrichmentError(NiksESBaseException):
    """Error during threat intelligence enrichment."""
    pass


class APIConnectionError(EnrichmentError):
    """Failed to connect to external API."""
    pass


class APIAuthenticationError(EnrichmentError):
    """API authentication failed (invalid key)."""
    pass


class APIRateLimitError(EnrichmentError):
    """API rate limit exceeded."""
    pass


class APITimeoutError(EnrichmentError):
    """API request timed out."""
    pass


class ProviderNotConfiguredError(EnrichmentError):
    """Enrichment provider is not configured."""
    pass


# ============================================================================
# Detection Exceptions
# ============================================================================

class DetectionError(NiksESBaseException):
    """Error during threat detection."""
    pass


class RuleExecutionError(DetectionError):
    """Error executing detection rule."""
    pass


class ScoringError(DetectionError):
    """Error calculating risk score."""
    pass


# ============================================================================
# AI Exceptions
# ============================================================================

class AIError(NiksESBaseException):
    """Error with AI/LLM operations."""
    pass


class AIProviderError(AIError):
    """AI provider returned an error."""
    pass


class AIContextLengthError(AIError):
    """Input exceeds AI context length."""
    pass


class AIRateLimitError(AIError):
    """AI provider rate limit exceeded."""
    pass


# ============================================================================
# Database Exceptions
# ============================================================================

class DatabaseError(NiksESBaseException):
    """Database operation failed."""
    pass


class RecordNotFoundError(DatabaseError):
    """Requested record not found."""
    pass


class DuplicateRecordError(DatabaseError):
    """Record already exists."""
    pass


# ============================================================================
# Export Exceptions
# ============================================================================

class ExportError(NiksESBaseException):
    """Error exporting analysis results."""
    pass


class UnsupportedFormatError(ExportError):
    """Export format is not supported."""
    pass


# ============================================================================
# Configuration Exceptions
# ============================================================================

class ConfigurationError(NiksESBaseException):
    """Application configuration error."""
    pass


class EncryptionError(ConfigurationError):
    """Error encrypting or decrypting data."""
    pass


class MissingAPIKeyError(ConfigurationError):
    """Required API key is not configured."""
    pass
