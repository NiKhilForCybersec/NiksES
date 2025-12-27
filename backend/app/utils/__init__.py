"""
NiksES Utilities Package
========================

Common utilities, constants, and helper functions used throughout the application.
"""

from app.utils.constants import (
    APP_NAME,
    APP_FULL_NAME,
    APP_VERSION,
    APP_DESCRIPTION,
    MAX_EMAIL_SIZE_BYTES,
    MAX_ATTACHMENT_SIZE_BYTES,
    RISK_THRESHOLDS,
    RISK_LEVEL_INFORMATIONAL,
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_CRITICAL,
    VERDICT_CLEAN,
    VERDICT_SUSPICIOUS,
    VERDICT_MALICIOUS,
    VERDICT_UNKNOWN,
)

from app.utils.exceptions import (
    NiksESBaseException,
    ParsingError,
    EnrichmentError,
    DetectionError,
    AIError,
    DatabaseError,
    ValidationError,
    APIConnectionError,
    APIAuthenticationError,
    APIRateLimitError,
)

from app.utils.helpers import (
    get_risk_level,
    calculate_hash,
    extract_domain,
    normalize_url,
    defang_url,
    defang_ip,
    extract_urls,
    extract_ips,
    extract_emails,
    utc_now,
    format_timestamp,
    truncate_string,
)

from app.utils.validators import (
    validate_file_upload,
    validate_email_address,
    validate_domain,
    validate_ip_address,
    validate_url,
    sanitize_string,
    sanitize_filename,
)

from app.utils.encryption import (
    EncryptionManager,
    mask_api_key,
    generate_secret_key,
    get_encryption_manager,
    init_encryption_manager,
)

from app.utils.security import (
    RateLimiter,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    sanitize_error_message,
    safe_error_response,
    validate_file_size,
    validate_file_extension,
    sanitize_search_query,
    MAX_FILE_SIZE,
)

__all__ = [
    # Constants
    "APP_NAME",
    "APP_FULL_NAME",
    "APP_VERSION",
    "APP_DESCRIPTION",
    "MAX_EMAIL_SIZE_BYTES",
    "MAX_ATTACHMENT_SIZE_BYTES",
    "RISK_THRESHOLDS",
    "RISK_LEVEL_INFORMATIONAL",
    "RISK_LEVEL_LOW",
    "RISK_LEVEL_MEDIUM",
    "RISK_LEVEL_HIGH",
    "RISK_LEVEL_CRITICAL",
    "VERDICT_CLEAN",
    "VERDICT_SUSPICIOUS",
    "VERDICT_MALICIOUS",
    "VERDICT_UNKNOWN",
    # Exceptions
    "NiksESBaseException",
    "ParsingError",
    "EnrichmentError",
    "DetectionError",
    "AIError",
    "DatabaseError",
    "ValidationError",
    "APIConnectionError",
    "APIAuthenticationError",
    "APIRateLimitError",
    # Helpers
    "get_risk_level",
    "calculate_hash",
    "extract_domain",
    "normalize_url",
    "defang_url",
    "defang_ip",
    "extract_urls",
    "extract_ips",
    "extract_emails",
    "utc_now",
    "format_timestamp",
    "truncate_string",
    # Validators
    "validate_file_upload",
    "validate_email_address",
    "validate_domain",
    "validate_ip_address",
    "validate_url",
    "sanitize_string",
    "sanitize_filename",
    # Encryption
    "EncryptionManager",
    "mask_api_key",
    "generate_secret_key",
    "get_encryption_manager",
    "init_encryption_manager",
    # Security
    "RateLimiter",
    "RateLimitMiddleware",
    "SecurityHeadersMiddleware",
    "sanitize_error_message",
    "safe_error_response",
    "validate_file_size",
    "validate_file_extension",
    "sanitize_search_query",
    "MAX_FILE_SIZE",
]
