"""
NiksES Encryption Utilities

Provides encryption/decryption for sensitive data like API keys.
Uses Fernet (AES-128-CBC) symmetric encryption.
"""

import os
import base64
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import EncryptionError


# Salt for key derivation (can be changed but must be consistent)
DEFAULT_SALT = b'nikses_api_key_salt_v1'


class EncryptionManager:
    """
    Encrypt and decrypt sensitive data using Fernet symmetric encryption.
    
    The encryption key is derived from a server-side secret using PBKDF2.
    """
    
    def __init__(self, secret_key: str, salt: bytes = DEFAULT_SALT):
        """
        Initialize encryption with server secret.
        
        Args:
            secret_key: Server-side secret key for deriving encryption key
            salt: Salt for key derivation
        """
        if not secret_key:
            raise EncryptionError("Secret key cannot be empty")
        
        self._salt = salt
        self._fernet_key = self._derive_key(secret_key)
        self._fernet = Fernet(self._fernet_key)
    
    def _derive_key(self, secret: str) -> bytes:
        """
        Derive a Fernet-compatible key from the secret.
        
        Uses PBKDF2 with SHA256 to derive a 32-byte key,
        then base64-encodes it for Fernet compatibility.
        
        Args:
            secret: Secret string to derive key from
            
        Returns:
            Base64-encoded 32-byte key suitable for Fernet
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
        )
        key = kdf.derive(secret.encode('utf-8'))
        return base64.urlsafe_b64encode(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext: String to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return ""
        
        try:
            encrypted = self._fernet.encrypt(plaintext.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            ciphertext: Base64-encoded encrypted string
            
        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            return ""
        
        try:
            decrypted = self._fernet.decrypt(ciphertext.encode('utf-8'))
            return decrypted.decode('utf-8')
        except InvalidToken:
            raise EncryptionError("Invalid token or wrong key")
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")
    
    def is_encrypted(self, value: str) -> bool:
        """
        Check if a value appears to be encrypted.
        
        Args:
            value: String to check
            
        Returns:
            True if value looks like Fernet-encrypted data
        """
        if not value:
            return False
        
        # Fernet tokens start with 'gAAAAA' when base64 encoded
        return value.startswith('gAAAAA')


def generate_secret_key(length: int = 32) -> str:
    """
    Generate a cryptographically secure secret key.
    
    Args:
        length: Number of random bytes (default 32)
        
    Returns:
        Hex-encoded secret key string
    """
    return secrets.token_hex(length)


def mask_api_key(api_key: str, visible_chars: int = 4) -> str:
    """
    Mask API key for display, showing only first/last few characters.
    
    Args:
        api_key: API key to mask
        visible_chars: Number of characters to show at start and end
        
    Returns:
        Masked string like "sk-ab...xy"
    """
    if not api_key:
        return ""
    
    if len(api_key) <= visible_chars * 2:
        return "*" * len(api_key)
    
    return f"{api_key[:visible_chars]}...{api_key[-visible_chars:]}"


# Global encryption manager instance
_encryption_manager: Optional[EncryptionManager] = None


def get_encryption_manager() -> Optional[EncryptionManager]:
    """Get the global encryption manager instance."""
    return _encryption_manager


def init_encryption_manager(secret_key: str) -> EncryptionManager:
    """
    Initialize the global encryption manager.
    
    Args:
        secret_key: Server-side secret key
        
    Returns:
        Initialized EncryptionManager
    """
    global _encryption_manager
    _encryption_manager = EncryptionManager(secret_key)
    return _encryption_manager


def encrypt_api_key(api_key: str) -> str:
    """
    Encrypt an API key using the global manager.
    
    Args:
        api_key: API key to encrypt
        
    Returns:
        Encrypted API key
    """
    manager = get_encryption_manager()
    if not manager:
        raise EncryptionError("Encryption manager not initialized")
    return manager.encrypt(api_key)


def decrypt_api_key(encrypted_key: str) -> str:
    """
    Decrypt an API key using the global manager.
    
    Args:
        encrypted_key: Encrypted API key
        
    Returns:
        Decrypted API key
    """
    manager = get_encryption_manager()
    if not manager:
        raise EncryptionError("Encryption manager not initialized")
    return manager.decrypt(encrypted_key)
