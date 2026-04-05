"""
Encryption utilities for securing sensitive data at rest.
"""
import os
import base64
from cryptography.fernet import Fernet

logger = None  # Will be set if logging is configured elsewhere

def get_encryption_key() -> bytes:
    """
    Get encryption key from environment variable.
    If not set, generate one and store it in a file for development.
    In production, this MUST be set via RELAY_ENCRYPTION_KEY environment variable.
    """
    key_env = os.getenv("RELAY_ENCRYPTION_KEY")
    if key_env:
        # Expect base64-encoded 32-byte key (already URL-safe base64 encoded)
        try:
            # Fernet key is already url-safe base64 encoded 32 bytes
            return key_env.encode('utf-8')  # Return as bytes
        except Exception:
            raise ValueError("RELAY_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
    
    # For development only - generate and save to file
    # WARNING: This is NOT secure for production!
    key_file = os.getenv("RELAY_ENCRYPTION_KEY_FILE", "data/encryption.key")
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        # Generate a new key
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        # In a real application, you would want to log this warning
        # but we avoid importing logger to prevent circular dependencies
    
    return key

def get_cipher() -> Fernet:
    """Get Fernet cipher instance."""
    key = get_encryption_key()
    return Fernet(key)

def encrypt_data(data: str) -> str:
    """
    Encrypt string data.
    Returns base64-encoded encrypted data.
    """
    if not data:
        return data
    
    cipher = get_cipher()
    encrypted_bytes = cipher.encrypt(data.encode('utf-8'))
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

def decrypt_data(encrypted_data: str) -> str:
    """
    Decrypt base64-encoded encrypted data.
    Returns original string.
    """
    if not encrypted_data:
        return encrypted_data
    
    try:
        cipher = get_cipher()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        # If decryption fails, return as-is (might be unencrypted data from before)
        # In production, you might want to handle this differently
        return encrypted_data