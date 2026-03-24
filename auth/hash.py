"""
UPDATED: Password hashing module - PBKDF2 with salt.
NOTE: In the corrected architecture, password hashing is performed SERVER-SIDE.
This module is retained for compatibility and can be used for local testing
or migration. The server maintains its own PBKDF2 implementation.
"""

import hashlib
import os
import secrets


# UPDATED: Replaced plain SHA-256 with PBKDF2-HMAC-SHA256
def hash_password(password: str, salt: bytes = None):
    """
    Hash password using PBKDF2 with random salt.
    Returns (salt_bytes, hash_hex) for storage.
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    # UPDATED: 100,000 iterations for key stretching
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000,
    )
    return salt, key.hex()


# UPDATED: Verify password against stored salt and hash
def verify_password(input_password: str, stored_salt_hex: str, stored_hash: str) -> bool:
    """Verify input password against stored salt and hash."""
    salt = bytes.fromhex(stored_salt_hex)
    _, computed_hash = hash_password(input_password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


# Testing
if __name__ == "__main__":
    pwd = input("Enter password: ")
    salt, hashed = hash_password(pwd)
    print("Salt (hex):", salt.hex())
    print("Hashed Password:", hashed)
    check = input("Re-enter password to verify: ")
    if verify_password(check, salt.hex(), hashed):
        print("Password Matched ✓")
    else:
        print("Wrong Password ✗")
