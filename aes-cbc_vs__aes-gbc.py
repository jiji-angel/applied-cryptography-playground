"""
AES-CBC vs AES-GCM: Security and Correctness Comparison

This example demonstrates why AES-CBC encryption without authentication
is dangerous, and how AES-GCM provides authenticated encryption (AEAD)
that detects tampering.

⚠️ Educational purpose only. Do NOT copy insecure patterns into production.
"""

import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------
# Insecure AES-CBC example (encryption without authentication)
# ---------------------------------------------------------------------

def encrypt_cbc_insecure(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts data using AES-CBC WITHOUT authentication.
    This is intentionally insecure and shown for demonstration only.
    """
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv, ciphertext


def decrypt_cbc_insecure(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts AES-CBC ciphertext.
    Note: This function provides NO integrity or authenticity guarantees.
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


# ---------------------------------------------------------------------
# Secure AES-GCM example (authenticated encryption)
# ---------------------------------------------------------------------

def encrypt_gcm_secure(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts data using AES-GCM (AEAD).
    Provides confidentiality + integrity + authenticity.
    """
    nonce = os.urandom(12)

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return nonce, ciphertext, encryptor.tag


def decrypt_gcm_secure(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    """
    Decrypts AES-GCM ciphertext.
    Tampering will be detected and raise an exception.
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


# ---------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------

def demo():
    key = os.urandom(32)  # AES-256
    message = b"Transfer amount=1000 INR"

    print("Original message:", message)
    
    # --- AES-CBC ---
    iv, cbc_ciphertext = encrypt_cbc_insecure(key, message)
    
    # Attacker flips a bit in ciphertext
    tampered_cbc = bytearray(cbc_ciphertext)
    tampered_cbc[0] ^= 1

    
    recovered = decrypt_cbc_insecure(key, iv, bytes(tampered_cbc))
    print("\n[AES-CBC] Decrypted tampered message:")
    print(recovered)

    # --- AES-GCM ---
    nonce, gcm_ciphertext, tag = encrypt_gcm_secure(key, message)

        
    tampered_gcm = bytearray(gcm_ciphertext)
    tampered_gcm[0] ^= 1

    
    print("\n[AES-GCM] Attempting to decrypt tampered message:")
    try:
        decrypt_gcm_secure(key, nonce, bytes(tampered_gcm), tag)
    except Exception as e:
        print("Tampering detected. ", str(e))


if __name__ == "__main__":
    demo()
