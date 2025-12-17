"""
Password Hashing: SHA-256 vs bcrypt vs Argon2

This example demonstrates why general-purpose hash functions like SHA-256
are unsuitable for password storage, and how password hashing schemes
(bcrypt, Argon2) mitigate offline brute-force attacks.

Focus:
- Cost asymmetry
- Salting
- Memory hardness (Argon2)
"""

import hashlib
import os
import time

import bcrypt
from argon2 import PasswordHasher


def sha256_hash(password: str) -> bytes:
    """
    Insecure password hashing using SHA-256.
    Fast and vulnerable to brute-force attacks.
    """
    return hashlib.sha256(password.encode()).digest()


def bcrypt_hash(password: str) -> bytes:
    """
    Secure password hashing using bcrypt.
    Includes salt and configurable cost.
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)


def argon2_hash(password: str) -> str:
    """
    Secure password hashing using Argon2.
    Memory-hard and GPU-resistant.
    """
    ph = PasswordHasher(
        time_cost=2,
        memory_cost=102400,  # 100 MB
        parallelism=8
    )
    return ph.hash(password)


def measure(func, password: str, label: str):
    start = time.perf_counter()
    result = func(password)
    elapsed = time.perf_counter() - start
    print(f"{label:<20}: {elapsed:.6f} seconds")
    return result


def demo():
    password = "correcthorsebatterystaple"

    print("Measuring password hashing time:\n")

    sha = measure(sha256_hash, password, "SHA-256")
    bc = measure(bcrypt_hash, password, "bcrypt")
    ar = measure(argon2_hash, password, "Argon2")

    print("\nHash lengths:")
    print("SHA-256 :", len(sha), "bytes")
    print("bcrypt  :", len(bc), "bytes")
    print("Argon2  :", len(ar), "chars")


if __name__ == "__main__":
    demo()
