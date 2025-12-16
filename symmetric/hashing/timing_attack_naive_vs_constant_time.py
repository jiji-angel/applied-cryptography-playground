"""
Timing Attacks: Naive Comparison vs Constant-Time Comparison

This example demonstrates how naive equality checks can leak information
via timing differences, and how constant-time comparison mitigates the issue.

The scenario is representative of:
- MAC verification
- API token validation
- Password hash comparison
"""

import hmac
import time
import os


#def insecure_compare(a: bytes, b: bytes) -> bool:
#    """
#    Insecure comparison using '=='.
#    May return early and leak timing information.
#    """
#    return a == b

def insecure_compare(a: bytes, b: bytes) -> bool:
    """
    Intentionally insecure byte-by-byte comparison.
    Returns early on mismatch and leaks timing information.
    """
    if len(a) != len(b):
        return False

    for x, y in zip(a, b):
        if x != y:
            return False

    return True


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison using hmac.compare_digest.
    """
    return hmac.compare_digest(a, b)


def measure_time(func, a: bytes, b: bytes, iterations: int = 10_000) -> float:
    """
    Measure average execution time of a comparison function.
    """
    start = time.perf_counter()
    for _ in range(iterations):
        func(a, b)
    end = time.perf_counter()
    return (end - start) / iterations


def demo():
    secret = os.urandom(32)

    # Attacker-controlled guesses
    guess_short_prefix = secret[:4] + os.urandom(28)
    guess_long_prefix = secret[:16] + os.urandom(16)
    guess_wrong = os.urandom(32)

    print("Measuring average comparison time (seconds):\n")

    print("[Insecure comparison]")
    print("Wrong guess:        ", measure_time(insecure_compare, secret, guess_wrong))
    print("4-byte prefix hit:  ", measure_time(insecure_compare, secret, guess_short_prefix))
    print("16-byte prefix hit: ", measure_time(insecure_compare, secret, guess_long_prefix))

    print("\n[Constant-time comparison]")
    print("Wrong guess:        ", measure_time(secure_compare, secret, guess_wrong))
    print("4-byte prefix hit:  ", measure_time(secure_compare, secret, guess_short_prefix))
    print("16-byte prefix hit: ", measure_time(secure_compare, secret, guess_long_prefix))


if __name__ == "__main__":
    demo()
