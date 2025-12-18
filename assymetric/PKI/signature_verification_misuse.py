"""
Digital Signature Verification Misuse

This example demonstrates common mistakes when verifying digital
signatures and contrasts them with correct usage.

Focus:
- Verifying signatures without binding context
- Verifying incorrect or incomplete data
- Proper signature verification
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def insecure_verify_without_context(public_key, signature, message):
    """
    Verifies a signature without binding it to application context.
    This allows replay in different contexts.
    """
    try:
        public_key.verify(signature, message)
        print("[Insecure] Signature verified (no context binding)")
    except InvalidSignature:
        print("[Insecure] Signature verification failed")


def insecure_verify_wrong_data(public_key, signature, original_message):
    """
    Developer mistake: verifies signature over the wrong data.
    """
    wrong_message = original_message.lower()  # subtle transformation
    try:
        public_key.verify(signature, wrong_message)
        print("[Insecure] Signature verified on wrong data")
    except InvalidSignature:
        print("[Insecure] Signature verification failed (wrong data)")


def secure_verify_with_context(public_key, signature, message, context):
    """
    Proper verification: signature covers both message and context.
    """
    signed_data = context + message
    try:
        public_key.verify(signature, signed_data)
        print("[Secure] Signature verified with context binding")
    except InvalidSignature:
        print("[Secure] Signature verification failed")


def main():
    private_key, public_key = generate_keypair()

    message = b"transfer=100"
    context = b"bank-api:v1"

    # Sign message without context (bad practice)
    signature_no_context = private_key.sign(message)

    # Sign message with context (good practice)
    signature_with_context = private_key.sign(context + message)

    print("\n--- Signature Verification Misuse Demo ---\n")

    insecure_verify_without_context(public_key, signature_no_context, message)

    insecure_verify_wrong_data(public_key, signature_no_context, message)

    secure_verify_with_context(public_key, signature_with_context, message, context)


if __name__ == "__main__":
    main()
