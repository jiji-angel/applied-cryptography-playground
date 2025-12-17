"""
TLS Certificate Validation Pitfalls

This example demonstrates common mistakes developers make when working
with TLS and PKI, and contrasts them with proper certificate validation.

Focus:
- Why disabling certificate verification is dangerous
- Why blindly trusting certificates breaks PKI
- How proper validation should be done
"""

import ssl
import socket


HOST = "example.com"
PORT = 443


def insecure_no_validation():
    """
    Completely disables certificate verification.
    Vulnerable to MITM attacks.
    """
    print("\n[Insecure] No certificate validation")

    context = ssl._create_unverified_context()

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            cert = ssock.getpeercert()
            print("Connected without validation")
            print("Peer certificate:", cert)


def insecure_trust_any_cert():
    """
    Loads default CAs but does not verify hostname.
    Vulnerable to hostname spoofing.
    """
    print("\n[Insecure] Certificate trusted without hostname check")

    context = ssl.create_default_context()
    context.check_hostname = False

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            cert = ssock.getpeercert()
            print("Connected with incomplete validation")
            print("Peer certificate subject:", cert.get("subject"))


def secure_proper_validation():
    """
    Proper PKI validation:
    - CA verification
    - Hostname verification
    """
    print("\n[Secure] Proper certificate validation")

    context = ssl.create_default_context()

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            cert = ssock.getpeercert()
            print("Securely connected")
            print("Peer certificate subject:", cert.get("subject"))


def main():
    insecure_no_validation()
    insecure_trust_any_cert()
    secure_proper_validation()


if __name__ == "__main__":
    main()
