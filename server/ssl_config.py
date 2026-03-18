"""
UPDATED: SSL/TLS configuration for Secure Remote Command Execution Server.
"""

import ssl
import os


# UPDATED: Centralized SSL context creation
def create_server_ssl_context():
    """
    Create and configure SSL context for the server.
    UPDATED: Load cert and key; use PROTOCOL_TLS_SERVER.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # UPDATED: Use absolute paths for cert and key
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.path.join(base_dir, "cert.pem")
    key_file = os.path.join(base_dir, "key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        raise FileNotFoundError(
            f"Certificate files not found. Run generate_cert.py first.\n"
            f"Expected: {cert_file}, {key_file}"
        )

    context.load_cert_chain(cert_file, key_file)
    # UPDATED: Disable legacy protocols (optional security hardening)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
