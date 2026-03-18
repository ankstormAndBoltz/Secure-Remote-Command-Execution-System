"""
UPDATED: Certificate generation for TLS server.
Generates self-signed cert.pem and key.pem for development.
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

# UPDATED: Use absolute paths so script works from any directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

with open(os.path.join(BASE_DIR, "key.pem"), "wb") as f:
    f.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureExec"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256())
)

with open(os.path.join(BASE_DIR, "cert.pem"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Certificate generated: cert.pem and key.pem")