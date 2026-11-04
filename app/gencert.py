"""Generate a self-signed TLS certificate covering every SAN in $CERT_SANS."""
import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = Path(os.environ.get("CERT_DIR", "/certs"))
sans_raw = [s.strip() for s in os.environ.get("CERT_SANS", "localhost,127.0.0.1").split(",") if s.strip()]
sans = []
for s in sans_raw:
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(s)))
    except ValueError:
        sans.append(x509.DNSName(s))

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tresorry"),
                  x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tresorry (self-signed)")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name).issuer_name(name).public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=30))  # tolerate skewed VM clocks
    .not_valid_after(now + datetime.timedelta(days=825))
    .add_extension(x509.SubjectAlternativeName(sans), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                 data_encipherment=False, key_agreement=True, key_cert_sign=False,
                                 crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(key, hashes.SHA256())
)
out.mkdir(parents=True, exist_ok=True)
keyfile = out / "key.pem"
keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
os.chmod(keyfile, 0o600)
(out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
fp = cert.fingerprint(hashes.SHA256()).hex(":").upper()
print(f"[tresorry] new self-signed cert for {', '.join(sans_raw)}")
print(f"[tresorry] SHA-256 fingerprint {fp}")
