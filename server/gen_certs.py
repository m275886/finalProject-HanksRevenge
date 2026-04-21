#!/usr/bin/env python3
"""
gen_certs.py - Generate a self-signed TLS certificate for the C2 server.

Run once before starting the server:
    python server/gen_certs.py

Requires the 'cryptography' package:
    pip install cryptography

Outputs:
    server/server.key  - RSA private key (PEM, unencrypted)
    server/server.crt  - Self-signed X.509 certificate (PEM)

The generated certificate is valid for 365 days and includes SANs for
'localhost', 'c2.lab', and 127.0.0.1 so that TLS hostname verification
passes when the server and implant run on the same machine.
"""

import datetime
import ipaddress
import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).parent
KEY_FILE   = SCRIPT_DIR / "server.key"
CERT_FILE  = SCRIPT_DIR / "server.crt"


def main() -> int:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("[!] Missing dependency.  Install with:  pip install cryptography")
        return 1

    if KEY_FILE.exists() and CERT_FILE.exists():
        print(f"[*] Certificate already present: {CERT_FILE}")
        print("[*] Delete server.key and server.crt to regenerate.")
        return 0

    print("[*] Generating 2048-bit RSA private key ...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,          "c2.lab"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,    "Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "C2"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("c2.lab"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"[+] Private key  -> {KEY_FILE}")

    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate  -> {CERT_FILE}")
    print("[*] Done.  Start the server with:  python server/server.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
