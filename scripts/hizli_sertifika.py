# Dosya adi: hizli_sertifika.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os

def main():
    # 1. 'certs' klasoru yoksa olustur
    if not os.path.exists("certs"):
        os.makedirs("certs")
        print(" -> 'certs' klasoru olusturuldu.")

    print(" -> Anahtar ve sertifika uretiliyor...")

    # 2. Private Key (Gizli Anahtar) oluştur
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 3. Sertifika Bilgilerini Hazırla (Self-Signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Odev"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # 4. Dosyaları Kaydet
    with open("certs/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    with open("certs/cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("BASARILI! 'certs/cert.pem' ve 'certs/key.pem' dosyalari hazir.")

if __name__ == "__main__":
    try:
        main()
    except ImportError:
        print("HATA: 'cryptography' kutuphanesi eksik. Lutfen 'pip install cryptography' yapin.")