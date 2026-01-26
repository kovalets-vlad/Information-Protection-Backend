import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)
from cryptography.exceptions import InvalidSignature

class DSSManager:
    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)

    def generate_keys(self, filename_prefix="dss_key"):
        """
        Генерує пару ключів, зберігає їх тимчасово (або постійно) на сервері 
        і повертає шляхи.
        """
        private_key = dsa.generate_private_key(key_size=2048)
        public_key = private_key.public_key()

        priv_path = os.path.join(self.key_dir, f"{filename_prefix}_private.pem")
        pub_path = os.path.join(self.key_dir, f"{filename_prefix}_public.pem")

        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        with open(pub_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))

        return priv_path, pub_path

    # --- НОВІ МЕТОДИ ДЛЯ РОБОТИ З БАЙТАМИ ---

    def sign_data_with_key_bytes(self, data: bytes, private_key_bytes: bytes) -> str:
        """Підписує дані, використовуючи байти приватного ключа."""
        private_key = load_pem_private_key(private_key_bytes, password=None)
        
        signature = private_key.sign(
            data,
            hashes.SHA256()
        )
        return signature.hex()

    def verify_signature_with_key_bytes(self, data: bytes, hex_signature: str, public_key_bytes: bytes) -> bool:
        """Перевіряє підпис, використовуючи байти публічного ключа."""
        public_key = load_pem_public_key(public_key_bytes)
        
        try:
            signature_bytes = bytes.fromhex(hex_signature)
            public_key.verify(
                signature_bytes,
                data,
                hashes.SHA256()
            )
            return True
        except (InvalidSignature, ValueError):
            return False