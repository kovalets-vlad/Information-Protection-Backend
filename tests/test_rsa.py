from unittest.mock import patch
import pytest
from zipfile import ZipFile
from io import BytesIO

def test_rsa_key_generate(client):
    enc_resp = client.get(
        "rsa/keys/generate"
    )
    assert enc_resp.status_code == 200

def test_rsa_file_encrypt_decrypt(client):
    key_resp = client.get("rsa/keys/generate")
    assert key_resp.status_code == 200
    
    with ZipFile(BytesIO(key_resp.content)) as zip_file:
        private_key = zip_file.read("private.pem")
        public_key = zip_file.read("public.pem")
    
    file_content = b"Image data bytes..." * 50
    filename = "photo.png"

    enc_resp = client.post(
        "rsa/encrypt",
        files={
            "file": (filename, file_content, "image/png"),
            "public_key": ("public.pem", public_key, "application/x-pem-file")
        }
    )

    assert enc_resp.status_code == 200
    encrypted_content = enc_resp.content

    assert "photo.png.enc" in enc_resp.headers["content-disposition"] or \
           "photo_encrypted" in enc_resp.headers["content-disposition"] or \
           "filename*=UTF-8''photo.png.enc" in enc_resp.headers["content-disposition"]

    dec_resp = client.post(
        "rsa/decrypt",
        files={
            "file": ("photo.png.enc", encrypted_content, "application/octet-stream"),
            "private_key": ("private.pem", private_key, "application/x-pem-file") 
        }
    )
    
    assert dec_resp.status_code == 200
    assert dec_resp.content == file_content