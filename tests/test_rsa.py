import pytest
from zipfile import ZipFile
from io import BytesIO

@pytest.fixture
def rsa_keys(client):
    resp = client.get("rsa/keys/generate")
    with ZipFile(BytesIO(resp.content)) as z:
        return {
            "private": z.read("private.pem"),
            "public": z.read("public.pem"),
        }
    
@pytest.fixture
def sample_file():
    content = b"Image data bytes..." * 50
    filename = "photo.png"
    return filename, content
    
def encrypt_file(client, public_key, filename, content):
    return client.post(
        "rsa/encrypt",
        files={
            "file": (filename, content, "image/png"),
            "public_key": ("public.pem", public_key, "application/x-pem-file")
        }
    )

def decrypt_file(client, private_key, encrypted_content):
    return client.post(
        "rsa/decrypt",
        files={
            "file": ("photo.png.enc", encrypted_content, "application/octet-stream"),
            "private_key": ("private.pem", private_key, "application/x-pem-file") 
        }
    )

def test_rsa_generate_keys(rsa_keys):
    public_key = rsa_keys["public"]
    private_key = rsa_keys["private"]
    assert len(public_key) > 0
    assert len(private_key) > 0

def test_rsa_encrypt(client, rsa_keys, sample_file):
    filename, content = sample_file
    public_key = rsa_keys["public"]

    resp = encrypt_file(client, public_key, filename, content)

    assert resp.status_code == 200
    assert resp.content != content
    assert len(resp.content) > len(content)

    assert "photo.png.enc" in resp.headers["content-disposition"] or \
           "photo_encrypted" in resp.headers["content-disposition"] or \
           "filename*=UTF-8''photo.png.enc" in resp.headers["content-disposition"]
    
def test_rsa_decrypt(client, rsa_keys, sample_file):
    filename, content = sample_file
    public_key = rsa_keys["public"]
    private_key = rsa_keys["private"]

    encr_file = encrypt_file(client, public_key, filename, content)

    encrypted_content = encr_file.content

    resp = decrypt_file(client, private_key, encrypted_content)

    assert resp.status_code == 200
    assert resp.content == content


def test_rsa_full_cycle(client, rsa_keys, sample_file):
    filename, content = sample_file

    public_key = rsa_keys["public"]
    private_key = rsa_keys["private"]

    enc_resp = encrypt_file(client, public_key, filename, content)
    assert enc_resp.status_code == 200
    encrypted_content = enc_resp.content

    assert encrypted_content != content
    assert len(encrypted_content) > len(content)

    dec_resp = decrypt_file(client, private_key, encrypted_content)
    assert dec_resp.status_code == 200

    assert dec_resp.content == content

def test_rsa_decrypt_wrong_key(client, rsa_keys, sample_file):
    filename, content = sample_file

    public_key = rsa_keys["public"]

    resp = client.get("rsa/keys/generate")
    with ZipFile(BytesIO(resp.content)) as z:
        wrong_private_key = z.read("private.pem")

    enc_resp = encrypt_file(client, public_key, filename, content)
    encrypted_content = enc_resp.content

    dec_resp = decrypt_file(client, wrong_private_key, encrypted_content)

    assert dec_resp.status_code in (400, 422, 500)

def test_rsa_encrypt_broken_public_key(client, sample_file):
    filename, content = sample_file

    broken_key = b"-----BEGIN PUBLIC KEY-----123456-----END PUBLIC KEY-----"

    resp = encrypt_file(client, broken_key, filename, content)

    assert resp.status_code in (400, 422)
