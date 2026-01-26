import pytest
from zipfile import ZipFile
from io import BytesIO

@pytest.fixture
def dsa_keys(client):
    prefix = "test_dsa"
    resp = client.post("/dsa/keys/generate", json={"filename_prefix": prefix})
    
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    
    with ZipFile(BytesIO(resp.content)) as z:
        return {
            "private": z.read(f"{prefix}_private.pem"),
            "public": z.read(f"{prefix}_public.pem"),
        }

@pytest.fixture
def sample_file():
    content = b"Important document content..." * 20
    filename = "doc.pdf"
    return filename, content


def sign_text(client, text, private_key):
    return client.post(
        "/dsa/sign/text",
        data={"text": text},
        files={
            "private_key_file": ("priv.pem", private_key, "application/x-pem-file")
        }
    )

def verify_text(client, text, signature_hex, public_key):
    return client.post(
        "/dsa/verify/text",
        data={
            "text": text,
            "signature_hex": signature_hex
        },
        files={
            "public_key_file": ("pub.pem", public_key, "application/x-pem-file")
        }
    )

def sign_file(client, filename, content, private_key):
    return client.post(
        "/dsa/sign/file",
        files={
            "file": (filename, content, "application/octet-stream"),
            "private_key_file": ("priv.pem", private_key, "application/x-pem-file")
        }
    )

def verify_file(client, filename, content, signature_hex, public_key):
    return client.post(
        "/dsa/verify/file",
        data={"signature_hex": signature_hex},
        files={
            "file": (filename, content, "application/octet-stream"),
            "public_key_file": ("pub.pem", public_key, "application/x-pem-file")
        }
    )

def test_dsa_generate_keys(dsa_keys):
    public_key = dsa_keys["public"]
    private_key = dsa_keys["private"]
    
    assert len(public_key) > 0
    assert len(private_key) > 0
    assert b"BEGIN PUBLIC KEY" in public_key
    assert b"BEGIN PRIVATE KEY" in private_key

def test_dsa_text_full_cycle(client, dsa_keys):
    text = "Hello DSA World"
    private_key = dsa_keys["private"]
    public_key = dsa_keys["public"]

    sign_resp = sign_text(client, text, private_key)
    assert sign_resp.status_code == 200
    
    data = sign_resp.json()
    signature_hex = data["signature_hex"]
    assert signature_hex
    assert data["input_text"] == text

    verify_resp = verify_text(client, text, signature_hex, public_key)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "success"
    assert "ДІЙСНИЙ" in verify_resp.json()["message"]

def test_dsa_text_verify_fail(client, dsa_keys):
    text = "Original Text"
    private_key = dsa_keys["private"]
    public_key = dsa_keys["public"]

    sign_resp = sign_text(client, text, private_key)
    signature_hex = sign_resp.json()["signature_hex"]

    fake_text = "Modified Text"
    verify_resp = verify_text(client, fake_text, signature_hex, public_key)
    
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "failure"
    assert "НЕ ДІЙСНИЙ" in verify_resp.json()["message"]

def test_dsa_file_full_cycle(client, dsa_keys, sample_file):
    filename, content = sample_file
    private_key = dsa_keys["private"]
    public_key = dsa_keys["public"]

    sign_resp = sign_file(client, filename, content, private_key)
    assert sign_resp.status_code == 200
    
    data = sign_resp.json()
    signature_hex = data["signature_hex"]
    assert signature_hex

    verify_resp = verify_file(client, filename, content, signature_hex, public_key)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "success"

def test_dsa_file_verify_fail(client, dsa_keys, sample_file):
    filename, content = sample_file
    private_key = dsa_keys["private"]
    public_key = dsa_keys["public"]

    sign_resp = sign_file(client, filename, content, private_key)
    signature_hex = sign_resp.json()["signature_hex"]

    tampered_content = content + b"!"
    
    verify_resp = verify_file(client, filename, tampered_content, signature_hex, public_key)
    
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "failure"

def test_dsa_wrong_key(client, dsa_keys, sample_file):
    filename, content = sample_file
    private_key = dsa_keys["private"]
    
    prefix_alien = "alien"
    resp = client.post("/dsa/keys/generate", json={"filename_prefix": prefix_alien})
    with ZipFile(BytesIO(resp.content)) as z:
        alien_public_key = z.read(f"{prefix_alien}_public.pem")

    sign_resp = sign_file(client, filename, content, private_key)
    signature_hex = sign_resp.json()["signature_hex"]

    verify_resp = verify_file(client, filename, content, signature_hex, alien_public_key)

    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "failure"

def test_dsa_sign_with_garbage_key(client):
    fake_key = b"not a key"
    resp = client.post(
        "/dsa/sign/text",
        data={"text": "test"},
        files={"private_key_file": ("fake.pem", fake_key, "application/x-pem-file")}
    )
    assert resp.status_code in (400, 500)