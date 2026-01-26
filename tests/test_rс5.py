import pytest

DEFAULT_PASS = "mypassword123"

@pytest.fixture
def sample_text():
    return "Hello world!", DEFAULT_PASS

@pytest.fixture
def sample_file():
    content = b"Test data for RC5 file encryption" * 30
    filename = "test.bin"
    return filename, content

def encrypt_text(client, text, password):
    return client.post(
        "/rc5/text/encrypt",
        json={"text": text, "password": password}
    )

def decrypt_text(client, encrypted_b64, password):
    return client.post(
        "/rc5/text/decrypt",
        json={"encrypted_data_b64": encrypted_b64, "password": password}
    )

def encrypt_file(client, filename, content, password):
    return client.post(
        "/rc5/file/encrypt",
        files={"file": (filename, content, "application/octet-stream")},
        data={"password": password}
    )

def decrypt_file(client, filename, encrypted_content, password, original_filename=None):
    files = {
        "file": (filename, encrypted_content, "application/octet-stream")
    }
    data = {"password": password}
    if original_filename:
        data["original_filename"] = original_filename

    return client.post(
        "/rc5/file/decrypt",
        files=files,
        data=data
    )

def test_rc5_text_encrypt(client, sample_text):
    text, password = sample_text

    resp = encrypt_text(client, text, password)

    assert resp.status_code == 200
    encrypted = resp.json()["encrypted_data_b64"]
    assert encrypted != ""
    assert encrypted != text

def test_rc5_text_full_cycle(client, sample_text):
    text, password = sample_text

    # Encrypt
    enc_resp = encrypt_text(client, text, password)
    encrypted_b64 = enc_resp.json()["encrypted_data_b64"]

    # Decrypt
    dec_resp = decrypt_text(client, encrypted_b64, password)
    assert dec_resp.status_code == 200
    assert dec_resp.json()["text"] == text

def test_rc5_text_wrong_password(client, sample_text):
    text, password = sample_text

    enc_resp = encrypt_text(client, text, password)
    encrypted_b64 = enc_resp.json()["encrypted_data_b64"]

    # Wrong password
    dec_resp = decrypt_text(client, encrypted_b64, "wrongpass")

    assert dec_resp.status_code == 400

def test_rc5_file_encrypt(client, sample_file):
    filename, content = sample_file

    resp = encrypt_file(client, filename, content, DEFAULT_PASS)

    assert resp.status_code == 200
    assert resp.content != content
    assert len(resp.content) > 0

    cd = resp.headers["content-disposition"]
    assert "encrypted" in cd

def test_rc5_file_decrypt(client, sample_file):
    filename, content = sample_file

    enc_resp = encrypt_file(client, filename, content, DEFAULT_PASS)
    encrypted = enc_resp.content

    dec_resp = decrypt_file(client, filename, encrypted, DEFAULT_PASS)

    assert dec_resp.status_code == 200
    assert dec_resp.content == content

def test_rc5_file_wrong_password(client, sample_file):
    filename, content = sample_file

    enc_resp = encrypt_file(client, filename, content, DEFAULT_PASS)
    encrypted = enc_resp.content

    dec_resp = decrypt_file(client, filename, encrypted, "badpass")

    assert dec_resp.status_code == 401
    assert dec_resp.content != content

def test_rc5_file_encrypt_no_file(client):
    resp = client.post(
        "/rc5/file/encrypt",
        data={"password": DEFAULT_PASS}
    )

    assert resp.status_code == 400

def test_rc5_file_encrypt_no_password(client, sample_file):
    filename, content = sample_file
    resp = client.post(
        "/rc5/file/encrypt",
        files={"file": (filename, content, "application/octet-stream")}
    )
    assert resp.status_code == 400
