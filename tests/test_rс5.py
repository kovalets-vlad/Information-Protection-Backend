from unittest.mock import patch
import pytest

IV_SIZE = 4 

@pytest.fixture
def mock_iv():
    with patch("backend.utils.crypto_utils.get_iv_from_lcg") as mock:
        mock.return_value = b'\x01' * IV_SIZE
        yield mock

def test_rc5_text_encrypt_decrypt(client, mock_iv):
    payload = {
        "text": "Слава Україні!",
        "password": "secret_password"
    }
    
    enc_resp = client.post("/text/encrypt", json=payload)
    assert enc_resp.status_code == 200
    data = enc_resp.json()
    assert "encrypted_data_b64" in data
    cipher_text = data["encrypted_data_b64"]

    dec_payload = {
        "encrypted_data_b64": cipher_text,
        "password": "secret_password"
    }
    dec_resp = client.post("/text/decrypt", json=dec_payload)
    assert dec_resp.status_code == 200
    assert dec_resp.json()["text"] == "Слава Україні!"

def test_rc5_file_encrypt_decrypt(client, mock_iv):
    file_content = b"Image data bytes..." * 50
    password = "secure_file_pass"
    filename = "photo.png"

    enc_resp = client.post(
        "/file/encrypt",
        data={"password": password},
        files={"file": (filename, file_content, "image/png")}
    )
    assert enc_resp.status_code == 200
    encrypted_content = enc_resp.content
    
    assert (
        "photo_encrypted.png" in enc_resp.headers["content-disposition"]
        or "photo_encrypted.png" in enc_resp.headers["content-disposition"].replace("%5F", "_")
    )

    dec_resp = client.post(
        "/file/decrypt",
        data={"password": password},
        files={"file": ("photo_encrypted.png", encrypted_content, "application/octet-stream")}
    )
    assert dec_resp.status_code == 200
    assert dec_resp.content == file_content

def test_rc5_text_to_file_flow(client, mock_iv):
    text = "Long text document content..."
    password = "123"

    enc_resp = client.post(
        "/text-to-file/encrypt",
        json={"text": text, "password": password}
    )
    assert enc_resp.status_code == 200
    file_content = enc_resp.content

    dec_resp = client.post(
        "/file-to-text/decrypt",
        data={"password": password},
        files={"file": ("encrypted_text.txt", file_content)}
    )
    assert dec_resp.status_code == 200
    assert dec_resp.json()["text"] == text

def test_rc5_decrypt_wrong_password(client, mock_iv):
    payload = {"text": "Secret", "password": "passA"}
    enc_resp = client.post("/text/encrypt", json=payload)
    cipher_text = enc_resp.json()["encrypted_data_b64"]

    dec_payload = {
        "encrypted_data_b64": cipher_text,
        "password": "passB_WRONG"
    }
    dec_resp = client.post("/text/decrypt", json=dec_payload)

    assert dec_resp.status_code in [400, 500]