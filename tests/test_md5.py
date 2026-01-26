import pytest
from unittest.mock import patch


@pytest.fixture
def sample_string():
    text = "Hello World"
    expected_hash = "b10a8db164e0754105b7a99be72e3fe5"
    return text, expected_hash

@pytest.fixture
def sample_file():
    content = b"File content for MD5 check..." * 100
    filename = "test_file.txt"
    return filename, content


def send_md5_string(client, text):
    return client.post(
        "/md5",
        json={"data": text}
    )

def send_md5_file(client, filename, content):
    return client.post(
        "/md5/file",
        files={"file": (filename, content, "text/plain")}
    )


def test_md5_string_success(client, sample_string):
    text, expected_hash = sample_string
    
    resp = send_md5_string(client, text)
    
    assert resp.status_code == 200
    data = resp.json()
    assert data["hex"] == expected_hash
    assert data["length"] == len(text)

def test_md5_string_empty(client):
    text = ""
    expected_hash = "d41d8cd98f00b204e9800998ecf8427e"
    
    resp = send_md5_string(client, text)
    
    assert resp.status_code == 200
    assert resp.json()["hex"] == expected_hash

def test_md5_file_success(client, sample_file):
    filename, content = sample_file
    
    resp = send_md5_file(client, filename, content)
    
    assert resp.status_code == 200
    data = resp.json()
    
    assert data["length"] == len(content)
    assert "hex" in data
    assert len(data["hex"]) == 32

def test_md5_string_exception(client):
    with patch("backend.api.md5.MD5") as MockMD5:
        mock_instance = MockMD5.return_value
        mock_instance.update.side_effect = Exception("Internal Hashing Error")
        
        resp = send_md5_string(client, "fail_me")
        
        assert resp.status_code == 500
        assert "Internal Hashing Error" in resp.json()["detail"]

def test_md5_file_exception(client, sample_file):
    filename, content = sample_file
    
    with patch("backend.api.md5.MD5") as MockMD5:
        mock_instance = MockMD5.return_value
        mock_instance.update.side_effect = Exception("File Processing Error")
        
        resp = send_md5_file(client, filename, content)
        
        assert resp.status_code == 400
        assert "File Processing Error" in resp.json()["detail"]