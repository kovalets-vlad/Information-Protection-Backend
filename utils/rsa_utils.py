import os
from typing import AsyncGenerator
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from fastapi import UploadFile, HTTPException

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32 
AES_BLOCK_SIZE = 128 
CHUNK_SIZE = 64 * 1024

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

async def encrypt_file_hybrid_stream(file: UploadFile, public_key_pem: bytes) -> AsyncGenerator[bytes, None]:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except ValueError:
        raise HTTPException(status_code=400, detail="Некоректний файл публічного ключа. Переконайтеся, що ви вибрали файл public.pem.")
    except Exception:
        raise HTTPException(status_code=400, detail="Помилка читання ключа.")

    session_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(16)

    try:
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"Помилка шифрування ключа: {str(e)}")

    yield encrypted_session_key
    yield iv

    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(AES_BLOCK_SIZE).padder()

    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        
        padded_chunk = padder.update(chunk)
        encrypted_chunk = encryptor.update(padded_chunk)
        yield encrypted_chunk

    final_padded = padder.finalize()
    final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
    yield final_encrypted

async def init_decrypt_session(file: UploadFile, private_key_pem: bytes):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except ValueError:
        raise HTTPException(status_code=400, detail="Некоректний файл приватного ключа (формат PEM).")

    enc_session_key_len = RSA_KEY_SIZE // 8
    encrypted_session_key = await file.read(enc_session_key_len)
    
    if len(encrypted_session_key) != enc_session_key_len:
        raise HTTPException(status_code=400, detail="Файл пошкоджений або не є RSA-контейнером.")

    iv = await file.read(16)

    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Неправильний приватний ключ! Неможливо розшифрувати файл.")

    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(AES_BLOCK_SIZE).unpadder()

    return decryptor, unpadder, iv


async def stream_decrypt_data(file: UploadFile, decryptor, unpadder) -> AsyncGenerator[bytes, None]:
    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        
        decrypted_chunk = decryptor.update(chunk)
        try:
            unpadded_chunk = unpadder.update(decrypted_chunk)
            yield unpadded_chunk
        except ValueError:
            pass

    try:
        final_decrypted = decryptor.finalize()
        final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
        yield final_unpadded
    except ValueError:
        raise Exception("Помилка цілісності даних (AES padding error).")