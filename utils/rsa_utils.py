import os
from typing import AsyncGenerator, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# sym_padding видалено, бо GCM не потребує padding
from fastapi import UploadFile, HTTPException

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32 
CHUNK_SIZE = 64 * 1024
# Константи для GCM
GCM_IV_SIZE = 12 
GCM_TAG_SIZE = 16

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
    except Exception:
        raise HTTPException(status_code=400, detail="Некоректний файл публічного ключа.")

    # Генеруємо сесійний ключ та IV (12 байт для GCM)
    session_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(GCM_IV_SIZE)

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

    # 1. Віддаємо зашифрований ключ та IV
    yield encrypted_session_key
    yield iv

    # 2. Ініціалізуємо AES-GCM
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        # GCM — це потоковий режим, просто шифруємо шматки
        yield encryptor.update(chunk)

    # 3. Фіналізуємо і обов'язково віддаємо TAG (підпис) в кінці
    yield encryptor.finalize()
    yield encryptor.tag

async def init_decrypt_session(file: UploadFile, private_key_pem: bytes) -> Tuple[object, int]:
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except ValueError:
        raise HTTPException(status_code=400, detail="Некоректний файл приватного ключа.")

    # 1. Читаємо зашифрований сесійний ключ RSA
    enc_session_key_len = RSA_KEY_SIZE // 8
    encrypted_session_key = await file.read(enc_session_key_len)
    
    if len(encrypted_session_key) != enc_session_key_len:
        raise HTTPException(status_code=400, detail="Файл пошкоджений або не є RSA-контейнером.")

    # 2. Розшифровуємо AES ключ
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

    # 3. Читаємо IV
    iv = await file.read(GCM_IV_SIZE)

    # 4. Витягуємо TAG з кінця файлу
    # Використовуємо file.file для синхронного доступу до курсора (це вирішує помилку 'UploadFile has no attribute tell')
    current_pos = file.file.tell()
    
    # Стрибаємо в кінець файлу
    file.file.seek(0, 2) 
    file_size = file.file.tell()
    
    if file_size < GCM_TAG_SIZE + enc_session_key_len + GCM_IV_SIZE:
         raise HTTPException(status_code=400, detail="Файл надто малий.")

    # Відступаємо 16 байт від кінця, щоб прочитати тег
    file.file.seek(-GCM_TAG_SIZE, 2) 
    tag = await file.read(GCM_TAG_SIZE)
    
    # Повертаємося назад до даних (відразу після IV)
    file.file.seek(current_pos)
    
    # Вираховуємо довжину саме зашифрованих даних (без тега в кінці)
    ciphertext_len = file_size - current_pos - GCM_TAG_SIZE

    # Ініціалізуємо дешифратор з отриманим тегом
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    # Повертаємо об'єкт дешифратора і довжину даних, яку треба прочитати
    return decryptor, ciphertext_len

async def stream_decrypt_data(file: UploadFile, decryptor, ciphertext_len: int) -> AsyncGenerator[bytes, None]:
    bytes_read = 0
    
    while bytes_read < ciphertext_len:
        # Читаємо шматок, але не більше, ніж залишилось даних (щоб не прочитати тег як дані)
        read_size = min(CHUNK_SIZE, ciphertext_len - bytes_read)
        chunk = await file.read(read_size)
        
        if not chunk:
            break
            
        try:
            yield decryptor.update(chunk)
            bytes_read += len(chunk)
        except Exception:
             raise HTTPException(status_code=400, detail="Помилка потокового дешифрування.")

    # Перевірка цілісності даних (GCM перевіряє тег тут)
    try:
        decryptor.finalize()
    except Exception:
        raise HTTPException(status_code=400, detail="Помилка цілісності: файл пошкоджено або підроблено (Tag mismatch).")