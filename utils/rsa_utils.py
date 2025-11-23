import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from fastapi import UploadFile

# Налаштування
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32  # 256 біт
AES_BLOCK_SIZE = 128 # 16 байт
CHUNK_SIZE = 1024 * 1024 # 1 MB для потоку

def generate_rsa_keys():
    """
    Генерує пару ключів RSA (Private + Public)
    Повертає їх у форматі PEM (байти)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    
    # Серіалізація приватного ключа
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # Для лаби без пароля на ключ
    )

    # Серіалізація публічного ключа
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

async def encrypt_file_hybrid_stream(file: UploadFile, public_key_pem: bytes):
    """
    Гібридне шифрування:
    1. Генеруємо сесійний ключ AES.
    2. Шифруємо файл через AES.
    3. Шифруємо ключ AES через RSA.
    4. Записуємо: [RSA-Enc-AES-Key] + [IV] + [AES-Enc-Data]
    """
    # 1. Завантажуємо публічний ключ RSA
    public_key = serialization.load_pem_public_key(public_key_pem)

    # 2. Генеруємо одноразовий ключ AES та IV
    session_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(16) # 128 біт для AES

    # 3. Шифруємо сесійний ключ AES алгоритмом RSA
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Віддаємо заголовок файлу (Зашифрований ключ + IV)
    yield encrypted_session_key # 256 байт (для RSA 2048)
    yield iv                    # 16 байт

    # 4. Налаштовуємо AES шифрування (CBC mode з PKCS7 padding)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(AES_BLOCK_SIZE).padder()

    # 5. Потокове шифрування даних
    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        
        # Додаємо паддінг та шифруємо
        padded_chunk = padder.update(chunk)
        encrypted_chunk = encryptor.update(padded_chunk)
        yield encrypted_chunk

    # Фіналізуємо паддінг та шифрування
    final_padded = padder.finalize()
    final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
    yield final_encrypted


async def decrypt_file_hybrid_stream(file: UploadFile, private_key_pem: bytes):
    """
    Гібридне дешифрування:
    1. Читаємо заголовок (ключ AES зашифрований RSA + IV).
    2. Дешифруємо ключ AES приватним ключем RSA.
    3. Дешифруємо тіло файлу ключем AES.
    """
    # 1. Завантажуємо приватний ключ RSA
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    # 2. Читаємо зашифрований сесійний ключ
    # Для RSA 2048 довжина шифротексту = 256 байт
    enc_session_key_len = RSA_KEY_SIZE // 8
    encrypted_session_key = await file.read(enc_session_key_len)
    
    if len(encrypted_session_key) != enc_session_key_len:
        raise ValueError("Некоректний файл або ключ")

    # 3. Читаємо IV
    iv = await file.read(16)

    # 4. Дешифруємо сесійний ключ AES
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 5. Налаштовуємо AES дешифрування
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(AES_BLOCK_SIZE).unpadder()

    # 6. Потокове дешифрування даних
    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        
        decrypted_chunk = decryptor.update(chunk)
        # Знімаємо паддінг на льоту (обережно, unpadder буферизує дані)
        try:
            unpadded_chunk = unpadder.update(decrypted_chunk)
            yield unpadded_chunk
        except Exception:
            # Це нормально, unpadder чекає на фінальний блок
            pass

    # Фіналізація
    final_decrypted = decryptor.finalize()
    final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
    yield final_unpadded