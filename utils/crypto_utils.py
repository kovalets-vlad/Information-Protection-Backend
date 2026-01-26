from fastapi import UploadFile
from utils.hashfun_utils import MD5
from utils.rc5_custom import RC5_custom as RC5
from db.models import RandomState
from utils.lcg_utils import lcg 
from core.core_varibles import RC5_ROUNDS, RC5_WORD_SIZE, STREAM_CHUNK_SIZE

BLOCK_SIZE = int(2 * ( RC5_WORD_SIZE/8 ))    
IV_SIZE = BLOCK_SIZE 

def pad(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(padded_data: bytes, block_size: int) -> bytes:
    if not padded_data:
        raise ValueError("Порожні дані, неможливо зняти доповнення")
        
    padding_len = padded_data[-1]
    
    if padding_len > block_size or padding_len == 0:
        raise ValueError("Неправильне значення доповнення (padding)")
    if padded_data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Неправильне доповнення (padding)")
        
    return padded_data[:-padding_len]

def get_key_from_password(password: str) -> bytes:
    md = MD5()
    md.update(password.encode('utf-8')) 
    key = md.digest()  
    return key


def get_iv_from_lcg(session) -> bytes:

    state = session.get(RandomState, 1)
    if not state:
        raise Exception("LCG RandomState (ID=1) не ініціалізовано в базі даних.")

    seed = lcg(state.seed)
    
    iv_bytes = (seed & 0xFFFFFFFF).to_bytes(4, 'little')

    state.seed = seed
    session.add(state)
    session.commit()
    
    return iv_bytes

def encrypt_text(password: str, plaintext: str, iv: bytes) -> bytes:
    key = get_key_from_password(password)
    cipher = RC5.new(key, RC5.MODE_CBC, IV=iv, 
                     word_size=RC5_WORD_SIZE, rounds=RC5_ROUNDS)
    
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, BLOCK_SIZE) 
    ciphertext = cipher.encrypt(padded_data)

    return iv + ciphertext

def decrypt_text(password: str, encrypted_data: bytes) -> str:
    try:
        iv = encrypted_data[:IV_SIZE] 
        ciphertext = encrypted_data[IV_SIZE:]

        key = get_key_from_password(password)
        cipher = RC5.new(key, RC5.MODE_CBC, IV=iv,
                         word_size=RC5_WORD_SIZE, rounds=RC5_ROUNDS)
        
        padded_data = cipher.decrypt(ciphertext)
        
        plaintext_bytes = unpad(padded_data, BLOCK_SIZE) 

        return plaintext_bytes.decode('utf-8')
        
    except UnicodeDecodeError:
        raise ValueError("Розшифровані дані не є текстом. Можливо, це файл іншого формату або неправильний пароль.")
    except (ValueError, KeyError) as e:
        print(f"Decryption error: {e}")
        raise ValueError("Неправильний пароль або пошкоджені дані")
    
async def decrypt_test(password: str, file: UploadFile):
    header = await file.read(IV_SIZE + BLOCK_SIZE)
    if len(header) < IV_SIZE + BLOCK_SIZE:
        raise ValueError("Файл надто короткий або пошкоджений")

    iv = header[:IV_SIZE]
    first_block = header[IV_SIZE:]

    key = get_key_from_password(password)
    cipher = RC5.new(
        key, 
        RC5.MODE_CBC,
        IV=iv,
        word_size=RC5_WORD_SIZE,
        rounds=RC5_ROUNDS
    )

    decrypted_block = cipher.decrypt(first_block)

    try:
        decrypted_block.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Wrong password")

    await file.seek(0)


async def encrypt_file_stream(password: str, input_file: UploadFile, iv: bytes):
    key = get_key_from_password(password)
    cipher = RC5.new(key, RC5.MODE_CBC, IV=iv,
                     word_size=RC5_WORD_SIZE, rounds=RC5_ROUNDS)
    yield iv 

    buffer = b""
    while True:
        chunk = await input_file.read(STREAM_CHUNK_SIZE)
        
        if not chunk:
            padded_chunk = pad(buffer, BLOCK_SIZE)
            yield cipher.encrypt(padded_chunk) 
            break
            
        buffer += chunk
        
        cutoff = (len(buffer) // BLOCK_SIZE) * BLOCK_SIZE
        if cutoff > 0:
            to_encrypt = buffer[:cutoff]
            buffer = buffer[cutoff:]

            yield cipher.encrypt(to_encrypt) 


async def decrypt_file_stream(password: str, input_file: UploadFile):
    try:
        key = get_key_from_password(password)
        
        iv = await input_file.read(IV_SIZE)
        if len(iv) < IV_SIZE:
            raise ValueError("Пошкоджений файл: заголовок занадто короткий.")

        cipher = RC5.new(key, RC5.MODE_CBC, IV=iv,
                         word_size=RC5_WORD_SIZE, rounds=RC5_ROUNDS)

        last_decrypted_chunk = b""
        buffer = b""

        while True:
            ciphertext_chunk = await input_file.read(STREAM_CHUNK_SIZE)

            if not ciphertext_chunk:
                if len(buffer) % BLOCK_SIZE != 0:
                    raise ValueError("Пошкоджені дані: неповний останній блок.")
                
                remaining_part = cipher.decrypt(buffer)
                
                total_last_data = last_decrypted_chunk + remaining_part
                
                if not total_last_data:
                     raise ValueError("Пошкоджений файл: немає даних після IV")

                unpadded_data = unpad(total_last_data, BLOCK_SIZE)
                
                yield unpadded_data
                break

            buffer += ciphertext_chunk
            
            cutoff = (len(buffer) // BLOCK_SIZE) * BLOCK_SIZE
            if cutoff == 0:
                continue 
                
            to_decrypt = buffer[:cutoff]
            buffer = buffer[cutoff:]

            decrypted_chunk = cipher.decrypt(to_decrypt)
            
            if last_decrypted_chunk:
                yield last_decrypted_chunk
            
            last_decrypted_chunk = decrypted_chunk

    except (ValueError, KeyError) as e:
        print(f"Decryption error in stream: {e}")
        raise ValueError("Неправильний пароль або пошкоджені дані")