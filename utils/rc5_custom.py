import struct
import numpy as np
from numba import jit, uint16
from core.core_varibles import RC5_ROUNDS, RC5_WORD_SIZE, KEY_SIZE

# Константи для 16/20/16 RC5 реалізації з JIT компіляцією

W_JIT = 16      
R_JIT = 20
T_JIT = 42
MODULO_JIT = 65536 
P_JIT = 0xB7E1
Q_JIT = 0x9E37

@jit(nopython=True, cache=True)
def _rol_jit(val, r):
    r %= W_JIT
    return uint16(((val << r) & (MODULO_JIT - 1)) | (val >> (W_JIT - r)))

@jit(nopython=True, cache=True)
def _ror_jit(val, r):
    r %= W_JIT
    return uint16((val >> r) | ((val << (W_JIT - r)) & (MODULO_JIT - 1)))

@jit(nopython=True, cache=True)
def _key_expansion_jit(key_np_array):
    L = key_np_array.astype(np.int64)
    S = np.zeros(T_JIT, dtype=np.int64)
    
    S[0] = P_JIT
    for i in range(1, T_JIT):
        S[i] = (S[i-1] + Q_JIT) % MODULO_JIT

    i = j = 0
    A = B = 0
    c = 8 
    
    for k in range(3 * T_JIT):
        A = S[i] = _rol_jit((S[i] + A + B), 3) 
        B = L[j] = _rol_jit((L[j] + A + B), (A + B))
        
        i = (i + 1) % T_JIT
        j = (j + 1) % c
        
    return S

@jit(nopython=True, cache=True)
def _encrypt_block_jit(A, B, S):
    A = (A + S[0]) % MODULO_JIT
    B = (B + S[1]) % MODULO_JIT

    for i in range(1, R_JIT + 1): 
        A = (_rol_jit((A ^ B), B) + S[2 * i]) % MODULO_JIT
        B = (_rol_jit((B ^ A), A) + S[2 * i + 1]) % MODULO_JIT
    
    return A, B

@jit(nopython=True, cache=True)
def _decrypt_block_jit(A, B, S):
    for i in range(R_JIT, 0, -1): 
        B = _ror_jit((B - S[2 * i + 1] + MODULO_JIT) % MODULO_JIT, A) ^ A
        A = _ror_jit((A - S[2 * i] + MODULO_JIT) % MODULO_JIT, B) ^ B

    B = (B - S[1] + MODULO_JIT) % MODULO_JIT
    A = (A - S[0] + MODULO_JIT) % MODULO_JIT

    return A, B

class RC5_custom:
    def __init__(self, key: bytes, mode: int, IV: bytes, word_size: int, rounds: int):
        if word_size != RC5_WORD_SIZE:
            raise ValueError("Ця реалізація підтримує лише word_size=16")
        if rounds != RC5_ROUNDS:
            raise ValueError("Ця реалізація підтримує лише 20 раундів")
        if len(key) != KEY_SIZE:
            raise ValueError("Ця реалізація підтримує лише 16-байтний ключ")
        if mode != self.MODE_CBC:
            raise ValueError("Підтримується лише режим MODE_CBC")
        
        # Встановлення констант для 16/20/16
        self.w = RC5_WORD_SIZE
        self.r = RC5_ROUNDS
        self.b = KEY_SIZE
        self.t = 2 * (self.r + 1) 
        
        self.modulo = 2**self.w 
        
        self.mode = mode
        self.block_size = 2 * (self.w // 8) 
        
        if len(IV) != self.block_size:
             raise ValueError(f"IV має бути {self.block_size} байт, а не {len(IV)}")
        self.iv = bytearray(IV) 

        L_np = np.frombuffer(key, dtype=np.uint16)
        self.S = _key_expansion_jit(L_np)

    MODE_CBC = 2

    @staticmethod
    def new(key, mode, IV, word_size, rounds):
        return RC5_custom(key, mode, IV, word_size, rounds)

    def _encrypt_block(self, data: bytes) -> bytes:
        A, B = struct.unpack('<2H', data) 
        
        A_enc, B_enc = _encrypt_block_jit(A, B, self.S)

        return struct.pack('<2H', A_enc, B_enc) 

    def _decrypt_block(self, data: bytes) -> bytes:

        A, B = struct.unpack('<2H', data)
        
        A_dec, B_dec = _decrypt_block_jit(A, B, self.S)

        return struct.pack('<2H', A_dec, B_dec) 


    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) % self.block_size != 0: 
            raise ValueError("Дані не вирівняні! Повинен бути застосований Pad.")

        ciphertext = bytearray()
        prev_block = self.iv 

        for i in range(0, len(plaintext), self.block_size): 
            block = plaintext[i : i + self.block_size]
            xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
            
            encrypted_block = self._encrypt_block(xor_block) 
            
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block 

        self.iv = prev_block
        return bytes(ciphertext)

    
    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self.block_size != 0: 
            raise ValueError("Дані не вирівняні! Неправильний шифротекст.")

        plaintext = bytearray()
        prev_block = self.iv 

        for i in range(0, len(ciphertext), self.block_size): 
            block = ciphertext[i : i + self.block_size]

            decrypted_block_xor = self._decrypt_block(block) 
            
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block_xor, prev_block))
            
            plaintext.extend(plain_block)
            prev_block = block 

        self.iv = prev_block
        return bytes(plaintext)