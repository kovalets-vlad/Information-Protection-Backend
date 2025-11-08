import struct

class RC5_custom:
    def __init__(self, key: bytes, mode: int, IV: bytes, word_size: int, rounds: int):
        if word_size != 16: # ЗМІНЕНО:
            raise ValueError("Ця реалізація підтримує лише word_size=16")
        if rounds != 20: # ЗМІНЕНО:
            raise ValueError("Ця реалізація підтримує лише 20 раундів")
        if len(key) != 16: # Без змін
            raise ValueError("Ця реалізація підтримує лише 16-байтний ключ")
        if mode != self.MODE_CBC:
            raise ValueError("Підтримується лише режим MODE_CBC")
        
        # --- Встановлення констант (для 16/20/16) ---
        self.w = 16 # ЗМІНЕНО:
        self.r = 20 # ЗМІНЕНО:
        self.b = 16 # Без змін
        self.t = 2 * (self.r + 1) # ЗМІНЕНО: (стало 42)
        
        self.modulo = 2**self.w # ЗМІНЕНО: (стало 2**16)
        
        # 16-бітні "магічні константи" P і Q
        self.P = 0xB7E1 # ЗМІНЕНО:
        self.Q = 0x9E37 # ЗМІНЕНО:

        self.mode = mode
        self.block_size = 2 * (self.w // 8) # ЗМІНЕНО: (стало 4 байти)
        
        # Перевіряємо, чи IV має правильний (новий) розмір
        if len(IV) != self.block_size:
             raise ValueError(f"IV має бути {self.block_size} байт, а не {len(IV)}")
        self.iv = bytearray(IV) 

        self.S = self._key_expansion(key)

    # --- Статичні константи для сумісності API ---
    MODE_CBC = 2

    @staticmethod
    def new(key, mode, IV, word_size, rounds):
        """Фабричний метод для імітації API pycryptodome"""
        return RC5_custom(key, mode, IV, word_size, rounds)

    # --- Допоміжні бітові операції (для 16 біт) ---
    # Ці функції параметризовані self.w, тому вони працюють без змін

    def _rol(self, val, r):
        """Циклічний зсув вліво (Rotate Left) для 16-бітних чисел"""
        r %= self.w
        return ((val << r) & (self.modulo - 1)) | (val >> (self.w - r))

    def _ror(self, val, r):
        """Циклічний зсув вправо (Rotate Right) для 16-бітних чисел"""
        r %= self.w
        return (val >> r) | ((val << (self.w - r)) & (self.modulo - 1))

    # --- Основні кроки алгоритму ---

    def _key_expansion(self, key: bytes) -> list:
        """
        Процедура розгортання 16-байтного ключа у таблицю
        круглих ключів S (42 x 16-бітних слів).
        """
        
        # b=16 байт, w=16 біт (2 байти) -> c = 16 / 2 = 8 слів
        c = 8 # ЗМІНЕНО:
        
        # Розпаковуємо 16 байт у 8 16-бітних слів (unsigned short, little-endian)
        L = list(struct.unpack('<8H', key)) # ЗМІНЕНО:
        
        S = [0] * self.t  # t = 42
        S[0] = self.P
        for i in range(1, self.t):
            S[i] = (S[i-1] + self.Q) % self.modulo

        # Перемішування S і L
        i = j = 0
        A = B = 0
        
        for k in range(3 * self.t): # 3 * 42 = 126 раундів
            A = S[i] = self._rol((S[i] + A + B), 3)
            B = L[j] = self._rol((L[j] + A + B), (A + B) % self.w)
            
            i = (i + 1) % self.t
            j = (j + 1) % c
            
        return S

    def _encrypt_block(self, data: bytes) -> bytes:
        """Шифрує один 4-байтний (32-бітний) блок"""
        
        # Перетворюємо 4 байти на два 16-бітних слова (little-endian)
        A, B = struct.unpack('<2H', data) # ЗМІНЕНО:

        A = (A + self.S[0]) % self.modulo
        B = (B + self.S[1]) % self.modulo

        for i in range(1, self.r + 1): # r=20
            A = (self._rol((A ^ B), B % self.w) + self.S[2 * i]) % self.modulo
            B = (self._rol((B ^ A), A % self.w) + self.S[2 * i + 1]) % self.modulo
        
        # Пакуємо назад у 4 байти
        return struct.pack('<2H', A, B) # ЗМІНЕНО:

    def _decrypt_block(self, data: bytes) -> bytes:
        """Дешифрує один 4-байтний (32-бітний) блок"""
        
        # Перетворюємо 4 байти на два 16-бітних слова
        A, B = struct.unpack('<2H', data) # ЗМІНЕНО:

        for i in range(self.r, 0, -1): # r=20
            B = self._ror((B - self.S[2 * i + 1]) % self.modulo, A % self.w) ^ A
            A = self._ror((A - self.S[2 * i]) % self.modulo, B % self.w) ^ B

        B = (B - self.S[1]) % self.modulo
        A = (A - self.S[0]) % self.modulo

        # Пакуємо назад у 4 байти
        return struct.pack('<2H', A, B) # ЗМІНЕНО:

    # --- Метод шифрування (з СBC) ---
    # Логіка CBC не змінилася, але тепер вона працює
    # з self.block_size = 4 байти
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Шифрує байти з використанням CBC."""
        
        if len(plaintext) % self.block_size != 0: # block_size тепер 4
            raise ValueError("Дані не вирівняні! Повинен бути застосований Pad.")

        ciphertext = bytearray()
        prev_block = self.iv # IV тепер 4 байти

        for i in range(0, len(plaintext), self.block_size): # Крок 4 байти
            block = plaintext[i : i + self.block_size]
            
            xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
            
            encrypted_block = self._encrypt_block(xor_block)
            
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block 

        self.iv = prev_block
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Дешифрує байти з використанням CBC."""
        
        if len(ciphertext) % self.block_size != 0: # block_size тепер 4
            raise ValueError("Дані не вирівняні! Неправильний шифротекст.")

        plaintext = bytearray()
        prev_block = self.iv # IV тепер 4 байти

        for i in range(0, len(ciphertext), self.block_size): # Крок 4 байти
            block = ciphertext[i : i + self.block_size]

            decrypted_block_xor = self._decrypt_block(block)
            
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block_xor, prev_block))
            
            plaintext.extend(plain_block)
            prev_block = block 

        self.iv = prev_block
        return bytes(plaintext)