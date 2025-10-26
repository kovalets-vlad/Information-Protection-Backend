from typing import Union
import struct
from math import sin, floor

def _left_rotate(x: int, amount: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

class MD5:
    def __init__(self, data: Union[bytes, bytearray, str] = b""):
        self._A = 0x67452301
        self._B = 0xEFCDAB89
        self._C = 0x98BADCFE
        self._D = 0x10325476

        self._buffer = b""
        self._counter = 0 

        self._K = [int(floor(abs(sin(i + 1)) * (1 << 32))) & 0xFFFFFFFF for i in range(64)]
        self._s = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5, 9, 14, 20,   5, 9, 14, 20,   5, 9, 14, 20,   5, 9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        ]

        if data:
            self.update(data)

    def update(self, data: Union[bytes, bytearray, str]):
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeError("MD5.update() приймає bytes/bytearray або str")

        self._buffer += data
        self._counter += len(data) * 8

        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def _process_block(self, block: bytes):
        M = list(struct.unpack('<16I', block))
        A = self._A
        B = self._B
        C = self._C
        D = self._D

        for i in range(64):
            if 0 <= i <= 15:
                F = (B & C) | (~B & D)
                g = i
            elif 16 <= i <= 31:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16

            F = (F + A + self._K[i] + M[g]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + _left_rotate(F, self._s[i])) & 0xFFFFFFFF

        self._A = (self._A + A) & 0xFFFFFFFF
        self._B = (self._B + B) & 0xFFFFFFFF
        self._C = (self._C + C) & 0xFFFFFFFF
        self._D = (self._D + D) & 0xFFFFFFFF

    def _pad(self) -> bytes:
        padding = b'\x80'
        pad_len = ((56 - (len(self._buffer) + 1) % 64) % 64)
        padding += b'\x00' * pad_len
        padding += struct.pack('<Q', self._counter)
        return padding

    def digest(self) -> bytes:
        saved_buffer = self._buffer
        saved_counter = self._counter
        saved_A, saved_B, saved_C, saved_D = self._A, self._B, self._C, self._D

        self.update(self._pad())
        result = struct.pack('<4I', self._A, self._B, self._C, self._D)

        self._buffer = saved_buffer
        self._counter = saved_counter
        self._A, self._B, self._C, self._D = saved_A, saved_B, saved_C, saved_D

        return result

    def hexdigest(self) -> str:
        return ''.join(f"{b:02x}" for b in self.digest())