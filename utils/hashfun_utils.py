from typing import Union
import struct
from math import sin, floor
from numba import jit

_K = [int(floor(abs(sin(i + 1)) * (1 << 32))) & 0xFFFFFFFF for i in range(64)]
_s = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5, 9, 14, 20,   5, 9, 14, 20,   5, 9, 14, 20,   5, 9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

@jit(nopython=True) 
def _left_rotate(x: int, amount: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

@jit(nopython=True) 
def _process_block_numba(A, B, C, D, M_tuple, K_tuple, s_tuple):
    A_orig, B_orig, C_orig, D_orig = A, B, C, D

    for i in range(64):
        if i < 16:
            F = (B & C) | (~B & D)
            g = i
        elif i < 32:
            F = (D & B) | (~D & C)
            g = (5 * i + 1) % 16
        elif i < 48:
            F = B ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            F = C ^ (B | ~D)
            g = (7 * i) % 16
        
        F = (F + A + K_tuple[i] + M_tuple[g]) & 0xFFFFFFFF
        A, D, C, B = D, C, B, (B + _left_rotate(F, s_tuple[i])) & 0xFFFFFFFF

    A = (A_orig + A) & 0xFFFFFFFF
    B = (B_orig + B) & 0xFFFFFFFF
    C = (C_orig + C) & 0xFFFFFFFF
    D = (D_orig + D) & 0xFFFFFFFF
    
    return A, B, C, D

class MD5:
    def __init__(self, data: Union[bytes, bytearray, str] = b""):
        self._A = 0x67452301
        self._B = 0xEFCDAB89
        self._C = 0x98BADCFE
        self._D = 0x10325476

        self._K_tuple = tuple(_K)
        self._s_tuple = tuple(_s)

        self._buffer = bytearray()
        self._counter = 0  

        if data:
            self.update(data)

    def update(self, data: Union[bytes, bytearray, str]):
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeError("MD5.update() приймає bytes/bytearray або str")

        self._buffer.extend(data)
        self._counter += len(data) * 8

        buf_len = len(self._buffer)
        n_blocks = buf_len // 64
        if n_blocks:
            mv = self._buffer 
            for i in range(n_blocks):
                offset = i * 64
                M_tuple = struct.unpack_from('<16I', mv, offset) 

                self._A, self._B, self._C, self._D = _process_block_numba(
                    self._A, self._B, self._C, self._D,
                    M_tuple, self._K_tuple, self._s_tuple
                )
            del self._buffer[:n_blocks * 64]

    def _process_block(self, buf: bytearray, offset: int):
        M = struct.unpack_from('<16I', buf, offset)
        A = self._A
        B = self._B
        C = self._C
        D = self._D

        K = _K
        s = _s
        for i in range(64):
            if i < 16:
                F = (B & C) | (~B & D)
                g = i
            elif i < 32:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16

            F = (F + A + K[i] + M[g]) & 0xFFFFFFFF
            A, D, C, B = D, C, B, (B + _left_rotate(F, s[i])) & 0xFFFFFFFF

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
        saved_buf = bytes(self._buffer)  
        saved_counter = self._counter
        saved_A, saved_B, saved_C, saved_D = self._A, self._B, self._C, self._D

        self.update(self._pad())
        result = struct.pack('<4I', self._A, self._B, self._C, self._D)

        self._buffer = bytearray(saved_buf)
        self._counter = saved_counter
        self._A, self._B, self._C, self._D = saved_A, saved_B, saved_C, saved_D

        return result

    def hexdigest(self) -> str:
        return ''.join(f"{b:02x}" for b in self.digest())
