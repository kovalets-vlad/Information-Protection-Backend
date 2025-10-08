import math
from ..core.core_varibles import MULTIPLIER, INCREASE, COMPARISON_MODULE

def lcg(seed: int, a=MULTIPLIER, c=INCREASE, m=COMPARISON_MODULE) -> int:
    return (a * seed + c) % m

def generate_lcg_sequence(seed: int, n: int, a=MULTIPLIER, c=INCREASE, m=COMPARISON_MODULE) -> list[int]:
    seq = [0] * n
    for i in range(n):
        seed = (a * seed + c) % m
        seq[i] = seed
    return seq

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def cesaro_test(sequence: list[int]) -> tuple[float, float]:
    pairs = len(sequence) // 2
    coprime_count = 0
    for i in range(pairs):
        a = sequence[2 * i]
        b = sequence[2 * i + 1]
        if gcd(a, b) == 1:
            coprime_count += 1
    P = coprime_count / pairs
    return math.sqrt(6 / P), P
