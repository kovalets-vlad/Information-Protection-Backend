import math
from ..core.core_varibles import COMPARISON_MODULE, INCREASE, MULTIPLIER

def lcg(seed: int, a=MULTIPLIER, c=INCREASE, m=COMPARISON_MODULE) -> int:
    return (a * seed + c) % m

def generate_lcg_sequence(seed: int, n: int) -> list[int]:
    seq = []
    for _ in range(n):
        seed = lcg(seed)
        seq.append(seed)
    return seq

def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a

def cesaro_test(sequence: list[int]) -> tuple[float, float]:
    pairs = len(sequence) // 2
    coprime_count = 0
    for i in range(pairs):
        a, b = sequence[2*i], sequence[2*i+1]
        if gcd(a, b) == 1:
            coprime_count += 1
    P = coprime_count / pairs
    pi_estimate = math.sqrt(6 / P)
    return pi_estimate, P
