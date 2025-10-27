import hashlib
import math
from typing import Iterable


def sha256_hash(text: str) -> str:
    normalized = " ".join(text.split()).encode("utf-8", "ignore")
    return hashlib.sha256(normalized).hexdigest()


def _tokenize(text: str) -> Iterable[int]:
    for token in text.lower().split():
        yield int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)


def simhash(text: str, bits: int = 64) -> str:
    if not text:
        return "0" * (bits // 4)
    v = [0] * bits
    for token_hash in _tokenize(text):
        for i in range(bits):
            bitmask = 1 << i
            v[i] += 1 if token_hash & bitmask else -1
    fingerprint = 0
    for i, weight in enumerate(v):
        if weight > 0:
            fingerprint |= 1 << i
    return f"{fingerprint:0{bits // 4}x}"


def hamming_distance(hash_a: str, hash_b: str) -> int:
    a = int(hash_a, 16)
    b = int(hash_b, 16)
    return bin(a ^ b).count("1")


__all__ = ["sha256_hash", "simhash", "hamming_distance"]
