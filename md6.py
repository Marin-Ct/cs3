"""MD6 (Rivest et al., SHA-3 candidate) - pure Python implementation, default parameters:
w = 64 bit words, n = 89, c = 16, b = 64, L = 64 (tree), no key, r = 40 + d/4.
Written from the MD6 specification (Rivest, 2008); used because hashlib has no MD6."""
import math

M64 = (1 << 64) - 1
N, C, B_WORDS = 89, 16, 64
TAPS = (17, 18, 21, 31, 67)                        # t0..t4
RSH = (10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12)
LSH = (11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9)
S0, SSTAR = 0x0123456789ABCDEF, 0x7311C2812425CFA0

# Q = first 15 words of the fractional part of sqrt(6)
Q = [(math.isqrt(6 << (2 * 64 * 15)) >> (64 * (14 - i))) & M64 for i in range(15)]


def rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & M64


def compress(Bw, level, index, z, p, d, r, K=None, keylen=0, L=64):
    """MD6 compression function f: 89 input words -> 16 output words."""
    U = (level << 56) | index
    V = (r << 48) | (L << 40) | (z << 36) | (p << 20) | (keylen << 12) | d
    A = Q + (K or [0] * 8) + [U, V] + list(Bw)
    S = S0
    for j in range(r):                              # r rounds of 16 steps
        for s in range(16):
            i = N + 16 * j + s
            x = S ^ A[i - N] ^ A[i - TAPS[0]] ^ (A[i - TAPS[1]] & A[i - TAPS[2]]) ^ (A[i - TAPS[3]] & A[i - TAPS[4]])
            x ^= x >> RSH[s]
            A.append((x ^ (x << LSH[s])) & M64)
        S = rotl(S, 1) ^ (S & SSTAR)
    return A[-16:]


def _words(data, nbits_total=4096):
    data = data + b"\x00" * (nbits_total // 8 - len(data))
    return [int.from_bytes(data[i:i + 8], "big") for i in range(0, len(data), 8)]


def md6(data: bytes, d: int = 256) -> str:
    r = 40 + d // 4
    level, msg = 1, data
    while True:
        chunks = [msg[i:i + 512] for i in range(0, len(msg), 512)] or [b""]
        final = len(chunks) == 1
        outs = []
        for idx, ch in enumerate(chunks):
            pad = (512 - len(ch)) * 8
            outs.append(compress(_words(ch), level, idx, 1 if final else 0, pad, d, r))
        if final:
            full = b"".join(w.to_bytes(8, "big") for w in outs[0])   # 1024 bits
            return full[-(d // 8):].hex()                           # last d bits
        msg = b"".join(w.to_bytes(8, "big") for o in outs for w in o)
        level += 1


if __name__ == "__main__":
    import sys
    print(md6(sys.argv[1].encode(), int(sys.argv[2]) if len(sys.argv) > 2 else 256))
