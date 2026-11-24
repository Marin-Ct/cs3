"""Lucrarea de laborator nr. 6: functii hash si semnaturi digitale.

Varianta k = 4  ->  i = (4 mod 24) + 1 = 5
  Sarcina 2: semnatura RSA (n >= 3072 biti), functia hash nr. 5 = MD6-256
  Sarcina 3: semnatura ElGamal (p 2048 biti, g = 2), functia hash nr. 5 = MD6-128
Mesajul m = textul clar obtinut in lucrarea nr. 2 (fisierul mesaj_lab2.txt).

Rulare:  python lab6.py [--seed N] [--short] [--json fisier] [--msg fisier]
"""
import argparse
import json
import math
import random
import secrets

from md6 import md6

K = 4
I = (K % 24) + 1

P = int(
    "3231700607131100730015351347782516336248805713348907517458843413926"
    "980683413621000279205636264016468545855635793533081692882902308057347"
    "262527355474246124574102620252791657297286270630032526342821314576693"
    "141422365422094111134862999165747826803423055308634905063555771221918"
    "789033272956969612974385624174123623722519734640269185579776797682301"
    "462539793305801522685873076119753243646747585546071504389684494036613"
    "049769781285429595865959756705128385213278446852292550456827287911372"
    "009893187395914337417583782600027803497319855206060753323412260325468"
    "4088120031105907484281003994966956119696956248629032338072839127039")
G = 2
SHORT = False


class Rng:
    def __init__(self, seed=None):
        self.r = random.Random(seed) if seed is not None else None

    def bits(self, k):
        return self.r.getrandbits(k) if self.r else secrets.randbits(k)

    def below(self, n):
        return self.r.randrange(n) if self.r else secrets.randbelow(n)


SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]


def is_prime(n, rounds=40, rng=None):
    """Testul Miller-Rabin."""
    if n < 2:
        return False
    for q in SMALL:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + (rng.below(n - 3) if rng else secrets.randbelow(n - 3))
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits, rng):
    while True:
        c = rng.bits(bits) | (3 << (bits - 2)) | 1      # primii 2 biti = 1 -> p*q are 2*bits biti
        if is_prime(c, rng=rng):
            return c


# ----------------------------------------------------------------- hash
def hash_dec(msg: bytes, d: int):
    """Valoarea hash MD6-d: (hex, zecimal)."""
    hx = md6(msg, d)
    return hx, int(hx, 16)


# ---------------------------------------------------------- RSA (sarcina 2)
def rsa_keys(rng, nbits=3072):
    p = random_prime(nbits // 2, rng)
    q = random_prime(nbits // 2, rng)
    while q == p:
        q = random_prime(nbits // 2, rng)
    n, phi = p * q, (p - 1) * (q - 1)
    e = 65537
    assert math.gcd(e, phi) == 1
    return dict(p=p, q=q, n=n, phi=phi, e=e, d=pow(e, -1, phi))


def rsa_sign(h, d, n):
    return pow(h, d, n)                  # s = h^d mod n


def rsa_verify(s, h, e, n):
    return pow(s, e, n) == h             # s^e mod n == h


# ------------------------------------------------------ ElGamal (sarcina 3)
def elgamal_keys(rng):
    x = 2 + rng.below(P - 3)             # cheia privata, 2 <= x <= p-2
    return dict(x=x, y=pow(G, x, P))     # cheia publica y = g^x mod p


def elgamal_sign(h, x, rng):
    while True:
        k = 2 + rng.below(P - 3)         # k aleator, gcd(k, p-1) = 1
        if math.gcd(k, P - 1) == 1:
            break
    r = pow(G, k, P)
    s = (h - x * r) * pow(k, -1, P - 1) % (P - 1)
    return dict(k=k, r=r, s=s)


def elgamal_verify(h, r, s, y):
    if not 0 < r < P:
        return False
    return pow(y, r, P) * pow(r, s, P) % P == pow(G, h, P)    # y^r * r^s = g^h


def show(label, value, per=70):
    s = str(value)
    if SHORT and len(s) > per:
        print(f"  {label} =")
        print(f"    {s[:36]}...{s[-20:]}  ({len(s)} cifre)")
        return
    print(f"  {label} =")
    for i in range(0, len(s), per):
        print("    " + s[i:i + per])


def main():
    global SHORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int)
    ap.add_argument("--short", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--msg", default="mesaj_lab2.txt")
    a = ap.parse_args()
    SHORT = a.short
    rng = Rng(a.seed)
    msg = open(a.msg, encoding="utf-8").read().strip()
    data = msg.encode("utf-8")
    bad = (msg[:-1] + ("X" if msg[-1] != "X" else "Y")).encode("utf-8")      # mesaj modificat (ultimul caracter)

    print(f"Numarul in lista grupei k = {K};  i = (k mod 24) + 1 = {I}")
    print(f"Mesajul m (lab. 2): {len(msg)} caractere, {len(data)} octeti UTF-8")
    print(f'  "{msg[:60]}..."')
    out = dict(k=K, i=I, msg_len=len(msg), bytes=len(data))

    # ---------------- sarcina 2: RSA + MD6-256
    print("\n=== Sarcina 2: semnatura RSA, hash MD6-256 (n >= 3072 biti) ===")
    hx, h = hash_dec(data, 256)
    print("  MD6-256(m) hex =", hx)
    show("h = MD6-256(m) zecimal", h)
    R = rsa_keys(rng)
    show("p (1536 biti)", R["p"]); show("q (1536 biti)", R["q"]); show("n = p*q", R["n"])
    print("  Biti in n:", R["n"].bit_length(), "| h < n:", h < R["n"])
    show("phi(n)", R["phi"]); print("  e =", R["e"], "(gcd(e, phi) = 1)"); show("d = e^-1 mod phi", R["d"])
    s = rsa_sign(h, R["d"], R["n"])
    show("s = h^d mod n  (semnatura)", s)
    w = pow(s, R["e"], R["n"])
    show("w = s^e mod n", w)
    hx2, h2 = hash_dec(data, 256)                  # verificatorul recalculeaza hash-ul mesajului primit
    print("  h' = MD6-256(m) recalculat (hex) =", hx2)
    print("  w == h':", w == h2)
    ok = rsa_verify(s, h2, R["e"], R["n"])
    print("  Semnatura VALIDA:", ok)
    hb = hash_dec(bad, 256)
    print("  Mesaj modificat (ultimul caracter) -> MD6-256 =", hb[0])
    print("  Semnatura VALIDA pentru mesajul modificat:", rsa_verify(s, hb[1], R["e"], R["n"]))
    out["rsa"] = dict(hash_hex=hx, h=h, **R, s=s, w=w, ok=ok, tamper_ok=rsa_verify(s, hb[1], R["e"], R["n"]), bad_hash=hb[0])

    # ---------------- sarcina 3: ElGamal + MD6-128
    print("\n=== Sarcina 3: semnatura ElGamal, hash MD6-128 ===")
    print("  p este prim (Miller-Rabin):", is_prime(P, rng=rng), "| biti in p:", P.bit_length(), "| g =", G)
    hx3, h3 = hash_dec(data, 128)
    print("  MD6-128(m) hex =", hx3)
    show("h = MD6-128(m) zecimal", h3)
    E = elgamal_keys(rng)
    show("x (cheia privata)", E["x"]); show("y = g^x mod p (cheia publica)", E["y"])
    S = elgamal_sign(h3, E["x"], rng)
    show("k (aleator, gcd(k, p-1) = 1)", S["k"])
    show("r = g^k mod p", S["r"])
    show("s = (h - x*r) * k^-1 mod (p-1)", S["s"])
    left = pow(E["y"], S["r"], P) * pow(S["r"], S["s"], P) % P
    right = pow(G, h3, P)
    show("stanga: y^r * r^s mod p", left); show("dreapta: g^h mod p", right)
    ok3 = elgamal_verify(h3, S["r"], S["s"], E["y"])
    print("  Semnatura VALIDA:", ok3)
    hb3 = hash_dec(bad, 128)
    print("  Mesaj modificat -> MD6-128 =", hb3[0])
    tamper3 = elgamal_verify(hb3[1], S["r"], S["s"], E["y"])
    print("  Semnatura VALIDA pentru mesajul modificat:", tamper3)
    out["elgamal"] = dict(hash_hex=hx3, h=h3, **E, **S, left=left, right=right, ok=ok3, tamper_ok=tamper3, bad_hash=hb3[0])

    if a.json:
        def txt(v):
            if isinstance(v, dict):
                return {k: txt(x) for k, x in v.items()}
            return str(v) if isinstance(v, int) and not isinstance(v, bool) else v
        json.dump(txt(out), open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
