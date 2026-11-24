"""Lucrarea de laborator nr. 5 (varianta 1): RSA, ElGamal si Diffie-Hellman.

Calculele sunt cele cerute pentru Wolfram, facute in Python (numere intregi de
precizie arbitrara).  Rulare:   python lab5_v1.py [--seed N] [--json fisier]
Fara --seed, numerele secrete se aleg aleatoriu (modulul secrets).
"""
import argparse
import hashlib
import json
import math
import random
import secrets
import shutil
import subprocess

MESSAGE = "Catana Marin"          # "Nume Prenume" (ASCII: fara diacritice)

# p si generatorul g din enuntul lucrarii (2048 de biti)
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


class Rng:
    """Sursa de numere aleatoare: criptografica sau reproductibila (--seed)."""
    def __init__(self, seed=None):
        self.r = random.Random(seed) if seed is not None else None

    def bits(self, k):
        return self.r.getrandbits(k) if self.r else secrets.randbits(k)

    def below(self, n):          # 0 <= x < n
        return self.r.randrange(n) if self.r else secrets.randbelow(n)


# ------------------------------------------------------------ numere prime
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
    """Numar prim de `bits` biti (primii doi biti = 1, ca produsul sa aiba 2*bits biti)."""
    while True:
        c = rng.bits(bits) | (3 << (bits - 2)) | 1
        if is_prime(c, rng=rng):
            return c


# -------------------------------------------------------------------- mesaj
def encode(text):
    data = text.encode("ascii")                     # doar ASCII
    hexs = " ".join(f"{b:02X}" for b in data)
    return data, hexs, int.from_bytes(data, "big")


def decode(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode("ascii")


# ---------------------------------------------------------------------- RSA
def rsa(m, rng):
    p = random_prime(1024, rng)
    q = random_prime(1024, rng)
    while q == p:
        q = random_prime(1024, rng)
    n, phi = p * q, (p - 1) * (q - 1)
    e = 65537
    assert math.gcd(e, phi) == 1
    d = pow(e, -1, phi)
    c = pow(m, e, n)
    m2 = pow(c, d, n)
    return dict(p=p, q=q, n=n, phi=phi, e=e, d=d, c=c, m2=m2, ok=(m2 == m),
                nbits=n.bit_length())


# ------------------------------------------------------------------ ElGamal
def elgamal(m, rng):
    assert m < P
    x = 2 + rng.below(P - 3)                         # cheia privata, 2..p-2
    h = pow(G, x, P)                                 # cheia publica
    k = 2 + rng.below(P - 3)                         # cheie efemera, 2..p-2
    c1 = pow(G, k, P)
    s = pow(h, k, P)                                 # secretul comun h^k
    c2 = m * s % P
    s2 = pow(c1, x, P)                               # = c1^x = h^k
    m2 = c2 * pow(s2, -1, P) % P
    return dict(x=x, h=h, k=k, c1=c1, s=s, c2=c2, s2=s2, m2=m2, ok=(m2 == m))


# ----------------------------------------------------------- Diffie-Hellman
def dh(rng):
    a = 2 + rng.below(P - 3)
    b = 2 + rng.below(P - 3)
    A, B = pow(G, a, P), pow(G, b, P)
    ka, kb = pow(B, a, P), pow(A, b, P)
    key = hashlib.sha256(ka.to_bytes(256, "big")).digest()      # cheie AES-256
    return dict(a=a, b=b, A=A, B=B, ka=ka, kb=kb, same=(ka == kb), key=key.hex())


def aes_demo(key_hex, text):
    """Alisa cripteaza cu AES-256-CBC, Bob decripteaza (foloseste openssl, daca exista)."""
    if not shutil.which("openssl"):
        return None
    iv = "000102030405060708090A0B0C0D0E0F"
    enc = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", key_hex, "-iv", iv, "-base64", "-A"],
                         input=text.encode(), capture_output=True, check=True).stdout.decode()
    dec = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-K", key_hex, "-iv", iv, "-base64", "-A"],
                         input=enc.encode(), capture_output=True, check=True).stdout.decode()
    return dict(iv=iv, cipher=enc, plain=dec)


SHORT = False        # --short: numerele lungi se afiseaza abreviat (pentru capturi de ecran)


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
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=None, help="seed pentru rezultate reproductibile")
    ap.add_argument("--short", action="store_true", help="afisare abreviata a numerelor lungi")
    ap.add_argument("--json", default=None, help="salveaza rezultatele intr-un fisier JSON")
    args = ap.parse_args()
    rng = Rng(args.seed)
    global SHORT
    SHORT = args.short

    data, hexs, m = encode(MESSAGE)
    print(f'Mesajul: "{MESSAGE}"')
    print("  Coduri ASCII (hex):", hexs)
    print("  Hex concatenat    :", "".join(f"{b:02X}" for b in data))
    show("m (zecimal)", m)
    print("  Biti in m:", m.bit_length())

    print("\n=== Sarcina 2.1: RSA ===")
    R = rsa(m, rng)
    for k in ("p", "q", "n"):
        show(k, R[k])
    print("  Biti in n:", R["nbits"])
    show("phi(n) = (p-1)(q-1)", R["phi"])
    print("  e =", R["e"], "(prim, gcd(e, phi) = 1)")
    show("d = e^-1 mod phi", R["d"])
    show("c = m^e mod n", R["c"])
    show("m' = c^d mod n", R["m2"])
    print("  Decriptare corecta:", R["ok"], '->', decode(R["m2"]))

    print("\n=== Sarcina 2.2: ElGamal ===")
    print("  p este prim (Miller-Rabin):", is_prime(P, rng=rng), "| biti in p:", P.bit_length(), "| g =", G)
    E = elgamal(m, rng)
    show("x (cheia privata)", E["x"])
    show("h = g^x mod p (cheia publica)", E["h"])
    show("k (aleator)", E["k"])
    show("c1 = g^k mod p", E["c1"])
    show("s = h^k mod p", E["s"])
    show("c2 = m * s mod p", E["c2"])
    show("s' = c1^x mod p", E["s2"])
    show("m' = c2 * s'^-1 mod p", E["m2"])
    print("  Decriptare corecta:", E["ok"], '->', decode(E["m2"]))

    print("\n=== Sarcina 3: Diffie-Hellman + AES-256 ===")
    H = dh(rng)
    show("a (secretul Alisei)", H["a"])
    show("b (secretul lui Bob)", H["b"])
    show("A = g^a mod p (trimis de Alisa)", H["A"])
    show("B = g^b mod p (trimis de Bob)", H["B"])
    show("K_Alisa = B^a mod p", H["ka"])
    show("K_Bob = A^b mod p", H["kb"])
    print("  Cheile coincid:", H["same"])
    print("  Cheia AES-256 = SHA-256(K) =", H["key"], f"({len(H['key']) * 4} biti)")
    A = aes_demo(H["key"], MESSAGE)
    if A:
        print("  AES-256-CBC, IV =", A["iv"])
        print("  Alisa cripteaza (Base64):", A["cipher"])
        print("  Bob decripteaza:", A["plain"])

    if args.json:
        out = dict(message=MESSAGE, hex=hexs, m=m, rsa=R, elgamal=E, dh=H, aes=A, p=P, g=G,
                   prime_p=is_prime(P, rng=rng))
        def txt(v):                                  # intregii mari ca text (JSON/JS pierd precizia)
            if isinstance(v, dict):
                return {k: txt(x) for k, x in v.items()}
            return str(v) if isinstance(v, int) and not isinstance(v, bool) else v
        json.dump(txt(out), open(args.json, "w"), indent=1)


if __name__ == "__main__":
    main()
