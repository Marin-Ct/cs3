"""Lucrare de laborator nr. 3, Sarcina 3.2 - cifrul Vigenère pentru alfabetul românesc.

Alfabetul are n = 31 de litere, codificate 0..30 (A = 0, Ă = 1, Â = 2, ... Z = 30).
    criptare:   c_i = (m_i + k_i) mod 31
    decriptare: m_i = (c_i - k_i) mod 31
"""
import unicodedata

ALPHABET = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"          # 31 de litere
N = len(ALPHABET)
CODE = {letter: i for i, letter in enumerate(ALPHABET)}
MIN_KEY_LEN = 7
ALLOWED = " ".join(ALPHABET)

# variantele cu sedilă (Ş, Ţ) se tratează ca Ș, Ț
CEDILLA_FIX = {"\u015e": "\u0218", "\u015f": "\u0219",
               "\u0162": "\u021a", "\u0163": "\u021b"}


# ---------------------------------------------------------------- validare
def to_letters(text, allow_spaces):
    """Returnează (text_curat, None) sau (None, caracter_respins)."""
    result = []
    for ch in unicodedata.normalize("NFC", text):
        if ch == " " and allow_spaces:
            continue
        ch = CEDILLA_FIX.get(ch, ch)
        up = ch.upper()
        if len(up) != 1 or up not in CODE:
            return None, ch
        result.append(up)
    return "".join(result), None


def read_key():
    """Cere cheia până când are cel puțin 7 litere valide."""
    while True:
        raw = input(f"Cheia (minim {MIN_KEY_LEN} litere): ").strip()
        key, bad = to_letters(raw, allow_spaces=False)
        if bad is not None:
            print(f"  Cheie invalidă: caracterul {bad!r} nu este permis. "
                  f"Se admit doar literele: {ALLOWED} (mari sau mici).")
        elif len(key) < MIN_KEY_LEN:
            print(f"  Cheie invalidă: are {len(key)} litere, "
                  f"sunt necesare cel puțin {MIN_KEY_LEN}.")
        else:
            return key


def read_text(prompt):
    """Cere mesajul / criptograma până când este valid (spațiile se elimină)."""
    while True:
        text, bad = to_letters(input(prompt), allow_spaces=True)
        if bad is not None:
            print(f"  Caracter invalid {bad!r}. Se admit doar literele "
                  f"alfabetului românesc ({ALLOWED}), mari sau mici, și spații.")
        elif not text:
            print("  Textul este gol: introduceți cel puțin o literă.")
        else:
            return text


# ------------------------------------------------------------- algoritmul
def encrypt(text, key, alphabet=ALPHABET):
    n = len(alphabet)
    code = {l: i for i, l in enumerate(alphabet)}
    out = []
    for i, ch in enumerate(text):
        k = code[key[i % len(key)]]                # litera cheii se repetă ciclic
        out.append(alphabet[(code[ch] + k) % n])
    return "".join(out)


def decrypt(text, key, alphabet=ALPHABET):
    n = len(alphabet)
    code = {l: i for i, l in enumerate(alphabet)}
    out = []
    for i, ch in enumerate(text):
        k = code[key[i % len(key)]]
        y = code[ch] - k
        if y < 0:                                  # aducem rezultatul în 0..n-1
            y += n
        out.append(alphabet[y])
    return "".join(out)


def codes(text):
    return " ".join(str(CODE[ch]) for ch in text)


# ------------------------------------------------------------------ meniu
def read_choice(prompt, options):
    while True:
        value = input(prompt).strip().upper()
        if value in options:
            return value
        print(f"  Alegere invalidă: introduceți {', '.join(options)}.")


def main():
    print("Lucrare de laborator nr. 3 - Vigenère (alfabetul românesc, n = 31)")
    while True:
        print("\n1) Criptare\n2) Decriptare\n0) Ieșire")
        choice = read_choice("Alegeți: ", ("1", "2", "0"))
        if choice == "0":
            break
        key = read_key()
        if choice == "1":
            text = read_text("Mesajul: ")
            print("  Mesaj (fără spații):", text)
            print("  Coduri mesaj :", codes(text))
            print("  Coduri cheie :", " ".join(str(CODE[key[i % len(key)]]) for i in range(len(text))))
            result = encrypt(text, key)
            print("Criptograma:", result)
        else:
            text = read_text("Criptograma: ")
            print("Mesaj decriptat:", decrypt(text, key))


if __name__ == "__main__":
    main()
