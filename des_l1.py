"""Lucrare de laborator nr. 4 (DES), sarcina 2.4.

Fiind dat mesajul (8 caractere), de aflat L1.

Pași: mesaj -> coduri ASCII -> bloc M de 64 de biți -> IP(M) -> L0 | R0 -> L1 = R0.
"""
import random

# Tabelul IP (permutarea inițială) din FIPS 46-3: bitul i al rezultatului
# este bitul IP[i] al blocului de intrare (biții se numerotează de la 1).
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

MSG_LEN = 8
PRINTABLE = [chr(c) for c in range(32, 127)]          # caractere ASCII afișabile


# ---------------------------------------------------------------- validare
def check_message(text):
    """Returnează un mesaj de eroare sau None dacă textul este valid."""
    if len(text) != MSG_LEN:
        return f"mesajul are {len(text)} caractere, trebuie să aibă exact {MSG_LEN}."
    for ch in text:
        if not 32 <= ord(ch) <= 126:
            return (f"caracterul {ch!r} nu este permis. Se admit doar caractere "
                    f"ASCII afișabile (coduri 32-126: litere latine fără diacritice, "
                    f"cifre, spațiu și semne de punctuație).")
    return None


def read_message():
    while True:
        text = input(f"Mesajul ({MSG_LEN} caractere): ")
        error = check_message(text)
        if error is None:
            return text
        print("  Mesaj invalid:", error)


# ----------------------------------------------------------------- biți
def to_bits(data):
    """Lista de biți (MSB primul) pentru o secvență de octeți."""
    return [(byte >> (7 - k)) & 1 for byte in data for k in range(8)]


def fmt_bits(bits, group=8):
    s = "".join(map(str, bits))
    return " ".join(s[i:i + group] for i in range(0, len(s), group))


def to_hex(bits):
    s = "".join(map(str, bits))
    return "".join(f"{int(s[i:i + 4], 2):X}" for i in range(0, len(s), 4))


def initial_permutation(bits):
    """IP(M): bitul i al rezultatului este bitul IP[i] al lui M."""
    return [bits[IP[i] - 1] for i in range(64)]


# ----------------------------------------------------------------- afișare
def show_steps(data, label):
    print(f"\nMesaj: {label}")
    print("\nPasul 1. Codurile ASCII ale caracterelor")
    print("  Nr  Caracter  Zecimal  Hex  Binar")
    for i, byte in enumerate(data, 1):
        ch = chr(byte) if 32 <= byte <= 126 else "-"
        print(f"  {i:<3} {ch!r:<9} {byte:<8} {byte:02X}   {byte:08b}")

    m = to_bits(data)
    print("\nPasul 2. Blocul M (64 de biți, câte un octet pe rând; biții sunt numerotați 1..64)")
    for r in range(8):
        print(f"  M{r * 8 + 1:>2}..M{r * 8 + 8:<2}  {''.join(map(str, m[r * 8:r * 8 + 8]))}")
    print("  M =", fmt_bits(m))

    print("\nPasul 3. Tabelul IP (permutarea inițială, FIPS 46-3)")
    for r in range(8):
        print("  " + " ".join(f"{x:>2}" for x in IP[r * 8:r * 8 + 8]))

    ipm = initial_permutation(m)
    print("\nPasul 4. IP(M): bitul i al rezultatului este bitul IP[i] al lui M")
    for r in range(8):
        pos = ", ".join(f"M{IP[r * 8 + k]}" for k in range(8))
        print(f"  {''.join(map(str, ipm[r * 8:r * 8 + 8]))}   <- {pos}")
    print("  IP(M) =", fmt_bits(ipm))

    l0, r0 = ipm[:32], ipm[32:]
    print("\nPasul 5. Se împarte IP(M) în L0 (primii 32 de biți) și R0 (ultimii 32 de biți)")
    print("  L0 =", fmt_bits(l0), " =", to_hex(l0))
    print("  R0 =", fmt_bits(r0), " =", to_hex(r0))

    l1 = r0
    print("\nPasul 6. În runda 1 se aplică L1 = R0 (și R1 = L0 xor f(R0, K1))")
    print("  L1 =", fmt_bits(l1), " =", to_hex(l1))
    return l0, r0, l1


# ------------------------------------------------------------------ meniu
def read_choice(prompt, options):
    while True:
        value = input(prompt).strip()
        if value in options:
            return value
        print(f"  Alegere invalidă: introduceți {', '.join(options)}.")


def main():
    print("Lucrare de laborator nr. 4 - DES, sarcina 2.4: determinarea lui L1")
    while True:
        print("\n1) Introduceți mesajul de 8 caractere")
        print("2) Generați mesajul aleatoriu")
        print("3) Verificare pe exemplul standard (M = 0123456789ABCDEF)")
        print("0) Ieșire")
        choice = read_choice("Alegeți: ", ("1", "2", "3", "0"))
        if choice == "0":
            break
        if choice == "3":
            data = bytes.fromhex("0123456789ABCDEF")
            show_steps(data, "0123456789ABCDEF (hex)")
            continue
        if choice == "1":
            text = read_message()
        else:
            text = "".join(random.choice(PRINTABLE) for _ in range(MSG_LEN))
        show_steps(text.encode("ascii"), repr(text))


if __name__ == "__main__":
    main()
