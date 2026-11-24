"""Laboratory Work No. 1 - Caesar cipher over the Romanian alphabet.

Task 1.1: classic Caesar cipher (one numeric key, 1..30).
Task 1.2: Caesar cipher with a permuted alphabet (numeric key + keyword >= 7 letters).
"""
import unicodedata

# ---------------------------------------------------------------- encoding
# Table 2 of the lab: A = 0, Ă = 1, Â = 2, ... , Z = 30
ALPHABET = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"
N = len(ALPHABET)                                   # 31
CODE = {letter: i for i, letter in enumerate(ALPHABET)}

# Cedilla variants (Ş, Ţ) are treated as the comma-below letters (Ș, Ț)
CEDILLA_FIX = {"\u015e": "\u0218", "\u015f": "\u0219",
               "\u0162": "\u021a", "\u0163": "\u021b"}

MIN_KEYWORD_LEN = 7
ALLOWED_LETTERS = " ".join(ALPHABET)


# ------------------------------------------------------------ validation
def to_letters(text, allow_spaces):
    """Return (clean_text, None) or (None, rejected_char).

    Converts to uppercase, merges cedilla variants and (if allowed)
    removes spaces. Any other character is rejected.
    """
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


def read_shift():
    """Ask for the numeric key until it is an integer in 1..N-1."""
    while True:
        raw = input("Key 1 (integer 1-30): ").strip()
        try:
            k = int(raw)
        except ValueError:
            k = None
        if k is not None and 1 <= k <= N - 1:
            return k
        print(f"  Invalid key '{raw}': the key must be an integer "
              f"from 1 to {N - 1} inclusive.")


def read_keyword():
    """Ask for the keyword until it is valid (letters only, length >= 7)."""
    while True:
        raw = input(f"Key 2 (keyword, min {MIN_KEYWORD_LEN} letters): ").strip()
        word, bad = to_letters(raw, allow_spaces=False)
        if bad is not None:
            print(f"  Invalid keyword: character {bad!r} is not allowed. "
                  f"Allowed letters: {ALLOWED_LETTERS}")
        elif len(word) < MIN_KEYWORD_LEN:
            print(f"  Invalid keyword: it has {len(word)} letter(s), "
                  f"at least {MIN_KEYWORD_LEN} are required.")
        else:
            return word


def read_text(prompt):
    """Ask for the message / ciphertext until it contains only valid letters."""
    while True:
        raw = input(prompt)
        text, bad = to_letters(raw, allow_spaces=True)
        if bad is not None:
            print(f"  Invalid character {bad!r} rejected. Allowed: Romanian "
                  f"letters ({ALLOWED_LETTERS}), upper or lower case, and spaces.")
        elif not text:
            print("  The text is empty: enter at least one letter.")
        else:
            return text


# ------------------------------------------------------------- the cipher
def build_alphabet(keyword=""):
    """Keyword letters (first occurrences only) + remaining letters in order."""
    order = []
    for ch in keyword + ALPHABET:
        if ch not in order:
            order.append(ch)
    return "".join(order)


def encrypt(text, k, alphabet=ALPHABET):
    """c = (x + k) mod n, where x is the position in `alphabet`."""
    pos = {l: i for i, l in enumerate(alphabet)}
    return "".join(alphabet[(pos[ch] + k) % N] for ch in text)


def decrypt(text, k, alphabet=ALPHABET):
    """m = (y - k) mod n; a negative result is brought back by adding n."""
    pos = {l: i for i, l in enumerate(alphabet)}
    out = []
    for ch in text:
        y = pos[ch] - k
        if y < 0:
            y += N
        out.append(alphabet[y])
    return "".join(out)


# ------------------------------------------------------------------- menu
def read_choice(prompt, options):
    while True:
        value = input(prompt).strip().upper()
        if value in options:
            return value
        print(f"  Invalid choice: enter one of {', '.join(options)}.")


def run_task(two_keys):
    op = read_choice("Operation - (E)ncrypt or (D)ecrypt: ", ("E", "D"))
    k = read_shift()
    alphabet = ALPHABET
    if two_keys:
        keyword = read_keyword()
        alphabet = build_alphabet(keyword)
        print("  Plain alphabet   :", " ".join(ALPHABET))
        print("  Permuted alphabet:", " ".join(alphabet))
    if op == "E":
        text = read_text("Message: ")
        print("Ciphertext:", encrypt(text, k, alphabet))
    else:
        text = read_text("Ciphertext: ")
        print("Decrypted message:", decrypt(text, k, alphabet))


def main():
    print("Laboratory Work No. 1 - Caesar cipher (Romanian alphabet, n = 31)")
    while True:
        print("\n1) Task 1.1 - Caesar cipher (one key)")
        print("2) Task 1.2 - Caesar cipher with a permuted alphabet (two keys)")
        print("0) Exit")
        choice = read_choice("Choose: ", ("1", "2", "0"))
        if choice == "0":
            break
        run_task(two_keys=(choice == "2"))


if __name__ == "__main__":
    main()
