#!/usr/bin/env python3
"""
Encryption Tool
Supports: Additive (Caesar), Multiplicative, Affine, Monoalphabetic,
Autokey, Vigenere, Playfair, Rail-Fence (keyless), Keyed Columnar,
Combination (Keyed + Rail), Double Transposition, plus a CLI.
"""

import string
from itertools import cycle
from math import ceil

ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = 26


def modinv(a, m):
    """Return modular inverse of a modulo m using extended Euclid, or None if no inverse."""
    a = a % m
    if a == 0:
        return None
    # Extended Euclidean algorithm
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        r0, r1, t0, t1 = r1, r0 - q * r1, t1, t0 - q * t1
    if r0 != 1:
        return None  # not coprime
    inv = t0 % m
    return inv


def _shift_char(ch, shift):
    """Shift single character preserving case; shift may be negative."""
    if ch.isalpha():
        base = ord('A') if ch.isupper() else ord('a')
        return chr((ord(ch) - base + shift) % ALPHABET_SIZE + base)
    return ch


def _alphabet_index(ch):
    return ord(ch.upper()) - ord('A')


# ----------------- ADDITIVE CIPHER (Caesar) -----------------
def additive_encrypt(plaintext, key):
    """Encrypt plaintext using Additive (Caesar) Cipher"""
    return ''.join(_shift_char(ch, key) for ch in plaintext)


def additive_decrypt(ciphertext, key):
    """Decrypt Additive Cipher"""
    return additive_encrypt(ciphertext, -key)


# ----------------- MULTIPLICATIVE CIPHER -----------------
def multiplicative_encrypt(plaintext, key):
    """Encrypt using Multiplicative Cipher"""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(((ord(ch) - base) * key) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return ''.join(result)


def multiplicative_decrypt(ciphertext, key):
    """Decrypt Multiplicative Cipher"""
    inv = modinv(key, ALPHABET_SIZE)
    if inv is None:
        return "Invalid Key! (not invertible mod 26)"
    return multiplicative_encrypt(ciphertext, inv)


# ----------------- AFFINE CIPHER -----------------
def affine_encrypt(plaintext, a, b):
    """Encrypt using Affine Cipher: E(x) = (a*x + b) mod 26"""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            result.append(chr((a * x + b) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return ''.join(result)


def affine_decrypt(ciphertext, a, b):
    """Decrypt Affine Cipher: D(y) = a_inv*(y - b) mod 26"""
    inv = modinv(a, ALPHABET_SIZE)
    if inv is None:
        return "Invalid key! 'a' not invertible mod 26"
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - base
            result.append(chr((inv * (y - b)) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return ''.join(result)


# ----------------- MONOALPHABETIC SUBSTITUTION -----------------
def _validate_mono_key(key):
    if len(key) != 26:
        return False
    up = key.upper()
    return set(up) == set(ALPHABET)


def monoalphabetic_encrypt(plaintext, key):
    """Encrypt using Monoalphabetic Substitution Cipher"""
    if not _validate_mono_key(key):
        raise ValueError("Key must be 26 unique letters A-Z")
    key_map = {ALPHABET[i]: key.upper()[i] for i in range(26)}
    result = []
    for ch in plaintext:
        if ch.isupper():
            result.append(key_map.get(ch, ch))
        elif ch.islower():
            result.append(key_map.get(ch.upper(), ch).lower())
        else:
            result.append(ch)
    return ''.join(result)


def monoalphabetic_decrypt(ciphertext, key):
    """Decrypt Monoalphabetic Cipher"""
    if not _validate_mono_key(key):
        raise ValueError("Key must be 26 unique letters A-Z")
    inv_map = {key.upper()[i]: ALPHABET[i] for i in range(26)}
    result = []
    for ch in ciphertext:
        if ch.isupper():
            result.append(inv_map.get(ch, ch))
        elif ch.islower():
            result.append(inv_map.get(ch.upper(), ch).lower())
        else:
            result.append(ch)
    return ''.join(result)


# ----------------- AUTOKEY CIPHER -----------------
def autokey_encrypt(plaintext, keyword):
    """Encrypt using Autokey Cipher: key = keyword + plaintext (letters only)"""
    key_stream = []
    # Build key stream using letters only from keyword and plaintext
    for ch in keyword:
        if ch.isalpha():
            key_stream.append(ch.upper())
    for ch in plaintext:
        if ch.isalpha():
            key_stream.append(ch.upper())
    result = []
    ks_index = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key_stream[ks_index]) - ord('A')
            result.append(chr((ord(ch) - base + k) % ALPHABET_SIZE + base))
            ks_index += 1
        else:
            result.append(ch)
    return ''.join(result)


def autokey_decrypt(ciphertext, keyword):
    """Decrypt Autokey Cipher"""
    result = []
    key_stream = [c.upper() for c in keyword if c.isalpha()]
    ks_index = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key_stream[ks_index]) - ord('A')
            plain_ch = chr((ord(ch) - base - k) % ALPHABET_SIZE + base)
            result.append(plain_ch)
            # append the decrypted letter (uppercase) to key stream for future letters
            key_stream.append(plain_ch.upper())
            ks_index += 1
        else:
            result.append(ch)
    return ''.join(result)


# ----------------- VIGENERE CIPHER -----------------
def vigenere_encrypt(plaintext, keyword):
    """Encrypt using Vigenere Cipher"""
    result = []
    key_iter = (k for k in cycle(keyword) if k.isalpha())
    for ch in plaintext:
        if ch.isalpha():
            k = next(key_iter)
            base = ord('A') if ch.isupper() else ord('a')
            k_val = ord(k.upper()) - ord('A')
            result.append(chr((ord(ch) - base + k_val) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decrypt(ciphertext, keyword):
    """Decrypt Vigenere Cipher"""
    result = []
    key_iter = (k for k in cycle(keyword) if k.isalpha())
    for ch in ciphertext:
        if ch.isalpha():
            k = next(key_iter)
            base = ord('A') if ch.isupper() else ord('a')
            k_val = ord(k.upper()) - ord('A')
            result.append(chr((ord(ch) - base - k_val) % ALPHABET_SIZE + base))
        else:
            result.append(ch)
    return ''.join(result)


# ----------------- PLAYFAIR CIPHER -----------------
def _playfair_prepare_text(text, filler='X'):
    """Prepare plaintext for Playfair: uppercase, replace J->I, remove non-alpha,
       insert filler between repeated letters in a digraph, and make even length."""
    letters = [c.upper() for c in text if c.isalpha()]
    # Replace J with I
    letters = ['I' if c == 'J' else c for c in letters]
    i = 0
    out = []
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else None
        if b is None:
            out.append(a)
            i += 1
        elif a == b:
            out.extend([a, filler])
            i += 1
        else:
            out.extend([a, b])
            i += 2
    if len(out) % 2 == 1:
        out.append(filler)
    return out


def _playfair_key_square(keyword):
    """Return 5x5 key square (list of lists) and mapping from letter to (r,c). J merged with I."""
    seen = []
    for c in keyword.upper():
        if not c.isalpha():
            continue
        ch = 'I' if c == 'J' else c
        if ch not in seen:
            seen.append(ch)
    for c in ALPHABET:
        ch = 'I' if c == 'J' else c
        if ch not in seen:
            seen.append(ch)
    # build 5x5
    square = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    pos = {square[r][c]: (r, c) for r in range(5) for c in range(5)}
    return square, pos


def playfair_encrypt(plaintext, keyword):
    """Playfair encryption (classic 5x5)"""
    square, pos = _playfair_key_square(keyword)
    prepared = _playfair_prepare_text(plaintext)
    cipher = []
    for i in range(0, len(prepared), 2):
        a, b = prepared[i], prepared[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            # same row -> shift right
            cipher.append(square[ra][(ca + 1) % 5])
            cipher.append(square[rb][(cb + 1) % 5])
        elif ca == cb:
            # same column -> shift down
            cipher.append(square[(ra + 1) % 5][ca])
            cipher.append(square[(rb + 1) % 5][cb])
        else:
            # rectangle -> swap columns
            cipher.append(square[ra][cb])
            cipher.append(square[rb][ca])
    # preserve case by mapping onto original plaintext pattern
    result = []
    alpha_iter = iter(cipher)
    for ch in plaintext:
        if ch.isalpha():
            out = next(alpha_iter)
            result.append(out if ch.isupper() else out.lower())
        else:
            result.append(ch)
    return ''.join(result)


def playfair_decrypt(ciphertext, keyword):
    square, pos = _playfair_key_square(keyword)
    letters = [c.upper() for c in ciphertext if c.isalpha()]
    plain = []
    for i in range(0, len(letters), 2):
        a, b = letters[i], letters[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            plain.append(square[ra][(ca - 1) % 5])
            plain.append(square[rb][(cb - 1) % 5])
        elif ca == cb:
            plain.append(square[(ra - 1) % 5][ca])
            plain.append(square[(rb - 1) % 5][cb])
        else:
            plain.append(square[ra][cb])
            plain.append(square[rb][ca])
    # Map decrypted letters onto original ciphertext pattern to preserve case and non-alpha
    result = []
    alpha_iter = iter(plain)
    for ch in ciphertext:
        if ch.isalpha():
            out = next(alpha_iter)
            result.append(out if ch.isupper() else out.lower())
        else:
            result.append(ch)
    return ''.join(result)


# ----------------- KEYLESS TRANSPOSITION (Rail-Fence) -----------------
def rail_fence_encrypt(plaintext, depth=3):
    """Simple rail-fence: build rails and then concatenate them."""
    if depth <= 1:
        return plaintext
    rails = ['' for _ in range(depth)]
    rail = 0
    direction = 1  # 1 down, -1 up
    for ch in plaintext:
        rails[rail] += ch
        # move rail pointer for every character (includes non-alpha to preserve positions)
        rail += direction
        if rail == depth - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    return ''.join(rails)


def rail_fence_decrypt(ciphertext, depth=3):
    if depth <= 1:
        return ciphertext
    n = len(ciphertext)
    # build pattern
    pattern = [None] * n
    rail = 0
    direction = 1
    for i in range(n):
        pattern[i] = rail
        rail += direction
        if rail == depth - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    # count how many chars in each rail
    counts = [pattern.count(r) for r in range(depth)]
    rails = []
    idx = 0
    for c in counts:
        rails.append(list(ciphertext[idx:idx + c]))
        idx += c
    # reconstruct
    result = []
    for r in pattern:
        result.append(rails[r].pop(0))
    return ''.join(result)


# ----------------- KEYED TRANSPOSITION (Columnar) -----------------
def _column_order_from_key(key):
    """Return order of columns by sorting key letters; repeated letters handled left-to-right."""
    key_letters = [c for c in key if c.isalpha()]
    enumerated = list(enumerate(key_letters))
    # sort by letter then by original index to make ordering stable for duplicates
    sorted_enum = sorted(enumerated, key=lambda x: (x[1].upper(), x[0]))
    order = [None] * len(key_letters)
    for new_pos, (orig_index, _) in enumerate(sorted_enum):
        order[orig_index] = new_pos
    return order


def keyed_columnar_encrypt(plaintext, key):
    if len(key.strip()) == 0:
        raise ValueError("Key must be non-empty")
    cols = len([c for c in key if c.isalpha()])
    if cols == 0:
        raise ValueError("Key must contain alphabetic characters")
    # build matrix row-wise including all characters (so non-alpha included)
    rows = ceil(len(plaintext) / cols)
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(plaintext):
                matrix[r][c] = plaintext[idx]
                idx += 1
            else:
                matrix[r][c] = ''
    order = _column_order_from_key(key)
    # read columns in increasing order index
    result = []
    for read_pos in range(cols):
        # find which original column has order == read_pos
        orig_col = order.index(read_pos)
        for r in range(rows):
            if matrix[r][orig_col] != '':
                result.append(matrix[r][orig_col])
    return ''.join(result)


def keyed_columnar_decrypt(ciphertext, key):
    if len(key.strip()) == 0:
        raise ValueError("Key must be non-empty")
    cols = len([c for c in key if c.isalpha()])
    rows = ceil(len(ciphertext) / cols)
    order = _column_order_from_key(key)
    # determine number of full cells in each column
    base = len(ciphertext) // cols
    extra = len(ciphertext) % cols
    col_counts = []
    # columns will be filled in sorted order
    for read_pos in range(cols):
        orig_col = order.index(read_pos)
        cnt = base + (1 if orig_col < extra else 0)
        col_counts.append((orig_col, cnt))
    # Create empty column lists
    columns = {i: [] for i in range(cols)}
    idx = 0
    # Fill columns by reading ciphertext sequentially according to sorted order
    for read_pos in range(cols):
        orig_col, cnt = col_counts[read_pos]
        columns[orig_col] = list(ciphertext[idx:idx + cnt])
        idx += cnt
    # Reconstruct row-wise
    result = []
    for r in range(rows):
        for c in range(cols):
            if columns[c]:
                result.append(columns[c].pop(0))
    return ''.join(result)


# ----------------- COMBINATION & DOUBLE TRANSPOSITION -----------------
def combination_transposition_encrypt(plaintext, key):
    """Apply keyed columnar, then rail-fence (keyless)."""
    first = keyed_columnar_encrypt(plaintext, key)
    second = rail_fence_encrypt(first, depth=3)
    return second


def double_transposition_encrypt(plaintext, key1, key2):
    """Apply keyed columnar with key1, then keyed columnar with key2."""
    first = keyed_columnar_encrypt(plaintext, key1)
    second = keyed_columnar_encrypt(first, key2)
    return second


def double_transposition_decrypt(ciphertext, key1, key2):
    """Decrypt double transposition: reverse keyed with key2, then keyed with key1."""
    first = keyed_columnar_decrypt(ciphertext, key2)
    second = keyed_columnar_decrypt(first, key1)
    return second


# ----------------- CLI -----------------
def main():
    MENU = """
Encryption Tool - Select Cipher:
0) Exit
1) Additive (Caesar)
2) Multiplicative
3) Affine
4) Monoalphabetic Substitution
5) Autokey
6) Vigenere
7) Playfair
8) Rail-Fence (Keyless Transposition)
9) Keyed Columnar Transposition
10) Combination (Keyed + Rail Fence)
11) Double Transposition (Keyed x2)
"""
    while True:
        print(MENU)
        try:
            choice = int(input("Select Cipher (0-11): ").strip())
        except ValueError:
            print("Please enter a number.")
            continue
        if choice == 0:
            print("Goodbye.")
            break
        text = input("Enter text: ")
        if choice == 1:
            try:
                key = int(input("Enter integer key: "))
            except ValueError:
                print("Invalid integer key.")
                continue
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", additive_encrypt(text, key))
            else:
                print("Result:", additive_decrypt(text, key))
        elif choice == 2:
            try:
                key = int(input("Enter integer key coprime with 26: "))
            except ValueError:
                print("Invalid integer key.")
                continue
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", multiplicative_encrypt(text, key))
            else:
                print("Result:", multiplicative_decrypt(text, key))
        elif choice == 3:
            try:
                a = int(input("Enter a (coprime with 26): "))
                b = int(input("Enter b (integer): "))
            except ValueError:
                print("Invalid integers.")
                continue
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", affine_encrypt(text, a, b))
            else:
                print("Result:", affine_decrypt(text, a, b))
        elif choice == 4:
            key = input("Enter 26-letter key (A-Z, permutation): ").strip().upper()
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            try:
                if mode == 'E':
                    print("Result:", monoalphabetic_encrypt(text, key))
                else:
                    print("Result:", monoalphabetic_decrypt(text, key))
            except ValueError as e:
                print("Error:", e)
        elif choice == 5:
            keyword = input("Enter keyword: ").strip()
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", autokey_encrypt(text, keyword))
            else:
                print("Result:", autokey_decrypt(text, keyword))
        elif choice == 6:
            keyword = input("Enter keyword: ").strip()
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", vigenere_encrypt(text, keyword))
            else:
                print("Result:", vigenere_decrypt(text, keyword))
        elif choice == 7:
            keyword = input("Enter keyword: ").strip()
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", playfair_encrypt(text, keyword))
            else:
                print("Result:", playfair_decrypt(text, keyword))
        elif choice == 8:
            try:
                depth = int(input("Enter rail depth (default 3): ") or "3")
            except ValueError:
                print("Invalid depth")
                continue
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", rail_fence_encrypt(text, depth=depth))
            else:
                print("Result:", rail_fence_decrypt(text, depth=depth))
        elif choice == 9:
            key = input("Enter key (word): ").strip()
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            try:
                if mode == 'E':
                    print("Result:", keyed_columnar_encrypt(text, key))
                else:
                    print("Result:", keyed_columnar_decrypt(text, key))
            except ValueError as e:
                print("Error:", e)
        elif choice == 10:
            key = input("Enter key (word): ").strip()
            print("Result:", combination_transposition_encrypt(text, key))
        elif choice == 11:
          key1 = input("Enter first key: ").strip()
            key2 = input("Enter second key: ").strip()
            mode = input("Encrypt(E) or Decrypt(D)? ").strip().upper()
            if mode == 'E':
                print("Result:", double_transposition_encrypt(text, key1, key2))
            else:
                try:
                    print("Result:", double_transposition_decrypt(text, key1, key2))
                except Exception as e:
                    print("Error during decryption:", e)
        else:
            print("Invalid choice. Pick 0-11.")


if _name_ == "_main_":
    main()
