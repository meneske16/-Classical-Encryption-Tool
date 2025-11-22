Development of Encryption Tool

This repository contains a Python-based encryption tool implementing several classical ciphers:
- Additive (Caesar)
- Multiplicative
- Affine
- Monoalphabetic substitution
- Autokey
- Vigenere
- Playfair
- Rail-Fence (keyless transposition)
- Keyed Columnar transposition
- Combination (keyed columnar + rail-fence)
- Double transposition (two keyed columnar passes)

This project implementation and test vectors are derived from the assignment PDF submitted for the CS-375 Information Security course. (Original PDF used as source included in the submission.) 1

## Files
- encryption_tool.py — main script (CLI)
- README.md — this file
- LICENSE — MIT
- .gitignore — Python ignores
- requirements.txt — (none required; runs with standard library)

## Usage
Make the script executable and run:
```bash
python3 encryption_tool.py

Follow the interactive menu to choose cipher, provide keys and text, and get results.

Quick tests (expected outputs from assignment)

(These examples match the expected outputs recorded in the assignment PDF.)

1. Additive (Caesar)



Plaintext: Aleena
Key: 9
Encrypt -> junnwj
Decrypt -> aleena

2. Multiplicative



Plaintext: minahil
Key: 9
Encrypt -> eunaluv
Decrypt -> minahil

3. Affine (a=9, b=9)



Plaintext: Aleena
Encrypt -> jettwj
Decrypt -> aleena

4. Monoalphabetic substitution (key=qwertyuiopasdfghjklzxcvbnm)



Plaintext: minahil
Encrypt -> dofqios
Decrypt -> minahil

5. Autokey



Plaintext: Aleena
Key: sehar
Encrypt -> spleea
Decrypt -> aleena

6. Vigenere



Plaintext: minahil
Key: nadeem
Encrypt -> ziqeluy
Decrypt -> minahil

7. Playfair



Plaintext: Aleena
Key: sehar
Encrypt -> hmhwrk
Decrypt -> alexen (assignment's expected "alexen")

8. Rail-Fence (depth=2)



Plaintext: Minahil
Encrypt -> mnhliai
Decrypt -> minahil

9. Keyed Columnar (key=sehar)



Plaintext: Aleena
Encrypt -> elenaa
Decrypt -> Aleena

10. Combination (keyed + rail)



Plaintext: Aleena
Key: sehar
Encrypt -> ealnae
Decrypt -> aleena

11. Double Transposition (example in assignment)



Plaintext: HELLO
Keys: KEY1, KEY2
Encrypt -> LOHEL
Decrypt -> HELLO

> Note: Playfair and transposition variants depend on implementation details (J/I handling, filler letter, handling of non-alpha). The code follows the assignment's approach.
