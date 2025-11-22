🔐 Information Security – Classical Encryption Tool

A Python-based multi-cipher encryption and decryption toolkit

This project is an implementation of a complete classical cryptography encryption tool, developed as part of an Information Security assignment. It includes 11 traditional ciphers, each implemented from scratch using the Python standard library only — no external dependencies.

The tool provides a menu-driven CLI where users can choose a cipher, enter plaintext/ciphertext, provide necessary keys, and obtain results instantly.


---

✨ Features

✔ Additive (Caesar) Cipher
✔ Multiplicative Cipher
✔ Affine Cipher
✔ Monoalphabetic Substitution Cipher
✔ Autokey Cipher
✔ Vigenere Cipher
✔ Playfair Cipher (5×5, J→I mapping)
✔ Rail-Fence Transposition (Keyless)
✔ Keyed Columnar Transposition
✔ Combination Transposition (Keyed + Rail-Fence)
✔ Double Transposition (Two different keys)

All algorithms support:

Case preservation

Non-alphabet handling

Custom keys

Both encryption & decryption where applicable



---

🛠 How It Works

Run the script and select the cipher from a numeric menu. Depending on the cipher, you’ll be asked for:

plaintext/ciphertext

encryption/decryption mode

keys (numeric or word-based)
The tool then outputs the processed text immediately.



---

📄 Files Included

encryption_tool.py — Main CLI program

README.md — Full project overview & usage

.gitignore — Standard Python ignores

LICENSE — MIT License

requirements.txt — No external libraries needed



---

📌 Example Outputs (from assignment)

The repository includes example encryptions & decryptions taken directly from the submitted assignment PDF. These help verify correctness.


---

🎯 Purpose of This Project

This tool demonstrates understanding of:

Classical encryption algorithms

Python string manipulation

Modular arithmetic

Key-stream generation

Matrix-based transpositions

Secure coding of historical ciphers


It is meant for educational use, cryptography learning, and information security coursework.


