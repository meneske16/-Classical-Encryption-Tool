# 🔐 Classical Encryption Toolkit – Python

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python\&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green) ![No Dependencies](https://img.shields.io/badge/Dependencies-None-lightgrey)

A **Python-based multi-cipher encryption and decryption toolkit** for classical cryptography, built entirely from scratch.

> **No external dependencies** — fully implemented using Python’s standard library.

---

## ✨ Features

Includes **11 classical ciphers**, all supporting encryption & decryption with:

* ✅ Case preservation
* ✅ Non-alphabet character handling
* ✅ Custom keys

| Cipher                             | Type                                     |
| ---------------------------------- | ---------------------------------------- |
| Additive (Caesar) Cipher           | Shift-based                              |
| Multiplicative Cipher              | Modular arithmetic                       |
| Affine Cipher                      | Combination of additive & multiplicative |
| Monoalphabetic Substitution Cipher | Custom mapping                           |
| Autokey Cipher                     | Key-stream based                         |
| Vigenère Cipher                    | Repeating key stream                     |
| Playfair Cipher                    | 5×5 matrix, J→I mapping                  |
| Rail-Fence Transposition           | Keyless zigzag pattern                   |
| Keyed Columnar Transposition       | Columnar permutation                     |
| Combination Transposition          | Keyed + Rail-Fence                       |
| Double Transposition               | Two separate keys                        |

---

## 🛠 How It Works

Run the script and interact via **menu-driven CLI**:

```bash
python encryption_tool.py
```

**Example session:**

```text
🔹 Select Cipher:
1. Additive (Caesar)
2. Multiplicative
3. Affine
...
Enter your choice: 1

Enter plaintext: HELLO WORLD
Enter key (numeric): 3
Encrypted text: KHOOR ZRUOG
```

**Decryption is equally simple:**

```text
Enter ciphertext: KHOOR ZRUOG
Enter key (numeric): 3
Decrypted text: HELLO WORLD
```

> The interface automatically handles upper/lowercase, spaces, and punctuation.

---

## 📄 Project Files

| File                 | Description                          |
| -------------------- | ------------------------------------ |
| `encryption_tool.py` | Main CLI program with all 11 ciphers |
| `README.md`          | Full project overview & usage        |
| `.gitignore`         | Standard Python ignores              |
| `LICENSE`            | MIT License                          |
| `requirements.txt`   | No external libraries needed         |

---

## 📌 Example Outputs

All example encryptions & decryptions are included from the submitted assignment PDF.

> Use these examples to verify correctness of each cipher.

---

## 🎯 Purpose

This project demonstrates:

* ✅ Mastery of **classical encryption algorithms**
* ✅ Python **string manipulation & modular arithmetic**
* ✅ **Key-stream generation** and **matrix-based transpositions**
* ✅ **Secure coding of historical ciphers** in a modular CLI tool

---

## 🚀 Getting Started

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/classical-encryption-tool.git
cd classical-encryption-tool
```

2. Run the tool:

```bash
python encryption_tool.py
```

3. Follow the prompts to encrypt/decrypt using **any of the 11 ciphers**.

---

## 💡 Tips

* For Playfair cipher, **J is replaced by I** automatically.
* Rail-Fence transposition requires **no key**, while columnar and double transpositions do.
* Supports **custom keys**, including numeric and word-based keys.

---

## 🏆 Contribution & License

This project is licensed under the **MIT License**. Contributions are welcome — feel free to fork and experiment.

![MIT](https://img.shields.io/badge/License-MIT-green)

---


