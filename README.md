# AES Encryption/Decryption GUI Tool

This application provides a graphical interface for encrypting and decrypting files using the Advanced Encryption Standard (AES). Designed for simplicity, it allows users to easily protect their sensitive data.

## Features

- **File Encryption**: Securely encrypt files with AES algorithm, adding a `.aes` extension.
- **File Decryption**: Decrypt files previously encrypted with AES.
- **Key Management**: Generate new AES keys or load existing ones.
- **User-friendly Interface**: Straightforward graphical interface making encryption and decryption accessible to all users.

## Code Dependencies

- Python 3.6 or later.
- PyCryptodome for cryptographic functions.
- Tkinter for the graphical interface.

## Installation

1. Python 3.6+.
2. Install the PyCryptodome package if not already installed:
    pip install pycryptodome

## How to Use

1. Start the application by navigating to the downloaded directory and running:
    python AES_Encryption_Tool.py
2. **Generate or Load a Key**:
    - Before encrypting or decrypting files, you must have an AES key. Use the "Generate Key" button to create a new one or "Load Key" to use an existing key. Remember to save the generated keys securely.
3. **Encrypting Files**:
    - Click the "Browse" button in the "File to encrypt" section to select a file.
    - Click "Encrypt" and choose where to save the encrypted file.
4. **Decrypting Files**:
    - Click the "Browse" button in the "File to decrypt" section to select an encrypted file.
    - Click "Decrypt" and choose where to save the decrypted file.
