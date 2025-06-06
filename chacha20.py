from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os

# Encrypt a message using ChaCha20
def encrypt_chacha20(key, nonce, plaintext):
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)

# Decrypt the ciphertext
def decrypt_chacha20(key, nonce, ciphertext):
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

if __name__ == "__main__":
    # Generate key and nonce
    key = os.urandom(32)   # 256-bit key
    nonce = os.urandom(16) # 128-bit nonce (required size for ChaCha20)

    # Message to encrypt
    plaintext = b"Fuck you"

    # Encrypt
    ciphertext = encrypt_chacha20(key, nonce, plaintext)
    print("Encrypted (hex):", ciphertext.hex())

    # Decrypt
    decrypted = decrypt_chacha20(key, nonce, ciphertext)
    print("Decrypted:", decrypted.decode('utf-8'))
