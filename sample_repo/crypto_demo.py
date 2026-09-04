# sample_repo/crypto_demo.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# 1. High Quantum Risk: Classical Asymmetric Encryption
def generate_user_keys():
    key = RSA.generate(2048)
    return key

# 2. Quantum-Safe: Symmetric Encryption (256-bit)
def encrypt_payload(data, secret_key):
    cipher = AES.new(secret_key, AES.MODE_GCM)
    return cipher.encrypt(data)