import hashlib
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA

def hash_password(password):
    # This uses a weak, deprecated hashing algorithm
    m = hashlib.md5()
    m.update(password.encode('utf-8'))
    return m.hexdigest()

def encrypt_data(data, key):
    # This uses a weak, deprecated encryption cipher
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def generate_server_key():
    # Vulnerable asymmetric key generation
    return RSA.generate(1024)
