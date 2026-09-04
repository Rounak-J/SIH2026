import hashlib
from Crypto.PublicKey import RSA

def generate_keys():
    # RSA is vulnerable to Shor's algorithm
    key = RSA.generate(2048)
    return key

def hash_data(data):
    # MD5 is weak against collision attacks
    return hashlib.md5(data.encode()).hexdigest()
