from Crypto.Cipher import AES

def encrypt_aes_gcm(data, key):
    # AES-256-GCM is currently considered quantum resistant
    # Migration to ML-KEM recommended for asymmetric parts
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext
