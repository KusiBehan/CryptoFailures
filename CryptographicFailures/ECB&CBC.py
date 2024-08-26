import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from KeyConventions import predictable_key


# Using ECB mode for AES encryption (Cryptographic Failure)
def encrypt_ecb_mode(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_ecb_mode(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted


# Using CBC mode für AES encryption (Cryptographic Failure)
def encrypt_cbc_mode(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')


def decrypt_cbc_mode(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted


data = b"Sensitive data that needs encryption"
key = predictable_key()

encrypted_data = encrypt_ecb_mode(data, key)
print("Encrypted with ECB (Insecure):", encrypted_data)
decrypted_data = decrypt_ecb_mode(encrypted_data, key)
print("Decrypted Data:", decrypted_data.decode('utf-8'))

encrypted_data = encrypt_cbc_mode(data, key)
print("Encrypted with ECB (Secure):", encrypted_data)
decrypted_data = decrypt_cbc_mode(encrypted_data, key)
print("Decrypted Data:", decrypted_data.decode('utf-8'))
