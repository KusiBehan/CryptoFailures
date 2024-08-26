import hashlib


# MD5 für das Hashing (Cryptographic Failure)
# MD5 is considered broken and insecure
def insecure_hash(data):
    return hashlib.md5(data).hexdigest()


# SHA256 für das Hashing
# SHA256 ist als sicher zu gelten
def secure_hash(data):
    return hashlib.sha256(data).hexdigest()


data = b"Sensitive data that needs encryption"
print("MD5 Hash (Insecure):", insecure_hash(data))
print("SHA256 Hash (secure):", secure_hash(data))
