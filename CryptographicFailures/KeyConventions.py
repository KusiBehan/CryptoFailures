from Crypto.Random import get_random_bytes


# Einfacher key (Cryptographic Failure)
# Vorhersehbarer und schwacher Key

def predictable_key():
    return b"predictable_key_"


# Starker random Key
def strong_random_key():
    return get_random_bytes(32)  # 256-bit key for AES


if __name__ == "__main__":
    print("Einfacher Schlüssel:",predictable_key())
    print("Starker Schlüssel:",strong_random_key())