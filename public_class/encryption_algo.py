import hashlib
import os
import cryptography
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def skc_generatekey():
    key1 = os.urandom(32)
    iv = os.urandom(16)
    encoded_key = key1.hex()
    encoded_iv = iv.hex()
    return encoded_key,encoded_iv

def skc_padding(data):
    pad_len = 16 - len(data) % 16
    padding = bytes([pad_len] * pad_len)
    return data + padding

def skc_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def skc_encrypt(input_file,output_file,key,iv):
    key_bytes = bytes.fromhex(key)
    iv_bytes = bytes.fromhex(iv)
    cipher = Cipher(AES256(key_bytes), modes.CBC(iv_bytes))
    encryptor = cipher.encryptor()
    try:
        with open(input_file, 'rb') as f:
            pt = f.read()
        padded_pt = skc_padding(pt)
        ct = encryptor.update(padded_pt) + encryptor.finalize()
        with open(output_file, 'wb') as f:
            f.write(ct)
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None, None


def skc_decrypt(input_file,output_file,key,iv):
    try:
        key_bytes = bytes.fromhex(key)
        iv_bytes = bytes.fromhex(iv)
        if len(key_bytes) != 32:
            raise ValueError("Incorrect AES key length")
        cipher = Cipher(AES256(key_bytes), modes.CBC(iv_bytes))
        decryptor = cipher.decryptor()
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = skc_unpad(decryptor.update(encrypted_data) + decryptor.finalize())
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
    except Exception as e:
        print(f"An error occurred during decryption: {e}")

def pkc_generatekey():
    # """Generate RSA key pair (client-side implementation)"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def pkc_encrypt(data: bytes, public_key) -> bytes:
    # """Encrypt data with public key (client-side)"""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def pkc_decrypt(encrypted_data: bytes, private_key) -> bytes:
    # """Decrypt data with private key (client-side)"""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def save_key_to_file(key, filename):
    key_bytes = bytes.fromhex(key)
    with open(filename, "wb") as f:
        f.write(key_bytes)

def save_iv_to_file(iv, filename):
    iv_bytes = bytes.fromhex(iv)
    with open(filename, "wb") as f:
        f.write(iv_bytes)

def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        key = f.read()
        encoded_key = key.hex()
        return encoded_key

def load_iv_from_file(filename):
    with open(filename, "rb") as f:
        iv = f.read()
        encoded_iv = iv.hex()
        return encoded_iv

"""Testing
def main():
    key, iv = skc_generatekey()
    save_iv_to_file(iv, "iv.txt")
    save_key_to_file(key,"key.txt")
    print("Key: ",load_key_from_file("key.txt"))
    print("IV: ",load_iv_from_file("iv.txt"))
    skc_encrypt("initial.txt","second.txt",load_key_from_file("key.txt"),load_iv_from_file("iv.txt"))
    skc_decrypt("second.txt", "output.txt", load_key_from_file("key.txt"), load_iv_from_file("iv.txt"))

    #placeholder

if __name__ == "__main__":
    main()

"""