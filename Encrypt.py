import os
import base64
import hmac
import hashlib
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def HOTP(secret, counter, digits=6):
        key = base64.b32decode(secret, True)

        #convert counter to 8 bytes
        counter_bytes = struct.pack(">Q", counter)
        # HMAC-SHA1
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

        #get the offset
        offset = hmac_hash[-1] & 0x0F

        binary = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF  #take 31-bit
        otp = binary % (10 ** digits)
        return str(otp).zfill(digits)  # make sure that the length is 6 digits

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_bytes, public_bytes

def save_key_to_file(key_bytes, filename):
    with open(filename, "wb") as f:
        f.write(key_bytes)

def load_key_from_file(filename, is_private=True):
    with open(filename, "rb") as f:
        key_bytes = f.read()
        if is_private:
            return serialization.load_pem_private_key(key_bytes, password=None)
        else:
            return serialization.load_pem_public_key(key_bytes)