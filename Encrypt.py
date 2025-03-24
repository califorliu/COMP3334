import hmac
import hashlib
import base64
import struct


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