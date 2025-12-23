import hashlib
import Crypto.Cipher.DES as DES

class OldCrypto:
    def hash_data(self, data):
        # Using SHA1 - deprecated!
        return hashlib.sha1(data).hexdigest()
    
    def encrypt_legacy(self, plaintext, key):
        # Using DES encryption - OBSOLETE!
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(plaintext)
    
    def weak_aes(self, data):
        # Using AES-128 instead of AES-256
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)
