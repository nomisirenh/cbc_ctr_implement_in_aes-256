from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_ECB)
plaintext = "Very cool and very long plaintext to be encrypted, wow such a cool plaintext"

bit_plaintext = ''.join(format(ord(c), 'b') for c in plaintext)
print(bit_plaintext)
print(len(bit_plaintext))

def encrypt_with_cbc(key, plain_text):
    pass

def decrypt_with_cbc(key, cipher_text):
    pass

def encrypt_with_ctr(key, plaintext):
    pass

def decrypt_with_ctr(key, ciphertext):
    pass
