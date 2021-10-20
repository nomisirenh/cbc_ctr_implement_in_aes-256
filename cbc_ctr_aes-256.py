from typing import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Util import Counter
from time import time

#convert the bit plaintext into block of 128, the function take in argument the bitstream reversed.
#so i can add padding to the begining more easily
def convert_block_of_128_bit(plaintext):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    
    return blocks

def byte_xor(byte1, byte2):
    return bytes([ a ^  b for  a,  b in zip(byte1, byte2)])

def encrypt_with_cbc(plaintext, cipher, iv):
    blocks = convert_block_of_128_bit(plaintext)
    cipher_text = bytes()

    c = iv
    for i in range(len(blocks)):
        xor = byte_xor(blocks[i], c)
        c = cipher.encrypt(xor)
        cipher_text += c

    return cipher_text

def decrypt_with_cbc(cipher_text, cipher, iv):
    blocks = convert_block_of_128_bit(cipher_text)
    #blocks = cipher_text
    decrypt_text = bytes()

    b = iv
    for i in range(len(blocks)):
        d = cipher.decrypt(blocks[i])
        xor = byte_xor(d, b)
        b = blocks[i]
        decrypt_text += xor

    return unpad(decrypt_text, 16).decode('utf-8')  

def encrypt_with_ctr(plaintext, cipher, iv):
    blocks = convert_block_of_128_bit(plaintext)
    cipher_text = bytes()

    for i in range(len(blocks)):
        if i == 0:
            c = cipher.encrypt(iv)
        else:
            c = cipher.encrypt((int.from_bytes(iv, 'big') + i).to_bytes(16, 'big'))

        xor = byte_xor(blocks[i], c)
        cipher_text += xor
    
    return cipher_text

def decrypt_with_ctr(cipher_text, cipher, iv):
    blocks = convert_block_of_128_bit(cipher_text)
    #blocks = cipher_text
    decrypt_text = bytes()

    for i in range(len(blocks)):
        if i == 0:
            c = cipher.encrypt(iv)
        else:
            c = cipher.encrypt((int.from_bytes(iv, 'big') + i).to_bytes(16, 'big'))

        xor = byte_xor(blocks[i], c)
        decrypt_text += xor
    
    return unpad(decrypt_text, 16).decode('utf-8')

def main():
    #key = get_random_bytes(32)
    key = b'\xc9s\x89@\t\x0f\xdd\x9b\x88\xbd\x9b\xa8\xd9\x99\x8a\x87(\xf1e]5\xdbj\xe6\n\xf1!e\x9f\x06\xb8\xe5'

    plaintext = None
    with open("plaintext.txt", 'r') as p:
        plaintext = p.read()

    #plaintext = "Very cool and very long plaintext to be encrypted, wow such a cool plaintext".encode("UTF-8")
    plaintext = pad(plaintext.encode("utf-8"), 16)

    #iv = get_random_bytes(16)
    iv = b'>Z\x861\x18\x9ek#\xe9\xda:y\x0cu,\x1b'

    #Cipher from Crypto library
    counter = Counter.new(128,initial_value = bytes_to_long(iv))
    cipher = AES.new(key, AES.MODE_ECB)
    true_CBC_enc = AES.new(key, AES.MODE_CBC, iv)
    true_CBC_dec = AES.new(key, AES.MODE_CBC, iv)
    true_CTR_enc = AES.new(key, AES.MODE_CTR, counter=counter)
    true_CTR_dec = AES.new(key, AES.MODE_CTR, counter=counter)

    #Encrypt
    print("---------Encrypt with my CBC---------")
    start = time()
    c_text_cbc = encrypt_with_cbc(plaintext, cipher, iv)
    end = time()
    print("Time taken by MY CBC cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Encrypt with my CTR---------")
    start = time()
    c_text_ctr = encrypt_with_ctr(plaintext, cipher, iv)
    end = time()
    print("Time taken by MY CTR cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Encrypt with CTR From library---------")
    start = time()
    c_text_ctr_bis = true_CBC_enc.encrypt(plaintext)
    end = time()
    print("Time taken by the library CBC cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Encrypt with CTR From library---------")
    start = time()
    c_text_cbc_bis = true_CTR_enc.encrypt(plaintext)
    end = time()
    print("Time taken by the library CTR cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    #Decrypt
    print("---------Decrypt with my CBC---------")
    start = time()
    d_text_cbc = decrypt_with_cbc(c_text_cbc, cipher, iv)
    end = time()
    print("Time taken by MY CBC cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Decrypt with my CTR---------")
    start = time()
    d_text_ctr = decrypt_with_ctr(c_text_ctr, cipher, iv)
    end = time()
    print("Time taken by MY CTR cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Decrypt with CBC from library---------")
    start = time()
    d_text_cbc_bis = true_CBC_dec.decrypt(c_text_cbc)
    end = time()
    print("Time taken by the library CBC cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Decrypt with CTR from library---------")
    start = time()
    d_text_ctr_bis = true_CTR_dec.decrypt(c_text_ctr)
    end = time()
    print("Time taken by the library CTR cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")
    
main()