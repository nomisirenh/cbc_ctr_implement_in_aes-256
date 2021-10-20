from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

#convert the bit plaintext into block of 128, the function take in argument the bitstream reversed.
#so i can add padding to the begining more easily
def convert_block_of_128_bit(plaintext):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    
    return blocks

def byte_xor(byte1, byte2):
    return bytes([ a ^  b for  a,  b in zip(byte1, byte2)])

def encrypt_with_cbc(plaintext, cipher, iv):
    blocks = convert_block_of_128_bit(plaintext)
    cipher_text = []

    c = iv
    for i in range(len(blocks)):
        xor = byte_xor(blocks[i], c)
        c = cipher.encrypt(xor)
        cipher_text.append(c)

    return cipher_text

def decrypt_with_cbc(cipher_text, cipher, iv):
    #blocks = convert_block_of_128_bit(cipher_text)
    blocks = cipher_text
    decrypt_text = []

    b = iv
    for i in range(len(blocks)):
        d = cipher.decrypt(blocks[i])
        xor = byte_xor(d, b)
        b = blocks[i]
        decrypt_text.append(xor)

    return decrypt_text  

def encrypt_with_ctr(key, plaintext):
    pass

def decrypt_with_ctr(key, ciphertext):
    pass

def main():

    #key = get_random_bytes(32)
    key = b'\xc9s\x89@\t\x0f\xdd\x9b\x88\xbd\x9b\xa8\xd9\x99\x8a\x87(\xf1e]5\xdbj\xe6\n\xf1!e\x9f\x06\xb8\xe5'
    cipher = AES.new(key, AES.MODE_ECB)
    

    plaintext = "Very cool and very long plaintext to be encrypted, wow such a cool plaintext".encode("UTF-8")
    plaintext = pad(plaintext, 16)

    #iv = get_random_bytes(16)
    iv = b'>Z\x861\x18\x9ek#\xe9\xda:y\x0cu,\x1b'

    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    test = cipher2.encrypt(plaintext)
    #print(test)
    print(" ")

    c_text = encrypt_with_cbc(plaintext, cipher, iv)
    d_text = decrypt_with_cbc(c_text, cipher, iv)
    

    for c in c_text:
        print(c)
    
    print(" ")

    for d in d_text:
        print(d)

main()