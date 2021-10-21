from typing import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Util import Counter
from time import time

#convert the bit plaintext into block of 128, so 16 bytes
def convert_block_of_128_bit(plaintext):
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    
    return blocks

#for XORed two bytes, i found this function here https://nitratine.net/blog/post/xor-python-byte-strings/ 
def byte_xor(byte1, byte2):
    return bytes([ a ^  b for  a,  b in zip(byte1, byte2)])

def encrypt_with_cbc(plaintext, cipher, iv):                                #function for encrypt with CBC mode
    blocks = convert_block_of_128_bit(plaintext)                                #convert into blocks of 16 bytes
    cipher_text = bytes()                                                       #initialize the variable to return, in byte()

    c = iv                                                      
    for i in range(len(blocks)):                
        xor = byte_xor(blocks[i], c)                                             #xor between the blocks and, the iv in the first round, the previous ciphered block for the other rounds
        c = cipher.encrypt(xor)                                                  #Encrypt with AES-ECB
        cipher_text += c                                                         #Append each block

    return cipher_text

def decrypt_with_cbc(cipher_text, cipher, iv):                              #function for decrypt with CBC mode
    blocks = convert_block_of_128_bit(cipher_text)              
    decrypt_text = bytes()                                      

    b = iv
    for i in range(len(blocks)):
        d = cipher.decrypt(blocks[i])                                           #Decrypt the block with AES-ECB
        xor = byte_xor(d, b)                                                    #Xor between each decrypt blocks and, the iv in the first round, the previous decrypted block for the other rounds
        b = blocks[i]                                           
        decrypt_text += xor                                                     #Append each block

    return unpad(decrypt_text, 16).decode('utf-8')                              #Return an unpaded and decoded plaintext, a String

def encrypt_with_ctr(plaintext, cipher, iv):                                #function for encrypt with CTR mode
    blocks = convert_block_of_128_bit(plaintext)                
    cipher_text = bytes()                                       

    for i in range(len(blocks)):          
        if i == 0:
            c = cipher.encrypt(iv)                                              #For the first round, encrypt just the IV with AES-ECB
        else:
            c = cipher.encrypt((int.from_bytes(iv, 'big') + i).to_bytes(16, 'big'))     #For the other rounds, I encrypt the IV + the index number of the round

        xor = byte_xor(blocks[i], c)                                            #xor the bit and the IV 
        cipher_text += xor                                                      
    
    return cipher_text

def decrypt_with_ctr(cipher_text, cipher, iv):                              #function for decrypt with CTR mode
    blocks = convert_block_of_128_bit(cipher_text)            
    decrypt_text = bytes()

    for i in range(len(blocks)):
        if i == 0:
            c = cipher.encrypt(iv)
        else:
            c = cipher.encrypt((int.from_bytes(iv, 'big') + i).to_bytes(16, 'big'))

        xor = byte_xor(blocks[i], c)                                            #The only difference with the encryption is that we XOR the cipher block and not the plain text block
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

    with open("my_cbc_encrypt.txt", "wb") as f:
        f.write(c_text_cbc)
        print("> Cipher text wirten into --> my_cbc_encrypt.txt")
    print("> Time taken by MY CBC cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Encrypt with my CTR---------")
    start = time()
    c_text_ctr = encrypt_with_ctr(plaintext, cipher, iv)
    end = time()

    with open("my_ctr_encrypt.txt", "wb") as f:
        f.write(c_text_ctr)
        print("> Cipher text wirten into --> my_ctr_encrypt.txt")
    print("> Time taken by MY CTR cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Encrypt with CBC From library---------")
    start = time()
    c_text_cbc_bis = true_CBC_enc.encrypt(plaintext)
    end = time()

    with open("library_cbc_encrypt.txt", "wb") as f:
        f.write(c_text_cbc_bis)
        print("> Cipher text wirten into --> library_cbc_encrypt.txt")
    print("> Time taken by the library CBC cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Encrypt with CTR From library---------")
    start = time()
    c_text_ctr_bis = true_CTR_enc.encrypt(plaintext)
    end = time()

    with open("library_ctr_encrypt.txt", "wb") as f:
        f.write(c_text_ctr_bis)
        print("> Cipher text wirten into --> library_ctr_encrypt.txt")
    print("> Time taken by the library CTR cipher for the ENCRYTPION: " + str(end - start) + " seconds")
    print(" ")

    #Decrypt
    print("---------Decrypt with my CBC---------")
    start = time()
    d_text_cbc = decrypt_with_cbc(c_text_cbc, cipher, iv)
    end = time()

    with open("my_cbc_decrypt.txt", "w") as f:
        f.write(d_text_cbc)
        print("> Plain text wirten into --> my_cbc_decrypt.txt")
    print("> Time taken by MY CBC cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Decrypt with my CTR---------")
    start = time()
    d_text_ctr = decrypt_with_ctr(c_text_ctr, cipher, iv)
    end = time()

    with open("my_ctr_decrypt.txt", "w") as f:
        f.write(d_text_ctr)
        print("> Plain text wirten into --> my_ctr_decrypt.txt")
    print("> Time taken by MY CTR cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Decrypt with CBC from library---------")
    start = time()
    d_text_cbc_bis = true_CBC_dec.decrypt(c_text_cbc)
    end = time()

    with open("library_cbc_decrypt.txt", "w") as f:
        f.write(unpad(d_text_cbc_bis, 16).decode('utf-8'))
        print("> Plain text wirten into --> library_cbc_decrypt.txt")

    print("> Time taken by the library CBC cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")

    print("---------Decrypt with CTR from library---------")
    start = time()
    d_text_ctr_bis = true_CTR_dec.decrypt(c_text_ctr)
    end = time()

    with open("library_ctr_decrypt.txt", "w") as f:
        f.write(unpad(d_text_ctr_bis, 16).decode('utf-8'))
        print("> Plain text wirten into --> library_ctr_decrypt.txt")
    print("> Time taken by the library CTR cipher for the DECRYTPION: " + str(end - start) + " seconds")
    print(" ")
    
main()