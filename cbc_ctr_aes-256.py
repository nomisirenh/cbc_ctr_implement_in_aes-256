from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#convert the bit plaintext into block of 128, the function take in argument the bitstream reversed.
#so i can add padding to the begining more easily
def convert_block_of_128_bit(bit_plaintext):
    blocks = [bit_plaintext[i:i+128] for i in range(0, len(bit_plaintext), 128)]
    blocks.reverse()                    
    blocks_inverse = []
    for b in range(len(blocks)):
        blocks_inverse.append(format(int(blocks[b][::-1],2), '0128b'))
    
    return blocks_inverse

def byte_xor(byte1, byte2):
    return bytes([ a ^  b for  a,  b in zip(byte1, byte2)])

def encrypt_with_cbc():
    blocks = convert_block_of_128_bit(bit_plaintext)
    cipher_text = []

    for i in range(len(blocks)):
        if i == 0:
            xor = byte_xor(blocks[0].encode('UTF-8'), iv)
            c = cipher.encrypt(xor)
            print(len(c))
            cipher_text.append(c)

        else:
            xor = byte_xor(blocks[i].encode('UTF-8'), bytes(blocks[i - 1], 'UTF-8'))
            print(xor)
            c = cipher.encrypt(xor)
            print(len(c))
            cipher_text.append(c)

    return cipher_text

def decrypt_with_cbc(key, cipher_text):
    pass

def encrypt_with_ctr(key, plaintext):
    pass

def decrypt_with_ctr(key, ciphertext):
    pass

if __name__ == '__main__':

    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_ECB)
    

    plaintext = "Very cool and very long plaintext to be encrypted, wow such a cool plaintext"
    bit_plaintext = ''.join(format(ord(c), 'b') for c in plaintext)

    block_size = 128
    iv = get_random_bytes(int(block_size/8))

    c_text = encrypt_with_cbc()

    '''
    for c in c_text:
        print(c)
        print("")
    '''