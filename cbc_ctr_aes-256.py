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

def encrypt_with_cbc():
    blocks = convert_block_of_128_bit(bit_plaintext)
    cipher_text = []

    xor = format(int(blocks[0], 2) ^ int(bin_iv, 2), '0128b')
    xor_encode = xor.encode('UTF-8')
    

    c = cipher.encrypt(xor.encode('utf-8'))
    cipher_text.append(format(int.from_bytes(c, "big"), '0128b'))

    print(cipher_text)

'''
    for i in range(1, len(blocks)):
        cipher_text.append(cipher.encrypt(str(int(blocks[i]) ^ int(blocks[i - 1]))))

    return cipher_text '''

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
    bin_iv = format(int.from_bytes(iv, 'big'), '0128b')

    encrypt_with_cbc()
    