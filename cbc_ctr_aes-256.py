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

def encrypt_with_cbc(key, bit_plaintext):
    pass

def decrypt_with_cbc(key, cipher_text):
    pass

def encrypt_with_ctr(key, plaintext):
    pass

def decrypt_with_ctr(key, ciphertext):
    pass

key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_ECB)
plaintext = "Very cool and very long plaintext to be encrypted, wow such a cool plaintext"

bit_plaintext = ''.join(format(ord(c), 'b') for c in plaintext)
print(bit_plaintext)
print("----------------------")

b = convert_block_of_128_bit(bit_plaintext[::-1])

for i in range(len(b)):
    print(b[i])