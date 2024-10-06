import urllib.parse
import cbc
from Crypto.Cipher import AES
from Crypto import Random
import os
import urllib.parse

BLOCK_SIZE = 16
key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)

def submit(user_input: str) -> bytes:
    res = "userid=456; userdata=" + user_input + ";session-id=31337"
    url_encode = urllib.parse.quote(res, ' /')
    res_bytes = bytes(url_encode, 'utf-8')
    padding = 16 - (len(res_bytes) % 16)
    print(padding)
    for i in range(padding):
        res_bytes += bytes([padding])
    # get block list
    block_list = []
    for i in range(int(len(res_bytes)/16)):
        block_list.append(res_bytes[i*16:i*16+16])
    # encrypt
    key = Random.get_random_bytes(32)
    iv = Random.get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cbc.encrypt(block_list, cipher, iv)
    return b''.join(encrypted)

def verify(ciphertext: bytes) -> bool:
    block_list = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_blocks = cbc.decrypt(block_list, cipher, iv)
    decrypted = b''.join(decrypted_blocks)
    try:
        decrypted = unpad(decrypted).decode('utf-8')
    except ValueError:
        return False

    if ";admin=true;" in decrypted:
        return True
    return False

def pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding] * padding)

def unpad(data: bytes) -> bytes:
    padding = data[-1]
    return data[:-padding]

def xor(block: bytes, previous: bytes) -> bytes:
    result = []
    for i in range(len(block)):
        result.append(block[i] ^ previous[i])
    return bytes(result)

def bitflip_attack(ciphertext: bytes) -> bytes:
    # tried using xor helper function to swap per block
    # goal of this was to swap the userid portion of the string to ";admin=true;"
    flipped = bytearray(ciphertext)
    flipped[16 + 0] ^= ord('u') ^ ord(';')
    flipped[16 + 1] ^= ord('s') ^ ord('a')
    flipped[16 + 2] ^= ord('e') ^ ord('d')
    flipped[16 + 3] ^= ord('r') ^ ord('m')
    flipped[16 + 4] ^= ord('i') ^ ord('i')
    flipped[16 + 5] ^= ord('d') ^ ord('n')
    flipped[16 + 6] ^= ord('=') ^ ord('=')
    flipped[16 + 7] ^= ord('4') ^ ord('t')
    flipped[16 + 8] ^= ord('5') ^ ord('r')
    flipped[16 + 9] ^= ord('6') ^ ord('u')
    flipped[16 + 10] ^= ord(';') ^ ord('e')
    flipped[16 + 11] ^= ord('u') ^ ord(';')
    return bytes(flipped)

if __name__ == '__main__':
    #     user_input = input()
    #     submit(user_input)
    user_data = "You're the man now, dog"
    ciphertext = submit(user_data)
    print("ciphertext:", ciphertext)
    is_admin = verify(ciphertext)

    # should be false
    print("Is admin:", is_admin)
    tampered_ciphertext = bitflip_attack(ciphertext)

    is_admin_after_attack = verify(tampered_ciphertext)
    # should be true
    print("Is admin (after attack):", is_admin_after_attack)

