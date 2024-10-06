from typing import List
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher import AES
import os
import urllib.parse

BLOCK_SIZE = 16


# blocks pasted in does not include header
# block size and iv are both 16 bytes
def encrypt(blocks: List[bytes], cipher: EcbMode, iv: bytes) -> List[bytes]:
    encrypted_blocks = []
    prev_block = iv

    for block in blocks:
        xor = bytes([b_byte ^ p_byte for b_byte, p_byte in zip(block, prev_block)])
        encrypted = cipher.encrypt(xor)
        encrypted_blocks.append(encrypted)
        prev_block = encrypted

    return encrypted_blocks


def decrypt(blocks: List[bytes], cipher: EcbMode, iv: bytes) -> List[bytes]:
    decrypted_blocks = []
    prev_block = iv

    for block in blocks:
        decrypted = cipher.decrypt(block)
        xor = bytes([b_byte ^ p_byte for b_byte, p_byte in zip(decrypted, prev_block)])
        decrypted_blocks.append(xor)
        prev_block = block

    return decrypted_blocks

def pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding] * padding)

def unpad(data: bytes) -> bytes:
    padding = data[-1]
    return data[:-padding]

def submit(input: str, key: bytes, iv: bytes) -> bytes:
    encoded_input = urllib.parse.quote(input, safe='')
    string = f"userid=456;userdata={encoded_input};session-id=31337"
    pad_string = pad(string.encode())
    blocks = [pad_string[i:i+BLOCK_SIZE] for i in range(0, len(pad_string), BLOCK_SIZE)]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_blocks = encrypt(blocks, cipher, iv)
    return b''.join(encrypted_blocks)

def verify(ciphertext: bytes, key: bytes, iv: bytes) -> bool:
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_blocks = decrypt(blocks, cipher, iv)
    decrypted = b''.join(decrypted_blocks)
    decrypted = unpad(decrypted).decode()
    if ";admin=true" in decrypted:
        return True
    return False

if __name__ == "__main__":
    key = os.urandom(BLOCK_SIZE)
    iv = os.urandom(BLOCK_SIZE)
    user_data = "You're the man now, dog;admin=true"
    ciphertext = submit(user_data, key, iv)
    print(ciphertext)
    cipher = verify(ciphertext, key, iv)
    print(cipher)
