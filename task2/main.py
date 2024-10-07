import cbc
from Crypto.Cipher import AES
import os

BLOCK_SIZE = 16
key = os.urandom(32)
iv = os.urandom(BLOCK_SIZE)
cipher = AES.new(key, AES.MODE_ECB)

def submit(user_input: str) -> bytes:
    res = "userid=456;userdata=" + user_input + ";session-id=31337"
    res = res.replace(';', '%3B')
    res = res.replace('=', '%3D')
    res_bytes = bytes(res, 'utf-8')
    print("plaintext:", res_bytes)

    res_bytes = pad(res_bytes)

    # get block list
    block_list = []
    for i in range(0, len(res_bytes), BLOCK_SIZE):
        block_list.append(res_bytes[i:i + BLOCK_SIZE])
    # encrypt
    encrypted = cbc.encrypt(block_list, cipher, iv)
    return b''.join(encrypted)


def verify(encrypted: bytes) -> bool:
    block_list = [encrypted[i:i + BLOCK_SIZE] for i in range(0, len(encrypted), BLOCK_SIZE)]
    decrypted_blocks = cbc.decrypt(block_list, cipher, iv)
    decrypted = b''.join(decrypted_blocks)
    decrypted_unpad = unpad(decrypted)
    if b';admin=true;' in decrypted_unpad:
        return True
    return False


def pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding] * padding)


def unpad(data: bytes) -> bytes:
    padding = data[-1]
    if padding < BLOCK_SIZE:
        return data[:-padding]
    return data


if __name__ == '__main__':
    # padding so that our tampering allows us to just change 1 block
    user_data = "      @admin$true*"
    ciphertext = submit(user_data)
    print("ciphertext:", ciphertext)
    is_admin = verify(ciphertext)

    # should be false
    print("Is admin:", is_admin)

    # target locations: 32, 38, 43
    # tampering locations in ctxt : 16, 22, 27
    one = ord('@') ^ ord(';')
    two = ord('$') ^ ord('=')
    three = ord('*') ^ ord(';')

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[16] ^= one
    tampered_ciphertext[22] ^= two
    tampered_ciphertext[27] ^= three

    print("tampered ciphertext: ", tampered_ciphertext)

    is_admin_after_attack = verify(tampered_ciphertext)
    # should be true
    print("Is admin (after attack):", is_admin_after_attack)
