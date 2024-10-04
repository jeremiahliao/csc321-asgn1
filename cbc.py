from typing import List
from Crypto.Cipher._mode_ecb import EcbMode


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
