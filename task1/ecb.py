from typing import List
from Crypto.Cipher._mode_ecb import EcbMode


# blocks is a list of body blocks; does not expect header to be passed in
def encrypt(blocks: List[bytes], cipher: EcbMode) -> List[bytes]:
    # implement ECB
    encrypted_blocks = []

    for block in blocks:  # first item is header
        encrypted = cipher.encrypt(block)
        encrypted_blocks.append(encrypted)

    return encrypted_blocks


def decrypt(blocks: List[bytes], cipher: EcbMode, iv=None) -> List[bytes]:
    # implement ECB
    decrypted_blocks = []

    for block in blocks:
        decrypted = cipher.decrypt(block)
        decrypted_blocks.append(decrypted)

    return decrypted_blocks
