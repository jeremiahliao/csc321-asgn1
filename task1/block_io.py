from typing import List

BLOCK_SIZE = 16


def convert_to_blocks(file: str) -> List[bytes]:
    block_list = []
    with open(file, 'rb') as f:
        header = f.read(54)
        block_list.append(header)

        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            if len(block) < BLOCK_SIZE:  # add padding - should only be needed when encrypting
                pad_size = BLOCK_SIZE - len(block)
                for i in range(pad_size):
                    block += bytes([pad_size])
                block_list.append(block)
            else:
                block_list.append(block)
    return block_list


def write_blocks(file: str, header: bytes, block_list: List[bytes]) -> None:
    with open(file, 'wb') as f:
        f.write(header)
        for block in block_list:
            f.write(block)
