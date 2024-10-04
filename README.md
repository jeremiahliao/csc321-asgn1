# CSC321: Assignment 1

## Task 1

Usage:

`python main.py <file-path> <mode>`
 - mode is either "cbc" or "ecb"

*block_io.py*
`convert_to_blocks(file: str) -> List[bytes]`
 - takes in a file, converts it into a list of blocks of size 128 bits (16 bytes)
   - Blocks not 128 bits are padded using PKCS#7
     
`write_blocks(file: str, header: bytes, block_list: List[bytes]) -> None`
 - writes a list of blocks into a file with the appropriate header
