import urllib.parse
import cbc
from Crypto.Cipher import AES
from Crypto import Random

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
    cbc.encrypt(block_list, cipher, iv)


if __name__ == '__main__':
    user_input = input()
    submit(user_input)
