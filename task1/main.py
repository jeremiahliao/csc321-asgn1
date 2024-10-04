import sys
from Crypto.Cipher import AES
from Crypto import Random
import block_io
import cbc
import ecb


def main():
    file_name = sys.argv[1]
    mode = sys.argv[2]  # ecb/cbc
    key = Random.get_random_bytes(32)
    iv = Random.get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    header, *body = block_io.convert_to_blocks(file_name)

    if mode == "ecb":
        encrypted_output = ecb.encrypt(body, cipher)
    else:
        encrypted_output = cbc.encrypt(body, cipher, iv)

    file_arr = file_name.split('.')
    encrypted_file_name = file_arr[0] + '_' + mode + '_encrypted' + '.' + file_arr[1]
    block_io.write_blocks(
        encrypted_file_name,
        header,
        encrypted_output
    )

    header, *body = block_io.convert_to_blocks(encrypted_file_name)

    if mode == "ecb":
        decrypted_output = ecb.decrypt(body, cipher)
    else:
        decrypted_output = cbc.decrypt(body, cipher, iv)

    file_arr = file_name.split('.')
    block_io.write_blocks(
        file_arr[0] + '_' + mode + '_decrypted' + '.' + file_arr[1],
        header,
        decrypted_output
    )


if __name__ == '__main__':
    main()
