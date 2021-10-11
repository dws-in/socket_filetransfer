# $ python -m pip install PyCryptodome

from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import time


class AESCipher:
    def __init__(self, key):
        password = key.encode('utf-8')
        self.key = md5(password).digest()

    def encrypt(self, data):
        vector = get_random_bytes(AES.block_size)
        encryption_cipher = AES.new(self.key, AES.MODE_CBC, vector)
        return vector + encryption_cipher.encrypt(pad(data,  AES.block_size))

    def decrypt(self, data):
        file_vector = data[:AES.block_size]
        decryption_cipher = AES.new(self.key, AES.MODE_CBC, file_vector)
        return unpad(decryption_cipher.decrypt(data[AES.block_size:]), AES.block_size)



if __name__ == '__main__':
    start_time = time.time()
    print('TESTING ENCRYPTION')
    msg = "What is Lorem Ipsum? Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. What is Lorem Ipsum? Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.".encode('utf-8')
    pwd = "password"
    
    encrypted = AESCipher(pwd).encrypt(msg)
    # print('Ciphertext:', encrypted)
    # print('\nTESTING DECRYPTION')
    decrypted = AESCipher(pwd).decrypt(encrypted).decode('utf-8')
    # print("Original data: ", msg.decode('utf-8'))
    print("Decripted data:", decrypted)
    assert msg.decode('utf-8') == decrypted 
    print("--- %s seconds ---" % (time.time() - start_time))