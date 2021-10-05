import socket
import os
# from AES import AESCipher
from AES_lib import AESCipher
import random
from tqdm import tqdm

class Client:
    def __init__(self):
        """ Creating a client socket """
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostbyname(socket.gethostname())
        self.port = 5068
        self.addr = (self.host, self.port)
        self.header = 1024
        self.name = "bot"+str(random.randint(1,99999))
        self.format = "utf-8"
        self.disconnect = 'exit'

        """ Filename and filesize """
        self.filename = "filename.txt"
        self.filesize = os.path.getsize(self.filename)

        """ AES 16 bits Key and IV """
        self.key = b'\00' * 16
        # self.iv = b'\01' * 16
        self.aes=AESCipher(self.key)

    def start_client(self):
        """ Connecting to server then send client name"""
        self.client.connect(self.addr)
        self.client.send(self.name.encode(self.format))

        """ Sending filename and filesize to server """
        msg = f"{self.filename}_{self.filesize}"
        encrypted_msg = self.aes.encrypt(msg.encode(self.format))
        print(f"CLIENT: {msg}")
        self.client.send(encrypted_msg)
        
    def send_file(self):
        self.bar = tqdm(range(self.filesize), f"Sending {self.filename}", unit="B", unit_scale=True, unit_divisor=self.header)
        with open(self.filename, "r") as f:
            while True:
                """ Reading data from file """
                data = f.read(self.header)
                if not data:
                    break

                """ Encrypting data """
                encrypted_data = self.aes.encrypt(data.encode(self.format))
                self.client.send(encrypted_data)

                """ Receiving feedback from server """
                msg = self.client.recv(self.header)
                decrypted_msg = self.aes.decrypt(msg).decode(self.format)
                print(f"SERVER: {decrypted_msg}")

                """ Updating progress bar """
                self.bar.update(len(data))

    def stop_client(self):
        self.client.close()
        exit(0)


c=Client()
c.start_client()
c.send_file()
c.stop_client()