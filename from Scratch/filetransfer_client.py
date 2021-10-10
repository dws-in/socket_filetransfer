import os
import random
import socket
from key_exchange import DiffieHellman
from AES import AESCipher
from tqdm import tqdm

class Client:
    def __init__(self):
        """ Creating a client socket """
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostbyname(socket.gethostname())
        self.port = 5068
        self.addr = (self.host, self.port)
        self.header = 1024
        self.format = "utf-8"
        self.disconnect = 'exit'

        """ Generating random client name"""
        self.name = "bot"+str(random.randint(1,999))

        """ Filename and filesize """
        self.filename = "filename.txt"
        self.filesize = os.path.getsize(self.filename)

        """ Initial value """
        self.iv = b'\00' * 16

        """ Generating client public key """
        self.client_key = DiffieHellman()
        self.client_pub_key=str(self.client_key.gen_public_key())
        self.client_pvt_key=None

    def start_client(self):
        """ Connecting to server """
        self.client.connect(self.addr)

        """ Send client name """
        self.client.send(self.name.encode(self.format))

        """ Excangke keys """
        self.exchange_keys()

        """ Encrypting filename and filesize """
        data = f"{self.filename}_{self.filesize}"
        encrypted_data = self.aes.encrypt_cbc(data.encode(self.format), self.iv)
        
        """ Sending data """
        self.client.send(encrypted_data)
        print(f"CLIENT: {data}")

    def exchange_keys(self):
        """ Receiving server public key """
        server_pub_key=int(self.client.recv(self.header).decode(self.format))

        """ Generating client private key """
        self.client_pvt_key=self.client_key.gen_shared_key(server_pub_key)
        print(self.client_pvt_key)
        """ Sending client public key """
        self.client.send(self.client_pub_key.encode(self.format))

        """ Creating aes object with the client private key """
        self.aes=AESCipher(self.client_pvt_key)
        
    def send_file(self):
        self.bar = tqdm(range(self.filesize), f"Sending {self.filename}", unit="B", unit_scale=True, unit_divisor=self.header)
        with open(self.filename, "r") as f:
            while True:
                """ Reading data from file """
                data = f.read(self.header)
                if not data:
                    break

                """ Encrypting data """
                encrypted_data = self.aes.encrypt_cbc(data.encode(self.format), self.iv)
                
                """ Sending data """
                self.client.send(encrypted_data)

                """ Receiving feedback from server """
                msg = self.client.recv(self.header)
                decrypted_msg = self.aes.decrypt_cbc(msg, self.iv).decode(self.format)
                print(f"SERVER: {decrypted_msg}")

                """ Updating progress bar """
                self.bar.update(len(data))

    def stop_client(self):
        """ Close connection """
        self.client.close()
        exit(0)


c=Client()
c.start_client()
c.send_file()
c.stop_client()


# yang kurang ngecek format key dari DH