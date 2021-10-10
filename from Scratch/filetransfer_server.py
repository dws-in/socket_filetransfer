import socket
from key_exchange import DiffieHellman
from AES import AESCipher
from tqdm import tqdm

class Server:
    def __init__(self):
        """ Creating a client socket """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostbyname(socket.gethostname())
        self.port = 5068
        self.address = (self.host, self.port)
        self.header = 1024
        self.format = "utf-8"
        self.disconnect = 'exit'
        
        """ Initial value """
        self.iv = b'\00' * 16
        
        """ Generating server public key """
        self.server_key=DiffieHellman()
        self.server_pub_key=str(self.server_key.gen_public_key())
        self.server_pvt_key=None
        print(self.server_pub_key)

    def start_server(self):
        """ Binding and listening """
        self.server.bind(self.address)
        self.server.listen()
        print(f"Server is starting...\nServer [{self.host}] is ready to accept connections!")
        
        """ Receiving client name """
        self.client, self.client_addr = self.server.accept()
        self.client_name = self.client.recv(self.header).decode(self.format)
        print(f"[{self.client_addr}]-{self.client_name} - Connected")
        
        """ Exchange keys """
        self.exchange_keys()
        
        """ Receiving filename and filesize """
        msg = self.client.recv(self.header)

        """ Decrypting filename and filesize """
        decrypted_msg = self.aes.decrypt_cbc(msg, self.iv).decode(self.format)
        print(f"CLIENT: {decrypted_msg}")
        
        """ Extracting filename and filesize """
        item = decrypted_msg.split("_")
        self.filename = item[0]
        self.filesize = int(item[1])

    def exchange_keys(self):
        """ Sending server public key """
        self.client.send((self.server_pub_key).encode(self.format))

        """ Receiving client public key """
        client_pub_key=int(self.client.recv(self.header).decode(self.format))

        """ Generating server private key """
        self.server_pvt_key=self.server_key.gen_shared_key(client_pub_key)
        """ Creating aes object with the server private key """
        self.aes=AESCipher(self.server_pvt_key)

    def recv_file(self):
        self.bar = tqdm(range(self.filesize), f"Receiving {self.filename}", unit="B", unit_scale=True, unit_divisor=self.header)
        with open(f"recv_{self.filename}", "w") as f:
            while True:
                """ Receiving data from client """
                data = self.client.recv(self.header)
                if not data:
                    break

                """ Decrypting data """
                decrypted_data = self.aes.decrypt_cbc(data, self.iv).decode(self.format)
                
                """ Writing data to file"""
                f.write(decrypted_data)

                """ Sending feedback """
                msg = "Data recieved"
                encrypted_msg = self.aes.encrypt_cbc(msg.encode(self.format), self.iv)
                self.client.send(encrypted_msg)

                """ Updating progress bar """
                self.bar.update(len(data))
        
    def stop_client(self):
        """ Close connection """
        self.client.close()
        self.server.close()
        exit(0)


s=Server()
s.start_server()
s.recv_file()
s.stop_client()


# yang kurang ngecek format key dari DH