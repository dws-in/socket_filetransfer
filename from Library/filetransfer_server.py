import socket
# from AES import AESCipher
from AES_lib import AESCipher
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

        """ AES 16 bits Key and IV """
        self.key = b'\00' * 16
        # self.iv = b'\01' * 16
        self.aes=AESCipher(self.key)

    def start_server(self):
        """ Binding and listening """
        self.server.bind(self.address)
        self.server.listen()
        print(f"Server is starting...\nServer [{self.host}] is ready to accept connections!")
        
        """ Receiving client name """
        self.client, self.client_addr = self.server.accept()
        self.client_name = self.client.recv(self.header).decode(self.format)
        print(f"[{self.client_addr}]-{self.client_name} - Connected")

        """ Receiving filename and filesize """
        msg = self.client.recv(self.header)
        decrypted_msg = self.aes.decrypt(msg).decode(self.format)
        print(f"CLIENT: {decrypted_msg}")
        item = decrypted_msg.split("_")
        self.filename = item[0]
        self.filesize = int(item[1])

    def recv_file(self):
        self.bar = tqdm(range(self.filesize), f"Receiving {self.filename}", unit="B", unit_scale=True, unit_divisor=self.header)
        with open(f"recv_{self.filename}", "w") as f:
            while True:
                """ Receiving data from client """
                data = self.client.recv(self.header)
                if not data:
                    break

                """ Decrypting data """
                decrypted_data = self.aes.decrypt(data).decode(self.format)
                f.write(decrypted_data)

                """ Sending feedback """
                msg = "Data recieved by server"
                encrypted_msg = self.aes.encrypt(msg.encode(self.format))
                self.client.send(encrypted_msg)

                """ Updating progress bar """
                self.bar.update(len(data))
        
    def stop_client(self):
        self.client.close()
        self.server.close()
        exit(0)


s=Server()
s.start_server()
s.recv_file()
s.stop_client()