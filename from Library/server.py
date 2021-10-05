import socket
import threading
from AES_lib import AESCipher

class Server:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostbyname(socket.gethostname())
        self.port = 5068
        self.address = (self.host, self.port)
        self.header = 1024
        self.format = "utf-8"
        self.client_names = {}
        self.disconnect = 'exit'

        self.key = b'\00' * 16
        self.iv = b'\01' * 16
        self.aes=AESCipher(self.key)

    def start_server(self):
        self.server.bind(self.address)
        self.server.listen()
        print(f"Server is starting...\nServer [{self.host}] is ready to accept connections!")
        while True:
            client, client_addr = self.server.accept()
            self.ask_name(client)
            thread = threading.Thread(target=self.handle_client, args=(client, client_addr))
            thread.start()

    def ask_name(self, client):
        msg=client.recv(self.header).decode(self.format)
        self.client_names[client]=msg

    def broadcast(self, msg):
        for client in self.client_names:
            encrypted_msg=self.aes.encrypt(msg.encode(self.format))
            client.send(encrypted_msg)

    def handle_client(self, client, client_addr):
        client_name=self.client_names[client]
        print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - Connected")
        print(f"Active Connections - {threading.active_count()-1}")
        self.broadcast(f"{client_name} has joined the chat!\n")
        while True:
            try:
                msg = self.aes.decrypt(client.recv(self.header)).decode(self.format)
                if msg==self.disconnect:
                    break
                print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - {msg}")
                msg=f'{client_name}: {msg}'
                self.broadcast(msg)
            except:
                break
        client.close()
        print(f"[{client_addr[0]}]-{client_addr[1]} - [{client_name}] - Disconnected")
        del self.client_names[client]
        self.broadcast(f'{client_name} has left the chat\n')
        print(f"Active Connections - {threading.active_count()-2}")

s=Server()
s.start_server()
