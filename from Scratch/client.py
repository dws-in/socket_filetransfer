import socket
import threading
from AES import AESCipher
import random

class Client:
    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostbyname(socket.gethostname())
        self.port = 5068
        self.addr = (self.host, self.port)
        self.header = 1024
        self.name = "bot"+str(random.randint(1,99999))
        self.format = "utf-8"
        self.disconnect = 'exit'

        self.key = b'\00' * 16
        self.iv = b'\01' * 16
        self.aes=AESCipher(self.key)

    def start_client(self):
        self.client.connect(self.addr)
        self.client.send(self.name.encode(self.format))

        recv_msg_thread=threading.Thread(target=self.recv_msg)
        recv_msg_thread.start()

        send_msg_thread=threading.Thread(target=self.send_msg)
        send_msg_thread.start()

    def stop_client(self):
        self.client.send(self.aes.encrypt_cbc(self.disconnect, self.iv))
        self.client.close()
        exit(0)

    def recv_msg(self):
        while True:
            try:
                msg = self.client.recv(self.header)
                msg = self.aes.decrypt_cbc(msg, self.iv).decode(self.format)
            except:
                print("Disconnected from server")
                break

    def send_msg(self):
        while True:
            try:
                msg = input('Message:')
                if msg == self.disconnect:
                    break
                msg = self.aes.encrypt_cbc(msg.encode(self.format), self.iv)
                self.client.send(msg)
            except:
                print("Disconnected from server")
                break

s=Client()
s.start_client()


