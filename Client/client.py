# Client/client.py
import socket
import ssl
import rsa
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_aes(key, encrypted_data):
    data = b64decode(encrypted_data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def handle_server_response(ssl_connection):
    while True:
        response = ssl_connection.recv(1024).decode()
        print(response)
        if "Goodbye" in response:
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 21))  # 连接服务器
    
    ssl_connection = ssl.wrap_socket(client_socket, keyfile=None, certfile='client.pem', server_side=False)
    
    public_key = ssl_connection.recv(1024).decode()
    ssl_connection.send(public_key.encode())

    username = input("Enter username: ")
    password = input("Enter password: ")
    
    ssl_connection.send(username.encode())
    ssl_connection.send(password.encode())
    
    response = ssl_connection.recv(1024).decode()
    if response != "Authentication Successful":
        print("Authentication Failed")
        ssl_connection.close()
        return

    while True:
        command = input("Enter command: ")
        if command == 'exit':
            ssl_connection.send(command.encode())
            print("Goodbye")
            break
        ssl_connection.send(command.encode())
        response = ssl_connection.recv(1024).decode()
        print(response)

    ssl_connection.close()

if __name__ == '__main__':
    start_client()
