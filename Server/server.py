# Server/server.py
import os
import socket
import ssl
import threading
import rsa
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
logging.basicConfig(filename='ftp_server.log', level=logging.INFO)

# 在命令处理时记录日志
def log_command(username, command):
    logging.info(f"User: {username} executed command: {command}")
# 生成 RSA 密钥对
def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key
# 更好的用户身份认证
def authenticate_user(username, password):
    stored_credentials = {
        'admin': {'password': 'encrypted_password'},  # 以加密形式存储
    }
    if username in stored_credentials:
        encrypted_stored_password = stored_credentials[username]['password']
        if rsa.verify(password.encode(), encrypted_stored_password, public_key):
            return True
    return False

# 文件操作命令（增强）
def handle_client(connection, addr):
    ssl_connection = ssl.wrap_socket(connection, keyfile=None, certfile='server.pem', server_side=True)
    public_key = ssl_connection.recv(1024).decode()
    ssl_connection.send(public_key.encode())

    username = ssl_connection.recv(1024).decode()
    password = ssl_connection.recv(1024).decode()

    if authenticate_user(username, password):
        ssl_connection.send("Authentication Successful".encode())
    else:
        ssl_connection.send("Authentication Failed".encode())
        ssl_connection.close()
        return

    current_directory = os.getcwd()

    while True:
        command = ssl_connection.recv(1024).decode()
        
        if command == 'exit':
            ssl_connection.send("Goodbye".encode())
            break
        
        elif command == 'list':
            ssl_connection.send(b64encode(str(os.listdir(current_directory)).encode()))
        
        elif command == 'cd':
            new_dir = ssl_connection.recv(1024).decode()
            try:
                os.chdir(new_dir)
                current_directory = os.getcwd()
                ssl_connection.send(f"Changed directory to {new_dir}".encode())
            except FileNotFoundError:
                ssl_connection.send("Directory not found.".encode())

        elif command == 'pwd':
            ssl_connection.send(current_directory.encode())
        
        elif command == 'mkdir':
            dir_name = ssl_connection.recv(1024).decode()
            try:
                os.mkdir(dir_name)
                ssl_connection.send(f"Directory {dir_name} created.".encode())
            except FileExistsError:
                ssl_connection.send("Directory already exists.".encode())
        
        elif command == 'get':
            filename = ssl_connection.recv(1024).decode()
            try:
                with open(filename, 'rb') as f:
                    while chunk := f.read(1024):  # 逐块读取文件
                        ssl_connection.send(chunk)
                ssl_connection.send(b"EOF")  # 文件结束标志
            except FileNotFoundError:
                ssl_connection.send("File not found.".encode())
        
        elif command == 'put':
            filename = ssl_connection.recv(1024).decode()
            with open(filename, 'wb') as f:
                while True:
                    file_data = ssl_connection.recv(1024)
                    if file_data == b"EOF":  # 判断文件结束标志
                        break
                    f.write(file_data)
            ssl_connection.send(f"File {filename} uploaded.".encode())
        
        elif command == 'rename':
            old_name = ssl_connection.recv(1024).decode()
            new_name = ssl_connection.recv(1024).decode()
            os.rename(old_name, new_name)
            ssl_connection.send(f"Renamed {old_name} to {new_name}".encode())
        
        elif command == 'attrib':
            filename = ssl_connection.recv(1024).decode()
            try:
                file_stats = os.stat(filename)
                file_info = f"Size: {file_stats.st_size}, Last Modified: {file_stats.st_mtime}"
                ssl_connection.send(file_info.encode())
            except FileNotFoundError:
                ssl_connection.send("File not found.".encode())


        elif command == 'create':
            filename = ssl_connection.recv(1024).decode()
            with open(filename, 'w') as f:
                pass
            ssl_connection.send(f"File {filename} created.".encode())
        
        elif command == 'add':
            username = ssl_connection.recv(1024).decode()
            password = ssl_connection.recv(1024).decode()
            # Add user and encrypt password here
            ssl_connection.send(f"Added user {username}".encode())
        
        else:
            ssl_connection.send("Command not recognized".encode())

    ssl_connection.close()

# 启动服务器
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 21))
    server_socket.listen(5)
    
    public_key, private_key = generate_rsa_keys()
    
    print("Server is listening on port 21...")
    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

if __name__ == '__main__':
    start_server()
