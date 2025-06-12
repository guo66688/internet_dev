# Client/client.py
import socket
import ssl
import rsa
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import os
import threading
import time
from threading import Event

# 配置
SSL_CERT_FILE = 'client.pem'
RSA_PUB_FILE = 'server_pubkey.pem'
CHAT_PREFIX = "CHAT:"

# 下载标志：只有在执行 get 命令后才置位
download_event = Event()

def encrypt_aes(key, data):
    """AES加密文本"""
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_aes(key, encrypted_data):
    """AES解密文本"""
    data = b64decode(encrypted_data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def encrypt_aes_binary(key, data):
    """AES加密二进制数据"""
    cipher = AES.new(key, AES.MODE_EAX)
    return cipher.nonce + cipher.encrypt(data)

def decrypt_aes_binary(key, encrypted_data):
    """AES解密二进制数据"""
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext)

def generate_aes_key():
    """生成随机AES密钥"""
    return os.urandom(32)

def encrypt_with_rsa(public_key, data):
    """RSA加密"""
    return rsa.encrypt(data, public_key)

def receive_responses(ssl_connection, aes_key):
    """接收服务器响应的线程函数"""
    while True:
        try:
            encrypted_response = ssl_connection.recv(4096)
            if not encrypted_response:
                print("Connection closed by server")
                break

            response = decrypt_aes(aes_key, encrypted_response)

            # 如果是下载流程的 READY，并且 download_event 已置位，执行下载
            if response == "READY" and download_event.is_set():
                download_event.clear()

                # 读取文件长度
                length_str = decrypt_aes(aes_key, ssl_connection.recv(1024).decode())
                file_size = int(length_str)
                encrypted_data = b''
                while len(encrypted_data) < file_size:
                    chunk = ssl_connection.recv(min(4096, file_size - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk
                file_data = decrypt_aes_binary(aes_key, encrypted_data)

                # 保存到本地
                filename = input("Enter filename to save: ")
                with open(filename, 'wb') as f:
                    f.write(file_data)
                print(f"File {filename} downloaded successfully")
                print("ftp> ", end='', flush=True)
                continue

            # 普通消息或聊天回复
            if response.startswith(CHAT_PREFIX):
                print(f"\n[Server]: {response[len(CHAT_PREFIX):]}\nftp> ", end='', flush=True)
            else:
                print(f"\nServer: {response}\nftp> ", end='', flush=True)

        except Exception as e:
            print(f"Error receiving response: {str(e)}")
            break

def start_client():
    """启动FTP客户端"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 21))

    # 创建SSL上下文
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    ssl_connection = context.wrap_socket(
        client_socket,
        server_hostname='localhost'
    )

    # 交换公钥
    server_pubkey = rsa.PublicKey.load_pkcs1(ssl_connection.recv(2048))

    # 用户认证
    username = input("Enter username: ")
    password = input("Enter password: ")
    ssl_connection.send(encrypt_with_rsa(server_pubkey, username.encode()))
    ssl_connection.send(encrypt_with_rsa(server_pubkey, password.encode()))

    response = ssl_connection.recv(1024).decode()
    if response != "Authentication Successful":
        print("Authentication Failed")
        ssl_connection.close()
        return

    # 生成并发送AES密钥
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_with_rsa(server_pubkey, aes_key)
    ssl_connection.send(encrypted_aes_key)

    # 启动接收线程
    threading.Thread(
        target=receive_responses,
        args=(ssl_connection, aes_key),
        daemon=True
    ).start()

    try:
        while True:
            command = input("ftp> ").strip()
            if not command:
                continue

            # 标记下载期望
            if command.startswith('get '):
                download_event.set()
                ssl_connection.send(encrypt_aes(aes_key, command).encode())

            # 上传文件
            elif command.startswith('put '):
                ssl_connection.send(encrypt_aes(aes_key, command).encode())
                filename = command[4:].strip()
                try:
                    with open(filename, 'rb') as f:
                        file_data = f.read()
                        encrypted_data = encrypt_aes_binary(aes_key, file_data)
                        ssl_connection.send(encrypt_aes(aes_key, str(len(encrypted_data))).encode())
                        ssl_connection.sendall(encrypted_data)
                    print(f"File {filename} sent, waiting for server confirmation...")
                except FileNotFoundError:
                    print(f"File {filename} not found")
                    ssl_connection.send(encrypt_aes(aes_key, "CANCEL").encode())

            # 聊天功能
            elif command.startswith('chat '):
                message = command[5:]
                ssl_connection.send(encrypt_aes(aes_key, f"{CHAT_PREFIX}{message}").encode())
                print("Message sent, waiting for reply...")

            # 退出
            elif command == 'exit':
                ssl_connection.send(encrypt_aes(aes_key, "exit").encode())
                time.sleep(0.1)
                break

            else:
                # 其他命令直接发给服务器
                ssl_connection.send(encrypt_aes(aes_key, command).encode())

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nDisconnecting...")
        ssl_connection.send(encrypt_aes(aes_key, "exit").encode())
    finally:
        ssl_connection.close()

if __name__ == '__main__':
    start_client()
