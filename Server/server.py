# Server/server.py
import os
import socket
import ssl
import threading
import rsa
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import logging
import mysql.connector
import bcrypt
import re
import time
from datetime import datetime

# 安全配置
SSL_CERT_FILE = 'server.pem'
RSA_KEY_FILE = 'server_privkey.pem'
CHAT_PREFIX = "CHAT:"  # 聊天消息标识

# 日志配置
logging.basicConfig(
    filename='ftp_server.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 数据库连接池
db_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="ftp_pool",
    pool_size=5,
    host='localhost',
    user='root',  # 替换为实际用户名
    password='123456',  # 替换为实际密码
    database='ftp_users',
    pool_reset_session=True,  # 关键修复：连接回收时重置会话
    autocommit=True  # 避免事务未提交导致的连接问题
)

def get_db_connection():
    return db_pool.get_connection()

def log_command(username, command, success=True):
    status = "SUCCESS" if success else "FAILED"
    logging.info(f"User: {username} - Command: {command} - Status: {status}")

def generate_rsa_keys():
    """生成或加载RSA密钥对"""
    if os.path.exists(RSA_KEY_FILE):
        with open(RSA_KEY_FILE, 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open(RSA_KEY_FILE.replace('priv', 'pub'), 'rb') as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        return public_key, private_key
    
    public_key, private_key = rsa.newkeys(2048)
    with open(RSA_KEY_FILE, 'wb') as f:
        f.write(private_key.save_pkcs1())
    with open(RSA_KEY_FILE.replace('priv', 'pub'), 'wb') as f:
        f.write(public_key.save_pkcs1())
    return public_key, private_key

def authenticate_user(username, password):
    """使用bcrypt验证用户凭证"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            return True
        return False
    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return False
    finally:
        cursor.close()
        conn.close()

def decrypt_with_rsa(private_key, encrypted_data):
    """RSA解密"""
    return rsa.decrypt(encrypted_data, private_key)

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

def is_safe_path(base, path):
    """防止路径遍历攻击"""
    base = os.path.abspath(base)
    target = os.path.abspath(os.path.join(base, path))
    return os.path.commonpath([base]) == os.path.commonpath([base, target])

def handle_client(connection, addr, private_key):
    """处理客户端连接"""
    # 创建一个 TLS-服务端上下文，只做一次
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # 把刚才生成的自签证书和私钥加载进来
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    ssl_connection = context.wrap_socket(
        connection,
        server_side=True
    )
    
    # 交换公钥
    with open(RSA_KEY_FILE.replace('priv', 'pub'), 'rb') as f:
        ssl_connection.send(f.read())
    
    # 接收并验证凭据
    encrypted_username = ssl_connection.recv(1024)
    encrypted_password = ssl_connection.recv(1024)
    username = decrypt_with_rsa(private_key, encrypted_username).decode()
    password = decrypt_with_rsa(private_key, encrypted_password).decode()
    
    if authenticate_user(username, password):
        ssl_connection.send("Authentication Successful".encode())
    else:
        ssl_connection.send("Authentication Failed".encode())
        ssl_connection.close()
        return
    
    # 接收并解密AES密钥
    encrypted_aes_key = ssl_connection.recv(1024)
    aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
    
    current_directory = os.getcwd()
    LAST_ACTIVITY = time.time()
    
    while True:
        try:
            # 会话超时检测
            if time.time() - LAST_ACTIVITY > 300:
                ssl_connection.send(encrypt_aes(aes_key, "Session timed out").encode())
                break
                
            encrypted_command = ssl_connection.recv(1024)
            if not encrypted_command:
                break
                
            command = decrypt_aes(aes_key, encrypted_command)
            LAST_ACTIVITY = time.time()
            
            # 退出命令
            if command == 'exit':
                ssl_connection.send(encrypt_aes(aes_key, "Goodbye").encode())
                log_command(username, "exit", True)
                break
            
            # 目录列表
            elif command == 'list':
                response = str(os.listdir(current_directory))
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
                log_command(username, "list", True)
            
            # 更改目录
            elif command.startswith('cd '):
                new_dir = command[3:].strip()
                if not is_safe_path(current_directory, new_dir):
                    response = "Invalid path"
                    log_command(username, f"cd {new_dir}", False)
                else:
                    try:
                        os.chdir(new_dir)
                        current_directory = os.getcwd()
                        response = f"Changed directory to {current_directory}"
                        log_command(username, f"cd {new_dir}", True)
                    except FileNotFoundError:
                        response = "Directory not found."
                        log_command(username, f"cd {new_dir}", False)
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
            
            # 返回上级目录
            elif command == 'cd..':
                os.chdir('..')
                current_directory = os.getcwd()
                response = f"Changed directory to {current_directory}"
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
                log_command(username, "cd..", True)
            
            # 显示当前目录
            elif command == 'pwd':
                response = current_directory
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
                log_command(username, "pwd", True)
            
            # 创建目录
            elif command.startswith('mkdir '):
                dir_name = command[6:].strip()
                if not is_safe_path(current_directory, dir_name):
                    response = "Invalid path"
                    log_command(username, f"mkdir {dir_name}", False)
                else:
                    try:
                        os.mkdir(dir_name)
                        response = f"Directory {dir_name} created."
                        log_command(username, f"mkdir {dir_name}", True)
                    except FileExistsError:
                        response = "Directory already exists."
                        log_command(username, f"mkdir {dir_name}", False)
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
            
            # 下载文件
            elif command.startswith('get '):
                filename = command[4:].strip()
                if not is_safe_path(current_directory, filename):
                    response = "Invalid path"
                    ssl_connection.send(encrypt_aes(aes_key, response).encode())
                    log_command(username, f"get {filename}", False)
                else:
                    try:
                        ssl_connection.send(encrypt_aes(aes_key, "READY").encode())
                        with open(filename, 'rb') as f:
                            file_data = f.read()
                            encrypted_data = encrypt_aes_binary(aes_key, file_data)
                            ssl_connection.send(encrypt_aes(aes_key, str(len(encrypted_data))).encode())
                            ssl_connection.sendall(encrypted_data)
                        log_command(username, f"get {filename}", True)
                    except FileNotFoundError:
                        response = "File not found."
                        ssl_connection.send(encrypt_aes(aes_key, response).encode())
                        log_command(username, f"get {filename}", False)
            
            # 上传文件
            elif command.startswith('put '):
                filename = command[4:].strip()
                if not is_safe_path(current_directory, filename):
                    response = "Invalid path"
                    ssl_connection.send(encrypt_aes(aes_key, response).encode())
                    log_command(username, f"put {filename}", False)
                else:
                    ssl_connection.send(encrypt_aes(aes_key, "READY").encode())
                    file_size = int(decrypt_aes(aes_key, ssl_connection.recv(1024).decode()))
                    encrypted_data = b''
                    while len(encrypted_data) < file_size:
                        packet = ssl_connection.recv(min(4096, file_size - len(encrypted_data)))
                        if not packet:
                            break
                        encrypted_data += packet
                    file_data = decrypt_aes_binary(aes_key, encrypted_data)
                    with open(filename, 'wb') as f:
                        f.write(file_data)
                    response = f"File {filename} uploaded."
                    ssl_connection.send(encrypt_aes(aes_key, response).encode())
                    log_command(username, f"put {filename}", True)
            
            # 重命名
            elif command.startswith('rename '):
                parts = command[7:].split()
                if len(parts) < 2:
                    response = "Usage: rename old_name new_name"
                    log_command(username, command, False)
                else:
                    old_name, new_name = parts[0], parts[1]
                    if (not is_safe_path(current_directory, old_name) or 
                        not is_safe_path(current_directory, new_name)):
                        response = "Invalid path"
                        log_command(username, f"rename {old_name} {new_name}", False)
                    else:
                        try:
                            os.rename(old_name, new_name)
                            response = f"Renamed {old_name} to {new_name}"
                            log_command(username, f"rename {old_name} {new_name}", True)
                        except FileNotFoundError:
                            response = "File not found."
                            log_command(username, f"rename {old_name} {new_name}", False)
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
            
            # 查看文件属性
            elif command.startswith('attrib '):
                filename = command[7:].strip()
                if not is_safe_path(current_directory, filename):
                    response = "Invalid path"
                    log_command(username, f"attrib {filename}", False)
                else:
                    try:
                        file_stats = os.stat(filename)
                        file_info = (
                            f"Size: {file_stats.st_size} bytes, "
                            f"Last Modified: {datetime.fromtimestamp(file_stats.st_mtime)}, "
                            f"Permissions: {oct(file_stats.st_mode)[-3:]}"
                        )
                        response = file_info
                        log_command(username, f"attrib {filename}", True)
                    except FileNotFoundError:
                        response = "File not found."
                        log_command(username, f"attrib {filename}", False)
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
            
            # 创建文件
            elif command.startswith('create '):
                filename = command[7:].strip()
                if not is_safe_path(current_directory, filename):
                    response = "Invalid path"
                    log_command(username, f"create {filename}", False)
                else:
                    try:
                        with open(filename, 'w') as f:
                            pass
                        response = f"File {filename} created."
                        log_command(username, f"create {filename}", True)
                    except Exception as e:
                        response = f"Error: {str(e)}"
                        log_command(username, f"create {filename}", False)
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
            
            # 聊天功能
            elif command.startswith(CHAT_PREFIX):
                message = command[len(CHAT_PREFIX):]
                print(f"[{username}]: {message}")
                reply = input("Server reply: ")
                ssl_connection.send(encrypt_aes(aes_key, f"{CHAT_PREFIX}{reply}").encode())
                log_command(username, "chat", True)
            
            # 添加用户
            elif command.startswith('add '):
                parts = command[4:].split()
                if len(parts) < 2:
                    response = "Usage: add username password"
                    log_command(username, command, False)
                else:
                    new_user, new_pass = parts[0], parts[1]
                    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', new_user):
                        response = "Invalid username format"
                        log_command(username, f"add {new_user}", False)
                    else:
                        try:
                            conn = get_db_connection()
                            cursor = conn.cursor()
                            hashed_pw = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
                            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
                                        (new_user, hashed_pw))
                            conn.commit()
                            response = f"User {new_user} added"
                            log_command(username, f"add {new_user}", True)
                        except mysql.connector.IntegrityError:
                            response = "Username already exists"
                            log_command(username, f"add {new_user}", False)
                        except Exception as e:
                            response = f"Error: {str(e)}"
                            log_command(username, f"add {new_user}", False)
                        finally:
                            cursor.close()
                            conn.close()
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
            
            # 未知命令
            else:
                response = "Command not recognized"
                ssl_connection.send(encrypt_aes(aes_key, response).encode())
                log_command(username, command, False)
                
        except Exception as e:
            logging.error(f"Error handling command: {str(e)}")
            response = f"Error: {str(e)}"
            ssl_connection.send(encrypt_aes(aes_key, response).encode())

    ssl_connection.close()

def start_server():
    """启动FTP服务器"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 21))
    server_socket.listen(5)
    
    public_key, private_key = generate_rsa_keys()
    
    print("FTP Server is listening on port 21...")
    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"New connection from {addr[0]}:{addr[1]}")
            threading.Thread(
                target=handle_client, 
                args=(client_socket, addr, private_key),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()