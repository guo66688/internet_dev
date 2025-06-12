import bcrypt

# 密码哈希
password = '123456'.encode()
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

print(hashed_password)
