from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt(plain_text, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return iv + cipher_text

def decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return plain_text

key = get_random_bytes(16)  # 16字节（128位）的随机密钥

plain_text = b'hello world'
cipher_text = encrypt(plain_text, key)
decrypted_text = decrypt(cipher_text, key)
print("\n")
print('Plain text:', plain_text)
print('key:', key)
print('Cipher text:', cipher_text)
print('Decrypted text:', decrypted_text)
