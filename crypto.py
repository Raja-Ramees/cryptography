import base64
import hashlib
import logging
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ================= AES Implementation =================
class AESCipher:
    def __init__(self, key: bytes):
        self.key = hashlib.sha256(key).digest()  # 256-bit key

    def encrypt(self, raw: str) -> str:
        raw_bytes = raw.encode("utf-8")
        cipher = AES.new(self.key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(raw_bytes)
        return base64.b64encode(cipher.iv + ciphertext).decode("utf-8")

    def decrypt(self, enc: str) -> str:
        enc_bytes = base64.b64decode(enc)
        iv = enc_bytes[:16]
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
        plaintext = cipher.decrypt(enc_bytes[16:])
        return plaintext.decode("utf-8")

# ================= RSA Implementation =================
class RSACipher:
    def __init__(self, key_size=2048):
        self.key = RSA.generate(key_size)
        self.public_key = self.key.publickey()
        self.cipher_encrypt = PKCS1_OAEP.new(self.public_key)
        self.cipher_decrypt = PKCS1_OAEP.new(self.key)

    def encrypt(self, message: str) -> str:
        ciphertext = self.cipher_encrypt.encrypt(message.encode("utf-8"))
        return base64.b64encode(ciphertext).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        enc_bytes = base64.b64decode(ciphertext)
        return self.cipher_decrypt.decrypt(enc_bytes).decode("utf-8")

# ================= Hashing Implementation =================
def hash_password(password: str, salt: bytes = None) -> (str, str):
    if not salt:
        salt = get_random_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return base64.b64encode(salt).decode("utf-8"), base64.b64encode(hashed).decode("utf-8")

# ================= Main Demo =================
if __name__ == "__main__":
    logging.info("Starting Cryptography Demonstration...")

    # AES Demo
    aes_key = b"my_secret_password"
    aes = AESCipher(aes_key)
    secret_message = "Hello Rayees, this is AES encryption!"
    encrypted_aes = aes.encrypt(secret_message)
    decrypted_aes = aes.decrypt(encrypted_aes)
    logging.info(f"AES Original: {secret_message}")
    logging.info(f"AES Encrypted: {encrypted_aes}")
    logging.info(f"AES Decrypted: {decrypted_aes}")

    # RSA Demo
    rsa = RSACipher()
    rsa_message = "Confidential Data via RSA!"
    encrypted_rsa = rsa.encrypt(rsa_message)
    decrypted_rsa = rsa.decrypt(encrypted_rsa)
    logging.info(f"RSA Original: {rsa_message}")
    logging.info(f"RSA Encrypted: {encrypted_rsa}")
    logging.info(f"RSA Decrypted: {decrypted_rsa}")

    # Password Hashing Demo
    salt, hashed_pw = hash_password("MySecurePassword123")
    logging.info(f"Password Salt: {salt}")
    logging.info(f"Password Hash (SHA256 + Salt): {hashed_pw}")

    logging.info("Cryptography Demonstration Completed.")

