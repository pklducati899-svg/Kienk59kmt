import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def aes_encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    # Tạo vector khởi tạo IV ngẫu nhiên 16 bytes
    iv = os.urandom(16)

    # Đệm dữ liệu (PKCS7) cho đủ bội số 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Thiết lập Cipher AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    # Giải mã AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Bỏ đệm dữ liệu (Unpad PKCS7)
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode('utf-8')


# --- CHƯƠNG TRÌNH THỬ NGHIỆM ---
if __name__ == "__main__":
    # Khóa 128-bit (16 bytes)
    secret_key = os.urandom(16)
    original_text = "phạm trung kiên k59kmt môn an toàn bảo mật thông tin"

    # Mã hóa
    iv, encrypted_data = aes_encrypt(original_text, secret_key)
    print(f"Bản mã (Hex): {encrypted_data.hex()}")

    # Giải mã
    decrypted_text = aes_decrypt(encrypted_data, secret_key, iv)
    print(f"Bản giải mã: {decrypted_text}")