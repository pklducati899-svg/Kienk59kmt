# Kienk59kmt

thông tin sinh viên

HỌ VÀ TÊN: PHẠM TRUNG KIÊN

LỚP: K59KMT.K01

MSSV: K235480106038

1. Thuật toán mã hóa đối xứng: DES và AES

Thuật toán DES (Data Encryption Standard)

DES là thuật toán mã hóa khối (Block Cipher) đối xứng ra đời năm 1977, làm việc trên khối dữ liệu 64-bit với độ dài khóa thực tế 56-bit (8 bit dùng kiểm tra parities).

Thuật toán AES (Advanced Encryption Standard)

AES là thuật toán mã hóa khối thay thế DES từ năm 2001, xử lý khối dữ liệu 128-bit với các độ dài khóa linh hoạt: 128-bit (10 vòng), 192-bit (12 vòng), hoặc 256-bit (14 vòng).


Cài đặt AES-128 (Chế độ CBC / GCM) bằng Python


<img width="1917" height="1077" alt="image" src="https://github.com/user-attachments/assets/b7b193a9-4b0e-40f1-8df7-fb902f5705a8" />




import os
         
         from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

         from cryptography.hazmat.primitives import padding

def aes_encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
  
    
         iv = os.urandom(16)
    
         padder = padding.PKCS7(128).padder()
    
         padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    
         cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
         encryptor = cipher.encryptor()
    
         ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
         return iv, ciphertext

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    
    
         cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
         decryptor = cipher.decryptor()
    
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    
        unpadder = padding.PKCS7(128).unpadder()
    
        data = unpadder.update(padded_data) + unpadder.finalize()
    
        return data.decode('utf-8')


 if __name__ == "__main__":
    
        secret_key = os.urandom(16)
    
        original_text = "Hệ thống An toàn và Bảo mật thông tin - Đại học TNUT"
    
        iv, encrypted_data = aes_encrypt(original_text, secret_key)
    print(f"Bản mã (Hex): {encrypted_data.hex()}")
    
        decrypted_text = aes_decrypt(encrypted_data, secret_key, iv)
    print(f"Bản giải mã: {decrypted_text}")

2. Thuật toán mã hóa bất đối xứng RSA

RSA dựa trên độ khó tính toán của bài toán phân tích một số nguyên lớn thành tích của hai số nguyên tố.

3. Các mô hình ứng dụng RSA & Bảng so sánh

Ký hiệu: A là người gửi, B là người nhận. PU_A, PR_A là khoá công khai và bí mật của A. PU_B, PR_B tương tự cho B.

Mô hình 1: Bảo mật (chỉ B đọc được)

A mã hoá bằng khoá công khai của B: C = E(PU_B, M). B giải mã bằng khoá bí mật của mình: M = D(PR_B, C).

Đảm bảo tính bí mật: chỉ B (người giữ PR_B) đọc được.

Không xác thực người gửi, vì ai cũng có PU_B nên ai cũng có thể gửi tin giả danh A.

Mô hình 2: Xác thực người gửi (chữ ký số)

A ký bằng khoá bí mật của A: S = E(PR_A, H(M)). Gửi (M, S). B kiểm tra bằng khoá công khai của A: D(PU_A, S) == H(M)?

Đảm bảo xác thực nguồn gốc, toàn vẹn và chống chối bỏ, vì chỉ A có PR_A.

Không bảo mật, vì M vẫn ở dạng rõ và ai cũng đọc được.

Thực tế người ta ký trên giá trị băm H(M) chứ không ký trực tiếp M, để nhanh và không bị giới hạn kích thước.

Mô hình 3: Cả bảo mật và xác thực (ký rồi mã hoá)

A ký M bằng PR_A để được S, rồi mã hoá (M ‖ S) bằng PU_B: C = E(PU_B, M ‖ E(PR_A, H(M))). B giải mã bằng PR_B, sau đó kiểm tra chữ ký bằng PU_A.

Đạt cả bảo mật (chỉ B đọc được) và xác thực người gửi (chỉ A ký được).

Ghi chú về thuật ngữ: trong nhiều giáo trình, "xác thực người nhận" được hiểu là mô hình 1 (chỉ người nắm PR_B mới đọc được), còn "xác thực người gửi" là mô hình 2. 
