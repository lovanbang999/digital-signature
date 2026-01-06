# Digital Signature System

Hệ thống chữ ký số tự xây dựng từ đầu (from scratch) sử dụng **RSA + SHA-256** với **PKCS#1 v1.5 padding**.

## Tính năng

- **RSA Key Generation** - Sinh cặp khóa RSA (512/1024/2048 bit)
- **SHA-256 Hashing** - Thuật toán băm tự cài đặt theo chuẩn FIPS 180-4
- **Digital Signature** - Ký và xác thực văn bản với PKCS#1 v1.5
- **PDF Signing** - Ký file PDF theo chuẩn PAdES (sử dụng pyHanko)
- **Web Interface** - Giao diện web thân thiện

## Cấu trúc project

```
digital-signature/
├── backend/
│   ├── utils/
│   │   ├── math_utils.py       # GCD, mod_inverse, power_mod
│   │   └── prime_utils.py      # Miller-Rabin, generate_prime
│   ├── crypto/
│   │   ├── rsa.py              # RSA encrypt/decrypt
│   │   └── sha256.py           # SHA-256 hash
│   ├── signature/
│   │   ├── digital_signature.py # RSA + SHA256 + PKCS#1 v1.5
│   │   └── pdf_signature.py    # PDF signing (PAdES)
│   └── main.py                 # FastAPI server
└── frontend/
    ├── index.html
    ├── script.js
    └── styles.css
```

## Cài đặt và chạy

### Yêu cầu
- Python 3.8+

### Cài đặt dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Chạy server
```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Server sẽ chạy tại: http://localhost:8000

### API Documentation
Truy cập: http://localhost:8000/docs

## API Endpoints

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| POST | `/generate-keys` | Sinh cặp khóa RSA |
| POST | `/sign` | Ký file |
| POST | `/verify` | Xác thực chữ ký |
| GET | `/directory` | Danh sách public keys |
| POST | `/sign-pdf` | Ký PDF (PAdES) |
| POST | `/verify-pdf` | Xác thực PDF |

## Thuật toán

### RSA Key Generation
1. Sinh 2 số nguyên tố lớn p, q (Miller-Rabin test)
2. Tính n = p × q
3. Tính φ(n) = (p-1)(q-1)
4. Chọn e = 65537 (số Fermat)
5. Tính d = e⁻¹ mod φ(n) (Extended Euclidean)

### Digital Signature (PKCS#1 v1.5)
```
Sign:   hash = SHA256(message)
        padded = PKCS1_PAD(hash)
        signature = padded^d mod n

Verify: decrypted = signature^e mod n
        hash' = PKCS1_UNPAD(decrypted)
        valid = (hash' == SHA256(message))
```

### PKCS#1 v1.5 Padding Format
```
EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || Hash
```

## License

MIT License
