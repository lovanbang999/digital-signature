from crypto.sha256 import SHA256
from crypto.rsa import RSA

# Header ASN.1 cho SHA-256 theo PKCS#1
SHA256_DIGEST_INFO = bytes([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20
])

class DigitalSignature:
    def __init__(self, key_size=512):
        self.rsa = RSA(key_size=key_size)
        self.sha256 = SHA256()
        self.public_key = None
        self.private_key = None
        self.key_size = key_size

    # Thêm padding PKCS#1 v1.5 vào hash
    def pkcs1_pad(self, hash_bytes: bytes, key_size_bytes: int) -> int:
        digest_info = SHA256_DIGEST_INFO + hash_bytes
        ps_len = key_size_bytes - 3 - len(digest_info)
        if ps_len < 8:
            raise ValueError(f"Key quá ngắn cho PKCS#1 v1.5 padding. Cần ít nhất {len(digest_info) + 11} bytes")
        em = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + digest_info
        return int.from_bytes(em, 'big')

    # Gỡ padding và lấy hash ra
    def pkcs1_unpad(self, signature_int: int, key_size_bytes: int) -> bytes:
        if signature_int.bit_length() > key_size_bytes * 8:
            return None
        em = signature_int.to_bytes(key_size_bytes, 'big')
        if len(em) < 11 or em[0:2] != b'\x00\x01':
            return None
        sep_idx = em.find(b'\x00', 2)
        if sep_idx == -1 or sep_idx < 10:
            return None
        if not all(b == 0xff for b in em[2:sep_idx]):
            return None
        digest_info_and_hash = em[sep_idx + 1:]
        if not digest_info_and_hash.startswith(SHA256_DIGEST_INFO):
            return None
        hash_value = digest_info_and_hash[len(SHA256_DIGEST_INFO):]
        return hash_value if len(hash_value) == 32 else None

    # Tạo cặp key mới
    def generate_keys(self, verbose=False):
        self.public_key, self.private_key = self.rsa.generate_keypair(verbose=verbose)
        return self.public_key, self.private_key

    # Ký dữ liệu với private key
    def sign(self, message, private_key=None):
        if private_key is None:
            private_key = self.private_key
        if private_key is None:
            raise ValueError("Chưa có private key. Hãy gọi generate_keys() trước.")
        d, n = private_key
        key_size_bytes = (n.bit_length() + 7) // 8
        hash_hex = self.sha256.hash(message)
        hash_bytes = bytes.fromhex(hash_hex)
        print(f"SHA-256 Hash: {hash_hex}")
        padded_message = self.pkcs1_pad(hash_bytes, key_size_bytes)
        print(f"PKCS#1 v1.5 Padded (int): {padded_message}")
        return self.rsa.decrypt(padded_message, private_key)

    # Kiểm tra chữ ký có đúng không
    def verify(self, message, signature, public_key=None):
        if public_key is None:
            public_key = self.public_key
        if public_key is None:
            raise ValueError("Chưa có public key.")
        e, n = public_key
        key_size_bytes = (n.bit_length() + 7) // 8
        decrypted = self.rsa.encrypt(signature, public_key)
        extracted_hash = self.pkcs1_unpad(decrypted, key_size_bytes)
        if extracted_hash is None:
            print("PKCS#1 v1.5 padding không hợp lệ!")
            return False
        hash_hex = self.sha256.hash(message)
        return extracted_hash == bytes.fromhex(hash_hex)

    # Hash message bằng SHA-256
    def get_hash(self, message):
        return self.sha256.hash(message)

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key
