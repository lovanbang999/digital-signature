from crypto.sha256 import SHA256
from crypto.rsa import RSA

# Chữ ký số: SHA-256 + RSA
# Ký:        sig = RSA(hash(message), private_key)
# Xác thực:    hash(message) == RSA(sig, public_key)
class DigitalSignature:
    def __init__(self, key_size=512):
        self.rsa = RSA(key_size=key_size)
        self.sha256 = SHA256()
        self.public_key = None
        self.private_key = None
    
    # Sinh cặp khóa
    def generate_keys(self, verbose=False):
        self.public_key, self.private_key = self.rsa.generate_keypair(verbose=verbose)
        return self.public_key, self.private_key
    
    # Ký message bằng private key
    def sign(self, message, private_key=None):
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            raise ValueError("Chưa có private key. Hãy gọi generate_keys() trước.")
        
        # Hash message bằng SHA-256
        hash_value = self.sha256.hash_int(message)
        
        print(f"SHA-256 Hash (int): {hash_value}")
        
        # Mã hóa hash bằng private key Đảm bảo hash < n
        d, n = private_key        
        hash_value = hash_value % n
        print(f"Hash after mod n: {hash_value}")
        
        # Sign = hash^d mod n
        signature = self.rsa.decrypt(hash_value, private_key)
        
        return signature
    
    # Xác minh chữ ký
    def verify(self, message, signature, public_key=None):
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            raise ValueError("Chưa có public key.")
        
        # Hash message bằng SHA-256
        hash_value = self.sha256.hash_int(message)
        
        # Giải mã signature bằng public key
        e, n = public_key
        hash_value = hash_value % n
        
        # decrypted_hash = signature^e mod n
        decrypted_hash = self.rsa.encrypt(signature, public_key)
        
        return hash_value == decrypted_hash
    
    # Lấy hash của message (dạng hex)
    def get_hash(self, message):
        return self.sha256.hash(message)
    
    # Lấy public key
    def get_public_key(self):
        return self.public_key
    
    # Lấy private key 
    def get_private_key(self):
        return self.private_key
