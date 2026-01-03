from utils.math_utils import gcd, mod_inverse, power_mod
from utils.prime_utils import generate_prime

class RSA:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
    
    # Sinh cặp khóa RSA: public (e, n), private (d, n)
    def generate_keypair(self, verbose=False):
        if verbose:
            print(f"Đang sinh khóa RSA {self.key_size}-bit...")
        
        # Sinh p, q (2 số nguyên tố khác nhau)
        p = generate_prime(self.key_size // 2)
        q = generate_prime(self.key_size // 2)

        while p == q:
            q = generate_prime(self.key_size // 2)
        
        if verbose:
            print(f"  p = {p}")
            print(f"  q = {q}")
        
        # Tính n = p * q
        n = p * q
        self.n = n
        
        if verbose:
            print(f"  n = {n}")
        
        # phi(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        
        # Chọn e sao cho gcd(e, phi_n) = 1 (thường dùng 65537) (2 số nguyên tố cùng nhau)
        e = 65537
        if gcd(e, phi_n) != 1:
            e = 3
            while gcd(e, phi_n) != 1:
                e += 2
        
        if verbose:
            print(f"  e = {e}")
        
        # Tính d là nghịch đảo của e theo modulo phi(n)
        d = mod_inverse(e, phi_n)
        
        if verbose:
            print(f"  d = {d}")
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        if verbose:
            print("==> Sinh khóa thành công!\n")
        
        return self.public_key, self.private_key
    
    # Mã hóa: c = m^e mod n
    def encrypt(self, plaintext, public_key=None):
        if public_key is None:
            public_key = self.public_key
        
        e, n = public_key
        
        if plaintext >= n:
            raise ValueError(f"Plaintext phải < n")
        
        return power_mod(plaintext, e, n)
    
    # Giải mã: m = c^d mod n
    def decrypt(self, ciphertext, private_key=None):
        if private_key is None:
            private_key = self.private_key
        
        d, n = private_key
        
        return power_mod(ciphertext, d, n)
