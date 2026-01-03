import random
from .math_utils import power_mod

# Test Miller-Rabin kiểm tra số nguyên tố
# n: số cần kiểm tra
def miller_rabin(n, k=5):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Viết n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Lặp k lần
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = power_mod(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = power_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

# Sinh số nguyên tố ngẫu nhiên có độ dài bits
def generate_prime(bits=16):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1))  # Set bit cao nhất
        n |= 1  # Đảm bảo số lẻ
        
        if miller_rabin(n, k=5):
            return n
