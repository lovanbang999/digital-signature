# Tính ước chung lớn nhất (Euclid)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Euclid mở rộng: trả về (g, x, y) sao cho a*x + b*y = g = gcd(a, b)
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    return gcd_val, y1 - (b // a) * x1, x1

# Tính nghịch đảo modulo: tìm x sao cho (a*x) % m = 1
def mod_inverse(a, m):
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError("Nghịch đảo modulo không tồn tại")
    return (x % m + m) % m

# Tính (base^exponent) % modulus - Square and Multiply
def power_mod(base, exponent, modulus):
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

