keys = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def binary(i, bits=32):
    py_binary = bin(i)[2:]
    return ("0" * (bits - len(py_binary))) + py_binary

def hex(i, bits=32):
    return format(i, '0' + str(bits // 4) + 'x')

def get_blocks(bin_str):
    block_size = 512
    for i in range(0, len(bin_str), block_size):
        yield bin_str[i:i+block_size]

def rotate(x, n, direction):
    assert direction in ("R", "L"), "Invalid direction"
    n %= 32
    if direction == "R":
        return (x >> n) | (x << (32 - n))
    else:
        return (x << n) | (x >> (32 - n))

def transform(x, mode):
    assert mode in (0, 1), "Invalid mode"
    if mode == 0:
        return (rotate(x, 7, "R") ^ rotate(x, 18, "R")) ^ (x >> 3)
    return (rotate(x, 17, "R") ^ rotate(x, 19, "R")) ^ (x >> 10)

def ch(e, f, g):
    return (e & f) ^ ((~e) & g)

def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)

def sigma1(a):
    return rotate(a, 2, "R") ^ rotate(a, 13, "R") ^ rotate(a, 22, "R")

def sigma2(e):
    return rotate(e, 6, "R") ^ rotate(e, 11, "R") ^ rotate(e, 25, "R")

def add(*values):
    return sum(values) % (2 ** 32)

def next_word(w, i):
    return add(transform(w[i - 2], 1), w[i - 7], transform(w[i - 15], 0), w[i - 16])

def pad(data):
    bin_str = ''.join(format(ord(ch), '08b') for ch in data) + '1'
    bin_str += '0' * ((-len(bin_str) - 64) % 512)
    bin_str += format(len(data) * 8, '064b')
    return bin_str

def compress(block, iv):
    a, b, c, d, e, f, g, h = iv
    words = [int(block[i:i+32], 2) for i in range(0, 512, 32)]
    for i in range(16, 64):
        words.append(next_word(words, i))
    for round_idx in range(64):
        t1 = add(h, sigma2(e), ch(e, f, g), keys[round_idx], words[round_idx])
        t2 = add(sigma1(a), maj(a, b, c))
        h, g, f, e, d, c, b, a = g, f, e, add(d, t1), c, b, a, add(t1, t2)
    return [add(i, j) for i, j in zip((a, b, c, d, e, f, g, h), iv)]

def sha256(data):
    states = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    bin_str = pad(data)
    for block in get_blocks(bin_str):
        states = compress(block, states)
    return ''.join(format(state, '08x') for state in states)

def hmac_sha256(key, message):
    if len(key) > 64:
        key = sha256(key)
    key = key.ljust(64, '\x00')
    
    inner_key_pad = ''.join([chr(ord(x) ^ 0x36) for x in key])
    outer_key_pad = ''.join([chr(ord(x) ^ 0x5C) for x in key])
    
    inner_hash = sha256(inner_key_pad + message)
    outer_hash = sha256(outer_key_pad + inner_hash)
    
    return outer_hash

if __name__ == "__main__":
    key = input("Enter the key: ")
    msg = input("\nEnter the message: ")
    hmac = hmac_sha256(key, msg)
    print("SHA256 hash:", sha256(msg))
    print("HMAC:", hmac)