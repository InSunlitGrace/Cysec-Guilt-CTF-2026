class XORshift:
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF

    def next(self) -> int:
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        self.state = x
        return self.state

def decrypt(ciphertext: bytes, seed: int) -> bytes:
    rng = XORshift(seed)
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 4):
        key_bytes = rng.state.to_bytes(4, "big")
        block = ciphertext[i:i + 4]
        plaintext.extend(a ^ b for a, b in zip(block, key_bytes))
        rng.next()
    return bytes(plaintext)


ct = b'\x8e\xad\xa0"\x052E\xd4\x9bQr\xd3*\xf6Y\xfb\x01TB\xdejd_J\xa9\xe4\xbc\xf7Dq\x04\r \x12k\xc9%,J\x00m\x9dS\xc9e\xc7#\x98'

known_prefix = b'exploiitm{'

S0 = int.from_bytes(ct[:4], "big") ^ int.from_bytes(known_prefix[:4], "big")
print(f"Recovered: {hex(S0)}")


pt = decrypt(ct, S0)
flag = pt.rstrip(b"\x00").decode()
print(f"flagiz: {flag}")


ints = [130, 101, 250, 179, 100]
rng = XORshift(S0)


for _ in range(len(ct) // 4):
    rng.next()

print("\nverification")
for expected in ints:
    actual = rng.state & 0xFF
    print(f"{actual} == {expected} -> {actual == expected}")
    rng.next()