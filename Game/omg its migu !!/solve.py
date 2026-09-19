def unxorshift_right(x, shift):
    y = x
    for _ in range(32 // shift):
        y = x ^ (y >> shift)
    return y & 0xffffffff

# We need the first 4 decrypted bytes to be "expl" (0x65 0x78 0x70 0x6c)
# First word XOR mask is r8 = 0xbd79375f
target = 0x6c707865 ^ 0xbd79375f   # = 0xd1094f3a

# Invert the hash to find the seed
rax_6 = unxorshift_right(target, 16)
inv_c2 = pow(0xc2b2ae35, -1, 2**32)
rax_4_xor = (rax_6 * inv_c2) & 0xffffffff
rax_4 = unxorshift_right(rax_4_xor, 13)
inv_85 = pow(0x85ebca6b, -1, 2**32)
rax_3 = (rax_4 * inv_85) & 0xffffffff
seed = unxorshift_right(rax_3, 16)

print(f"Seed: {seed} (0x{seed:x})")

# Decrypt the full 36-byte flag
constant = bytes.fromhex(
    "cde68f32acaa427b3f0fec212b772f40"
    "92cfce450cc4c292dbccb617c926532d"
)
r8 = 0xbd79375f
rsi = seed
out = bytearray()
for i in range(9):
    if i > 0:
        r8 = int.from_bytes(constant[(i-1)*4 : i*4], 'little')
    rax_3 = (rsi >> 16) ^ rsi
    rsi = (rsi - 0x61c88647) & 0xffffffff
    rax_4 = (rax_3 * 0x85ebca6b) & 0xffffffff
    rax_6 = ((rax_4 ^ (rax_4 >> 13)) * 0xc2b2ae35) & 0xffffffff
    rax_8 = (rax_6 ^ (rax_6 >> 16) ^ r8) & 0xffffffff
    out.extend(rax_8.to_bytes(4, 'little'))

print(out)