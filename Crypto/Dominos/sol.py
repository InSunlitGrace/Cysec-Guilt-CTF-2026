#!/usr/bin/env python3
import json
import random
import functools
from fpylll import IntegerMatrix, LLL
import cypari2
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from randcrack import RandCrack

F = 18446744073709551557 
PARI = cypari2.Pari()

def recover_pq(hints, n):
    N = len(hints)
    K = 1 << 2000 
    M = IntegerMatrix(N, N + 1)
    for i in range(N):
        M[i, i] = 1
        M[i, N] = K * hints[i]
    M2 = LLL.reduction(M)
    relations = []
    for i in range(N):
        row = [M2[i, j] for j in range(N + 1)]
        if row[N] == 0:
            relations.append(row[:N])

    relations.sort(key=lambda r: max(abs(x) for x in r))
    R = relations[: N - 2]

    flat = [x for row in R for x in row]
    Mpari = PARI.matrix(len(R), N, flat)
    ker = PARI.matkerint(Mpari)
    cols = []
    for j in range(1, ker.ncols() + 1):
        cols.append([int(ker[i, j - 1]) for i in range(N)])
    u, v = cols
    from sympy import Matrix

    i0, i1 = 0, 1
    A = Matrix([[u[i0], v[i0]], [u[i1], v[i1]]])
    b = Matrix([hints[i0], hints[i1]])
    sol = A.solve(b)
    P, Q = int(sol[0]), int(sol[1])

    p_cand = abs(P)
    assert n % p_cand == 0, "P is not a factor of n"
    p = p_cand
    q = n // p

    for A_expr, B_expr in [
        ([-u[i] - v[i] for i in range(N)], [-v[i] for i in range(N)]),
        ([u[i] for i in range(N)], [v[i] for i in range(N)]),
        ([-u[i] for i in range(N)], [-v[i] for i in range(N)]),
        ([v[i] for i in range(N)], [u[i] for i in range(N)]),
    ]:
        if all(hints[i] == A_expr[i] * p + B_expr[i] * q for i in range(N)):
            return p, q, A_expr, B_expr

    raise RuntimeError("could not resolve A, and B")

def rsa_decrypt(c1, e, p, q):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    n = p * q
    m = pow(c1, d, n)
    return long_to_bytes(m)

def words_from_int(x, nwords=10):
    b = x.to_bytes(4 * nwords, "big")
    return [int.from_bytes(b[i * 4:(i + 1) * 4], "big") for i in range(nwords)]

def recover_r2_seed(A, B):
    words = []
    for a_i, b_i in zip(A, B):
        words.extend(words_from_int(a_i))
        words.extend(words_from_int(b_i))

    rc = RandCrack()
    for w in words[:624]:
        rc.submit(w)
    remaining = words[624:]
    predicted = [rc.predict_getrandbits(32) for _ in range(len(remaining))]
    assert predicted == remaining, "MT recovery failed"

    seed_words = [rc.predict_getrandbits(32) for _ in range(8)]
    r2_seed = functools.reduce(lambda x, w: (x << 32) | w, seed_words, 0)
    return r2_seed

def eval_poly(coeffs, x, mod):
    s, xp = 0, 1
    for c in coeffs:
        s = (s + c * xp) % mod
        xp = (xp * x) % mod
    return s

def gauss_solve_mod(M, mod):
    n = len(M)
    M = [row[:] for row in M]
    for col in range(n):
        piv = next(r for r in range(col, n) if M[r][col] % mod != 0)
        M[col], M[piv] = M[piv], M[col]
        inv = pow(M[col][col], mod - 2, mod)
        M[col] = [(x * inv) % mod for x in M[col]]
        for r in range(n):
            if r != col and M[r][col] != 0:
                f = M[r][col]
                M[r] = [(M[r][k] - f * M[col][k]) % mod for k in range(n + 1)]
    return [M[i][n] for i in range(n)]

def recover_aes_key(r2_seed, published_y):
    r2 = random.Random(r2_seed)
    rc_list = [r2.getrandbits(64) % F for _ in range(8)]
    xs = []
    while len(xs) < 8:
        x = r2.getrandbits(64) % F
        if x not in xs:
            xs.append(x)
    prm = list(range(8))
    r2.shuffle(prm)

    xpoints, z = [], []
    for j in range(8):
        x = xs[prm[j]]
        zval = (published_y[j] - eval_poly(rc_list, x, F)) % F
        xpoints.append(x)
        z.append(zval)

    n = 8
    M = [[pow(xpoints[i], j, F) for j in range(n)] + [z[i]] for i in range(n)]
    k = gauss_solve_mod(M, F)

    k2 = b"".join(x.to_bytes(4, "big") for x in k)
    return k2

def main(path="output.txt"):
    d = json.load(open(path))
    n, e, c1 = d["n"], d["e"], d["c1"]
    hints = d["hints"]
    published_y = d["published_y"]
    iv2 = bytes.fromhex(d["iv2"])
    ct2 = bytes.fromhex(d["ct2"])
    print("OLAtack")
    p, q, A, B = recover_pq(hints, n)
    print(f"    p = {p}")
    print(f"    q = {q}")
    print("Decyrpting c1)
    flag1 = rsa_decrypt(c1, e, p, q)
    print(f"    flag part 1: {flag1}")
    print("[cloning mt19937")
    r2_seed = recover_r2_seed(A, B)
    print(f"    r2_seed = {r2_seed}")
    print("revovering aes through polynomial")
    key = recover_aes_key(r2_seed, published_y)
    print(f"    key = {key.hex()}")
    print("[decrypting ct2")
    pt = AES.new(key, AES.MODE_CBC, iv2).decrypt(ct2)
    flag2 = unpad(pt, 16)
    print(f"    flag part 2: {flag2}")

    print()
    print("FLAG:", (flag1 + flag2).decode())


if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "output.txt")