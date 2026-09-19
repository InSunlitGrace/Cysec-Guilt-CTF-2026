#!/usr/bin/env python3
"""
Solver for the "Dominos" RSA + MT19937 + Shamir-style AES-key challenge.

Pipeline:
  1. Orthogonal-lattice attack (LLL) on the `hints` to recover the two
     secret primes p, q from hints[i] = a_i*p + b_i*q.
  2. RSA-decrypt c1 with the recovered p, q  -> flag part 1.
  3. Recover the exact a_i, b_i values, extract the raw 32-bit MT19937
     words that produced them, clone the `random.Random` (r1) state,
     and predict the words used to seed r2.
  4. Re-simulate r2 deterministically to regenerate rc, xs, and the
     shuffle permutation, undo the polynomial masking on published_y,
     and Lagrange-interpolate to recover the AES-256 key.
  5. AES-CBC decrypt ct2 -> flag part 2.

Requires: pip install fpylll cysignals cypari2 pycryptodome randcrack
"""

import json
import random
import functools

from fpylll import IntegerMatrix, LLL
import cypari2
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from randcrack import RandCrack

F = 18446744073709551557  # prime modulus used for the polynomial scheme

PARI = cypari2.Pari()


# --------------------------------------------------------------------------
# Step 1: recover p, q from the hints via an orthogonal-lattice (LLL) attack
# --------------------------------------------------------------------------
def recover_pq(hints, n):
    N = len(hints)
    K = 1 << 2000  # scaling constant, must dwarf the hint bit-length

    # Lattice basis: row i = (e_i, K*hint_i). LLL finds short combinations
    # c with sum(c_i * hint_i) == 0 exactly.
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

    # The genuinely short relations (a_i, b_i cancel exactly) form a
    # rank (N-2) sublattice; sort by norm and keep the short ones.
    relations.sort(key=lambda r: max(abs(x) for x in r))
    R = relations[: N - 2]

    # Saturated integer kernel of R (rank 2) via PARI's matkerint.
    flat = [x for row in R for x in row]
    Mpari = PARI.matrix(len(R), N, flat)
    ker = PARI.matkerint(Mpari)
    cols = []
    for j in range(1, ker.ncols() + 1):
        cols.append([int(ker[i, j - 1]) for i in range(N)])
    u, v = cols

    # Solve h = P*u + Q*v using two hint equations.
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

    # Recover the true per-hint coefficients A_i, B_i (up to the specific
    # unimodular relation found here: A = -u-v, B = -v works for this
    # construction; verify and fall back to a general search if needed).
    for A_expr, B_expr in [
        ([-u[i] - v[i] for i in range(N)], [-v[i] for i in range(N)]),
        ([u[i] for i in range(N)], [v[i] for i in range(N)]),
        ([-u[i] for i in range(N)], [-v[i] for i in range(N)]),
        ([v[i] for i in range(N)], [u[i] for i in range(N)]),
    ]:
        if all(hints[i] == A_expr[i] * p + B_expr[i] * q for i in range(N)):
            return p, q, A_expr, B_expr

    raise RuntimeError("could not resolve A, B from the recovered basis")


# --------------------------------------------------------------------------
# Step 2: RSA decrypt
# --------------------------------------------------------------------------
def rsa_decrypt(c1, e, p, q):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    n = p * q
    m = pow(c1, d, n)
    return long_to_bytes(m)


# --------------------------------------------------------------------------
# Step 3: clone MT19937 (r1) from the recovered A_i, B_i, predict r2_seed
# --------------------------------------------------------------------------
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

    # sanity check against the remaining known words
    remaining = words[624:]
    predicted = [rc.predict_getrandbits(32) for _ in range(len(remaining))]
    assert predicted == remaining, "MT19937 state recovery failed sanity check"

    seed_words = [rc.predict_getrandbits(32) for _ in range(8)]
    r2_seed = functools.reduce(lambda x, w: (x << 32) | w, seed_words, 0)
    return r2_seed


# --------------------------------------------------------------------------
# Step 4: re-simulate r2, undo the polynomial mask, recover the AES key
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(path="output.txt"):
    d = json.load(open(path))
    n, e, c1 = d["n"], d["e"], d["c1"]
    hints = d["hints"]
    published_y = d["published_y"]
    iv2 = bytes.fromhex(d["iv2"])
    ct2 = bytes.fromhex(d["ct2"])

    print("[*] Recovering p, q via orthogonal lattice attack...")
    p, q, A, B = recover_pq(hints, n)
    print(f"    p = {p}")
    print(f"    q = {q}")

    print("[*] RSA-decrypting c1...")
    flag1 = rsa_decrypt(c1, e, p, q)
    print(f"    flag part 1: {flag1}")

    print("[*] Cloning MT19937 state and predicting r2_seed...")
    r2_seed = recover_r2_seed(A, B)
    print(f"    r2_seed = {r2_seed}")

    print("[*] Recovering AES key via polynomial interpolation...")
    key = recover_aes_key(r2_seed, published_y)
    print(f"    key = {key.hex()}")

    print("[*] AES-CBC decrypting ct2...")
    pt = AES.new(key, AES.MODE_CBC, iv2).decrypt(ct2)
    flag2 = unpad(pt, 16)
    print(f"    flag part 2: {flag2}")

    print()
    print("FLAG:", (flag1 + flag2).decode())


if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "output.txt")