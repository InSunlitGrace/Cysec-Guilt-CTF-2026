#!/usr/bin/env python3
import random
from math import isqrt
from hashlib import sha1
from sympy import factorint
from sympy.ntheory.modular import crt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = 106267532015697168520337191172088148412515620576161290874946589402878151571249
D = 42233242539448005099475028269993990446352013294366498148311505626717263001612
G = (102048330668061011078177084521527399007542737797660957136363503399801919446230,
     73159115351277642048716110709055707500362539496317081461959122153668971225415)
A = (13576866167002229829628682212089073935524598703068420926007376235818728075607,
     24596311476190289480258356776256149104553730312606239661463353580061167337137)
B = (25969029228340787796927547951552192885641602829554221315818875377640814404070,
     55051918571465903426055630502090765909144252223579472291416558946996065912443)
IV_HEX = "90ebd72eb142152246c7ed29d09d7f4f"
CT_HEX  = "4ca3655a9d842a47cc9db587dbcdb36c6f822acd1f2c84ede72473d81b7b6c6bbdcd2b12a7a1999b9c10bb44b4d78153"

def mul(P, Q):
    x1, y1 = P; x2, y2 = Q
    return ((x1*x2 + D*y1*y2) % p, (x1*y2 + x2*y1) % p)

def power(P, n):
    R = (1, 0)
    while n > 0:
        if n & 1:
            R = mul(R, P)
        P = mul(P, P)
        n >>= 1
    return R

def inv(P):
    x, y = P
    nrm = (x*x - D*y*y) % p
    ninv = pow(nrm, p-2, p)
    return ((x*ninv) % p, ((-y)*ninv) % p)

def bsgs(g, h, order):
    m = isqrt(order) + 1
    table = {}
    e = (1, 0)
    for j in range(m):
        table[e] = j
        e = mul(e, g)
    g_m_inv = inv(power(g, m))
    cur = h
    for i in range(m+1):
        if cur in table:
            x = (i*m + table[cur]) % order
            if power(g, x) == h:
                return x
        cur = mul(cur, g_m_inv)
    return None

def dlog_prime_power(g_full, h_full, q, e):
    order = q**e
    gamma = power(g_full, q**(e-1))          # order q elem
    x = 0
    for k in range(e):
        hh = mul(h_full, inv(power(g_full, x)))
        hk = power(hh, q**(e-1-k))
        dk = bsgs(gamma, hk, q)
        if dk is None:
            raise RuntimeError(f"BSGS failed q={q} e={e} k={k}")
        x += dk * (q**k)
    return x % order

assert pow(D, (p-1)//2, p) == p - 1, "D is QR"

def norm(P): return (P[0]*P[0] - D*P[1]*P[1]) % p
assert norm(G) == norm(A) == norm(B) == 1

N = p + 1

Nfactors = factorint(N)          

def component_order(P, q, e):
    x = power(P, N // (q**e))
    for kk in range(e+1):
        if power(x, q**kk) == (1, 0):
            return kk
    return e

ordG_factors = {q: component_order(G, q, e) for q, e in Nfactors.items() if component_order(G, q, e) > 0}
ordG = 1
for q, e in ordG_factors.items():
    ordG *= q**e

residues, moduli = [], []
for q, e in ordG_factors.items():
    qe = q**e
    g_i = power(G, ordG // qe)
    h_i = power(B, ordG // qe)
    xi = dlog_prime_power(g_i, h_i, q, e)
    residues.append(xi)
    moduli.append(qe)

n_b = crt(moduli, residues)[0] % ordG
assert power(G, n_b) == B


shared_x = power(A, n_b)[0]
key = sha1(str(shared_x).encode()).digest()[:16]
iv = bytes.fromhex(IV_HEX)
ct = bytes.fromhex(CT_HEX)
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

print(pt.decode())