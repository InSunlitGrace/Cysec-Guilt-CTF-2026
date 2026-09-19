#!/usr/bin/env python3

import sys
import math
from pwn import * 
context.log_level = 'info'

N  = 0xDB02EB1DDCDB0798F63CA143C24EE00240F4430E724843BAC31E4A764BA05DF3
pX = 0x35495D877123DB4181BA781D843E07194FE8B707FB0C70E095636A54F68398BE
pY = 0xA11AF18E9EDC908ABE6C97D1C6964C9147855889F44F749902BD7069206899C6
WIN = int.from_bytes(b"You've been pwned", "big")


def H(amount):
    return int.from_bytes(f"money {amount}".encode(), "big")

class Curve:
    def __init__(self, p, a, b):
        self.p, self.a, self.b = p, a, b


class Pt:
    def __init__(self, curve, x, y):
        self.c, self.x, self.y = curve, x, y

    def is_inf(self):
        return self.x is None

    @staticmethod
    def inf(curve):
        return Pt(curve, None, None)

    def __neg__(self):
        if self.is_inf():
            return self
        return Pt(self.c, self.x, (-self.y) % self.c.p)

    def dbl(self):
        if self.is_inf() or self.y % self.c.p == 0:
            return Pt.inf(self.c)
        p = self.c.p
        lam = (3 * self.x * self.x + self.c.a) * pow(2 * self.y, -1, p) % p
        x3 = (lam * lam - 2 * self.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Pt(self.c, x3, y3)

    def __add__(self, o):
        if self.is_inf():
            return o
        if o.is_inf():
            return self
        p = self.c.p
        if self.x == o.x:
            if (self.y + o.y) % p == 0:
                return Pt.inf(self.c)
            return self.dbl()
        lam = (o.y - self.y) * pow((o.x - self.x) % p, -1, p) % p
        x3 = (lam * lam - self.x - o.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Pt(self.c, x3, y3)

    def __mul__(self, n):
        if n < 0:
            return (-self) * (-n)
        r = Pt.inf(self.c)
        a = self
        n = int(n)
        while n:
            if n & 1:
                r = r + a
            a = a.dbl()
            n >>= 1
        return r

    __rmul__ = __mul__


def sqrt_mod_p3mod4(a, p):
    r = pow(a, (p + 1) // 4, p)
    return r if (r * r - a) % p == 0 else None

def lift(curve, x):
    rhs = (x ** 3 + curve.a * x + curve.b) % curve.p
    y = sqrt_mod_p3mod4(rhs, curve.p)
    if y is None:
        return None
    return (Pt(curve, x, y), Pt(curve, x, (-y) % curve.p))

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

curve = Curve(N, 1, 4)
G = Pt(curve, pX, pY)

def menu_choice(io, n):
    io.recvuntil(b"6. Exit\n")
    io.sendline(str(n).encode())

def flip_coin_once(io):
    menu_choice(io, 1)
    io.recvuntil(b"'heads' or 'tails'? ")
    io.sendline(b"heads")
    io.recvuntil(b"sacred wager of gold coins: ")
    io.sendline(b"1")
    io.recvline()  # win/lose message
    io.recvline()  # wallet total line

def convert_chips(io):
    menu_choice(io, 4)
    io.recvuntil(b"summon thee code\n")
    code = io.recvline().strip().decode()
    line = io.recvline().decode()
    amount = int(line.split(":")[1].strip())
    return amount, code

def claim(io, amount, code):
    menu_choice(io, 5)
    io.recvuntil(b"Declare the amount ye wish to claim: ")
    io.sendline(str(amount).encode())
    io.recvuntil(b"Pray, give thy enchanted code: ")
    io.sendline(code.encode())
    return io.recvall(timeout=3).decode(errors="replace")


def main():
    if len(sys.argv) >= 3:
        io = remote(sys.argv[1], int(sys.argv[2]))
    else:
        io = process(["python3", "chal.py"])

    x1, S1 = convert_chips(io)
    log.info(f"signed x1={x1} -> {S1}")
    flip_coin_once(io)
    x1p, S1p = convert_chips(io)
    log.info(f"signed x1p={x1p} -> {S1p}")
    m1, m1p = H(x1), H(x1p)
    g, a, b = egcd(m1, m1p)
    log.info(f"gcd(m1, m1p) = {g}")
    assert g == 1, "unlucky coprimality"
    R1_opts = lift(curve, int(S1, 16))
    R1p_opts = lift(curve, int(S1p, 16))
    assert R1_opts and R1p_opts, "point lift failed"

    Q = None
    for R1 in R1_opts:
        for R1p in R1p_opts:
            cand = (R1 * a) + (R1p * b)
            if cand.is_inf():
                continue
            chk1 = cand * m1
            if chk1.is_inf() or format(chk1.x, "x").rjust(len(S1), "0") != S1.rjust(len(S1), "0"):
                pass
            def to_hex(pt):
                if pt.is_inf():
                    return None
                nb = (pt.x.bit_length() + 7) // 8
                return pt.x.to_bytes(nb, "big").hex()
            if to_hex(cand * m1) == S1 and to_hex(cand * m1p) == S1p:
                Q = cand
                break
        if Q:
            break

    assert Q is not None, "failed to recover Q"
    log.success("recovered Q")
    amount2 = WIN + 1
    m2 = H(amount2)
    forged = Q * m2
    nb = (forged.x.bit_length() + 7) // 8
    code2 = forged.x.to_bytes(nb, "big").hex()

    log.info(f"forging code for amount2={amount2}")
    out = claim(io, amount2, code2)
    print(out)


if __name__ == "__main__":
    main()