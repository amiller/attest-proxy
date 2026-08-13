# NIST P-256 ECDSA verification, standard library only.
P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A  = P - 3
B  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, pt):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt = _add(pt, pt); k >>= 1
    return r


def verify(pub64: bytes, sig64: bytes, digest: bytes) -> bool:
    """pub64 = X||Y raw, sig64 = r||s raw, digest = the hash that was signed."""
    qx = int.from_bytes(pub64[:32], "big"); qy = int.from_bytes(pub64[32:], "big")
    if (qy * qy - (qx * qx * qx + A * qx + B)) % P != 0:
        return False                       # point not on the curve
    r = int.from_bytes(sig64[:32], "big"); s = int.from_bytes(sig64[32:], "big")
    if not (0 < r < N and 0 < s < N): return False
    e = int.from_bytes(digest, "big")
    w = pow(s, N - 2, N)
    pt = _add(_mul(e * w % N, (GX, GY)), _mul(r * w % N, (qx, qy)))
    return pt is not None and pt[0] % N == r
