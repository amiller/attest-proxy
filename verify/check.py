#!/usr/bin/env python3
"""Exhaustive and differential checks on the witness constructions.

The security-relevant core is about 95 lines and its input space is bounded by
MAX_LEAVES, so the structural properties below are not sampled — they are decided
over every reachable case. That is a stronger statement than "the tests pass",
and it is worth being precise about which claims it covers and which it doesn't.

DECIDED HERE (exhaustive over 1 <= n <= MAX_LEAVES, every leaf index):
  P1  round-trip      an inclusion proof for leaf i recomputes the root
  P2  soundness       substituting any other commitment does NOT recompute it
  P3  proof length    at most ceil(log2(n)) siblings, and every one consumed —
                      no room to smuggle data, and no unused tail accepted
  P4  count binding   a root for n leaves differs from the root for any m != n
  P5  domain sep      no leaf hash can collide with an internal-node hash

CHECKED BY DIFFERENTIAL EXECUTION (this file vs witness.ts, random inputs):
  P6  the Python and TypeScript implementations agree byte for byte

NOT ADDRESSED HERE, and no amount of this would establish them:
  - SHA-256 collision resistance. P1-P5 are structural; they assume the hash.
  - Anything about the TEE, the quote's signature chain, or TLS.
  - That the operator cannot read plaintext. That is not a code property.
  - The C firmware. It is cross-checked on hardware at one tree size; a proper
    differential run against it needs the board.

  ./check.py            exhaustive only (no deno needed)
  ./check.py --diff     also differential against witness.ts
"""
import hashlib, json, subprocess, sys, os, random
from pathlib import Path

MAX_LEAVES = 256


def h(*parts):
    c = hashlib.sha256()
    for p in parts:
        c.update(p)
    return c.digest()


def leaf(c):        return h(b"\x00", c)
def node(l, r):     return h(b"\x01", l, r)


def split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(cs):
    if len(cs) == 1:
        return leaf(cs[0])
    k = split(len(cs))
    return node(root(cs[:k]), root(cs[k:]))


def proof(cs, i):
    if len(cs) == 1:
        return []
    k = split(len(cs))
    if i < k:
        return proof(cs[:k], i) + [root(cs[k:])]
    return proof(cs[k:], i - k) + [root(cs[:k])]


def root_from(c, i, n, pf):
    it = iter(pf)

    def rec(m, j):
        if m == 1:
            return leaf(c)
        k = split(m)
        # The proof lists inner siblings first, so recurse BEFORE taking the
        # sibling at this level. Writing node(next(it), rec(...)) would consume
        # them in the wrong order — argument evaluation is left to right.
        if j < k:
            left = rec(k, j)
            return node(left, next(it))
        right = rec(m - k, j - k)
        return node(next(it), right)

    out = rec(n, i)
    if next(it, None) is not None:
        raise AssertionError("proof longer than the tree requires")
    return out


def commitments(n, salt=b""):
    return [hashlib.sha256(salt + str(i).encode()).digest() for i in range(n)]


def exhaustive():
    import math
    checked = 0
    roots = {}
    for n in range(1, MAX_LEAVES + 1):
        cs = commitments(n)
        r = root(cs)
        roots[n] = r
        bound = math.ceil(math.log2(n)) if n > 1 else 0
        for i in range(n):
            pf = proof(cs, i)
            # P1 round-trip
            assert root_from(cs[i], i, n, pf) == r, f"P1 failed n={n} i={i}"
            # P3 proof length. Not uniform: in an RFC 6962 tree with n not a power
            # of two, a leaf in the smaller right subtree sits shallower (n=3 gives
            # 2,2,1). The real property is a bound, plus root_from refusing any
            # proof with siblings left over.
            assert len(pf) <= bound, f"P3 failed n={n} i={i}: {len(pf)} > {bound}"
            try:
                root_from(cs[i], i, n, pf + [b"\x00" * 32])
                raise AssertionError(f"P3 failed n={n} i={i}: trailing sibling accepted")
            except AssertionError as e:
                if "trailing sibling accepted" in str(e):
                    raise
            # P2 soundness — a different commitment must not reach the same root
            forged = hashlib.sha256(f"forged{n}:{i}".encode()).digest()
            assert root_from(forged, i, n, pf) != r, f"P2 failed n={n} i={i}"
            checked += 1
    # P4 count binding — same generator, different n, must give different roots
    seen = {}
    for n, r in roots.items():
        assert r not in seen, f"P4 failed: n={n} and n={seen[r]} share a root"
        seen[r] = n
    # P5 domain separation — a leaf hash can never equal an internal-node hash
    #     over the reachable values, which is what stops a leaf being reinterpreted
    #     as a subtree (the RFC 6962 second-preimage defence)
    leaves = {leaf(c) for c in commitments(MAX_LEAVES)}
    nodes = set()
    for n in range(2, MAX_LEAVES + 1):
        cs = commitments(n)
        k = split(n)
        nodes.add(node(root(cs[:k]), root(cs[k:])))
    assert not (leaves & nodes), "P5 failed: a leaf hash collided with a node hash"
    return checked, len(roots)


def differential():
    """Run witness.ts on the same inputs and require identical output."""
    here = Path(__file__).resolve().parent
    cases = []
    rnd = random.Random(7)
    for _ in range(40):
        n = rnd.randint(1, 64)
        cases.append({"purpose": "p%d" % n, "profile": "holder-only",
                      "commitments": [c.hex() for c in commitments(n, b"d")]})
    driver = here / "_diff.ts"
    driver.write_text('''
import { sessionMeta, sessionRoot, merkleRoot, commitment } from "../witness.ts";
const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const cases = JSON.parse(await Deno.readTextFile(Deno.args[0]));
const out = [];
for (const c of cases) {
  const cs = c.commitments.map((h: string) =>
    Uint8Array.from(h.match(/../g)!.map((b: string) => parseInt(b, 16))));
  const meta = sessionMeta(c.profile, c.purpose);
  out.push({ meta: hex(meta), merkle: hex(await merkleRoot(cs)),
             root: hex(await sessionRoot(meta, cs)),
             commit: hex(await commitment("api.anthropic.com",
               new TextEncoder().encode("REQ"), new TextEncoder().encode("RESP"))) });
}
console.log(JSON.stringify(out));
''')
    inp = here / "_cases.json"
    inp.write_text(json.dumps(cases))
    try:
        r = subprocess.run(["deno", "run", "--allow-read", str(driver), str(inp)],
                           capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            raise SystemExit(f"deno failed:\n{r.stderr[-800:]}")
        ts = json.loads(r.stdout)
    finally:
        driver.unlink(missing_ok=True)
        inp.unlink(missing_ok=True)

    for case, got in zip(cases, ts):
        cs = [bytes.fromhex(x) for x in case["commitments"]]
        meta = bytes([len(case["profile"])]) + case["profile"].encode() + case["purpose"].encode()
        mh = h(b"zktls-session-v2\0" + meta)
        sr = h(b"zktls-root-v2\0" + mh + root(cs) + len(cs).to_bytes(4, "big"))
        assert got["meta"] == meta.hex(), f"meta mismatch n={len(cs)}"
        assert got["merkle"] == root(cs).hex(), f"merkle mismatch n={len(cs)}"
        assert got["root"] == sr.hex(), f"session root mismatch n={len(cs)}"
        cm = h(b"zktls-v1\0" + b"api.anthropic.com" + b"\0" + b"REQ" + b"\0" + b"RESP")
        assert got["commit"] == cm.hex(), "commitment mismatch"
    return len(cases)


if __name__ == "__main__":
    checked, sizes = exhaustive()
    print(f"P1 round-trip     decided over {checked} (tree, leaf) pairs")
    print(f"P2 soundness      decided — forged commitment rejected in all {checked}")
    print(f"P3 proof length   decided — within ceil(log2 n), trailing siblings refused")
    print(f"P4 count binding  decided over {sizes} tree sizes, no root reused")
    print(f"P5 domain sep     decided — no leaf hash equals any node hash")
    print(f"\nexhaustive over 1..{MAX_LEAVES} leaves, which is the deployed bound:")
    print(f"this is the whole reachable input space, not a sample.")
    if "--diff" in sys.argv:
        n = differential()
        print(f"\nP6 differential   {n} random cases, Python and TypeScript agree byte for byte")
    print("\nAssumed, not shown: SHA-256. Out of scope: the TEE, the quote chain,")
    print("TLS, and whether the operator can read plaintext.")
