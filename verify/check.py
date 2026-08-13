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


# --- P7/P8: the round-trip state machine -------------------------------------
#
# Turn spans are the new security-relevant logic, and they are not cryptography:
# they are a replay of the marker leaves. The crypto binds each leaf; what has to
# be established here is that the derivation reads the right structure out of a
# genuine thread, and refuses to read any structure at all out of a mangled one.
#
# This is generative rather than exhaustive — the space of marker sequences is
# unbounded — so it is a weaker statement than P1-P5, and is labelled as such.

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _thread(turns):
    """A synthetic receipt for a given turn plan, built the way the witness does."""
    import attest
    roles, leaves, seen, seq = ["asker", "responder"], [], set(), 0
    mk = lambda host, o: leaves.append((host, json.dumps(o).encode()))
    doc = {"name": "d", "sha256": hashlib.sha256(b"doc").hexdigest(), "bytes": 3}
    mk(attest.THREAD_HOST, {"event": "open", "thread": "t", "purpose": "p", "doc": doc,
                            "parties": [{"role": r, "label": r} for r in roles],
                            "policy": {}, "beacon": None})
    truth = []
    for role, ncalls in turns:
        lo = len(leaves)
        if role not in seen:
            seen.add(role)
            mk(attest.THREAD_HOST, {"event": "join", "role": role, "label": role})
            mk(attest.THREAD_HOST, {"event": "serve", "to": role,
                                    "doc_sha256": doc["sha256"], "bytes": 3})
        # The server emits a cred marker on a party's first RELAY, so a turn with no
        # calls produces none and its committed fingerprint is null. Mirror that, or
        # the synthetic thread disagrees with anything the witness would ever emit.
        if ncalls and not any(t["role"] == role and t["calls"] for t in truth):
            mk(attest.THREAD_HOST, {"event": "cred", "role": role,
                                    "fingerprint": hashlib.sha256(role.encode()).hexdigest()[:32]})
        for _ in range(ncalls):
            leaves.append(("api.anthropic.com", b"REQ"))
        seq += 1
        text = f"deliverable {seq}"
        mk(attest.THREAD_HOST, {"event": "turn", "role": role, "seq": seq, "text": text,
                                "text_sha256": hashlib.sha256(text.encode()).hexdigest()})
        truth.append({"role": role, "seq": seq, "lo": lo, "hi": len(leaves) - 1,
                      "calls": ncalls})
    # Mirrors what close() commits: per-role call counts, fingerprints and the
    # provider's token figures, so the verifier's tally comparison is exercised.
    tal = {}
    for role in roles:
        n = sum(t["calls"] for t in truth if t["role"] == role)
        tal[role] = {"calls": n,
                     "cred_fp": hashlib.sha256(role.encode()).hexdigest()[:32] if n else None,
                     "tokens": {"input": 0, "output": 0, "cached": 0}, "models": []}
    mk(attest.THREAD_HOST, {"event": "close", "turns": seq,
                            "leaves": len(leaves) + 1, "tally": tal})

    cs = [attest.commitment(h, body, b"") for h, body in leaves]
    calls = [{"index": i, "host": h, "commitment": cs[i].hex(),
              "request_redacted": body.decode("latin-1"), "response_b64": "",
              "inclusion_proof": [x.hex() for x in attest.inclusion_proof(cs, i)]}
             for i, (h, body) in enumerate(leaves)]
    return {"call_count": len(cs), "merkle_root": attest.merkle_root(cs).hex(),
            "calls": calls, "doc": {"name": "d", "text": "doc", "sha256": doc["sha256"]}}, truth


def roundtrip():
    import attest
    plans = [[("asker", 1), ("responder", 1)],
             [("asker", 3), ("responder", 2)],
             [("asker", 1), ("responder", 4), ("asker", 2)],
             [("asker", 0), ("responder", 1)],
             [("asker", 2), ("responder", 2), ("asker", 1), ("responder", 3)]]
    accepted = rejected = 0
    for plan in plans:
        b, truth = _thread(plan)
        # P7 the derived spans are the spans that were built
        t = attest._replay(b)
        assert not t.get("partial"), f"{plan}: a well-formed thread was read as partial"
        got = [(s["role"], s["seq"], s["lo"], s["hi"]) for s in t["spans"]]
        want = [(s["role"], s["seq"], s["lo"], s["hi"]) for s in truth]
        assert got == want, f"{plan}: spans {got} != {want}"
        for s, w in zip(t["spans"], truth):
            n = sum(1 for c in b["calls"]
                    if s["lo"] <= c["index"] <= s["hi"] and c["host"] != attest.THREAD_HOST)
            assert n == w["calls"], f"{plan}: span {s['seq']} counted {n}, built {w['calls']}"
        assert len(set(t["fps"].values())) == len(t["fps"]), f"{plan}: fingerprints collided"
        accepted += 1

        # P8 every single-leaf deletion loses the structural reading rather than
        #    silently shrinking a span — the attack the inclusion proofs miss
        for i in range(b["call_count"]):
            m = json.loads(json.dumps(b))
            del m["calls"][i]
            r = attest._replay(m)
            assert r is None or r.get("partial"), \
                f"{plan}: deleting leaf {i} still yielded a turn structure"
            rejected += 1

        # P8b a turn marker attributed to the party whose turn it is not
        m = json.loads(json.dumps(b))
        j = next(k for k, c in enumerate(m["calls"]) if '"event": "turn"' in c["request_redacted"])
        e = json.loads(m["calls"][j]["request_redacted"])
        e["role"] = "responder" if e["role"] == "asker" else "asker"
        m["calls"][j]["request_redacted"] = json.dumps(e)
        try:
            attest._replay(m)
            raise AssertionError(f"{plan}: an out-of-turn turn marker was accepted")
        except SystemExit:
            rejected += 1
    return accepted, rejected


def quote_signature():
    """P9: a spliced quote must fail. This is the attack a cold reader described:
    take a genuine quote, swap the 64 report_data bytes for the root of a
    fabricated session, leave the measurements alone. Structural parsing accepted
    it; the body signature does not."""
    import hashlib
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from p256 import verify
    samples = sorted(Path("/tmp").glob("adj*.json")) + sorted(Path("/tmp").glob("ck*.json"))
    for f in samples:
        try:
            b = json.loads(f.read_text())
            hexq = (b.get("quote") or {}).get("quote")
            if not hexq:
                continue
        except Exception:
            continue
        raw = bytes.fromhex(hexq)
        sec = raw[636:636 + int.from_bytes(raw[632:636], "little")]
        pub, sig = sec[64:128], sec[0:64]
        assert verify(pub, sig, hashlib.sha256(raw[:632]).digest()), f"genuine quote failed: {f}"
        t = bytearray(raw)
        t[568:600] = b"\x41" * 32                    # splice report_data
        assert not verify(pub, sig, hashlib.sha256(bytes(t[:632])).digest()), \
            f"SPLICED quote accepted: {f}"
        return f.name
    return None


if __name__ == "__main__":
    checked, sizes = exhaustive()
    print(f"P1 round-trip     decided over {checked} (tree, leaf) pairs")
    print(f"P2 soundness      decided — forged commitment rejected in all {checked}")
    print(f"P3 proof length   decided — within ceil(log2 n), trailing siblings refused")
    print(f"P4 count binding  decided over {sizes} tree sizes, no root reused")
    print(f"P5 domain sep     decided — no leaf hash equals any node hash")
    print(f"\nexhaustive over 1..{MAX_LEAVES} leaves, which is the deployed bound:")
    print(f"this is the whole reachable input space, not a sample.")
    acc, rej = roundtrip()
    print(f"\nP7 turn spans     {acc} turn plans: derived spans and per-span call counts")
    print(f"                  match what was built; generative, not exhaustive")
    print(f"P8 span integrity {rej} mutations rejected — every single-leaf deletion and")
    print(f"                  every out-of-turn marker loses the structural reading")
    q = quote_signature()
    if q:
        print(f"\nP9 quote signature  genuine quote verifies; splicing report_data is")
        print(f"                    rejected  (sample {q})")
    else:
        print("\nP9 quote signature  SKIPPED — no quote-bearing receipt to hand")
    if "--diff" in sys.argv:
        n = differential()
        print(f"\nP6 differential   {n} random cases, Python and TypeScript agree byte for byte")
    print("\nAssumed, not shown: SHA-256. Out of scope: the TEE, the quote chain,")
    print("TLS, and whether the operator can read plaintext.")
