#!/usr/bin/env python3
"""attest — run an agent whose every API call is witnessed, and check the result.

The agent gets no credential. This opens a session on the interposer, points the
agent at it, closes the session to collect a signed bundle, and can recheck that
bundle offline afterwards.

  attest.py run    --purpose "my matter" -- claude -p "..."
  attest.py check  bundle.json
  attest.py show   bundle.json --calls 2      # what a counterparty would see

Two parties taking turns on one document, each on their own subscription:

  attest.py ask    --purpose "..." --doc msa.md -- claude -p "..."   # prints an invite
  attest.py join   "<invite-url>#<token>"       -- claude -p "..."   # their side
  attest.py close  <handle>                     # asker seals it
  attest.py receipt <handle>                    # either side collects theirs

Needs only Python's standard library. CVM and INVITE come from the environment
or flags:

  export ATTEST_CVM=https://pod.dstack.soc1024.com
  export ATTEST_INVITE=$(cat ~/.claude/attest-proxy-invite-token)
"""
import os, sys, json, time, base64, hashlib, argparse, subprocess, urllib.request
from pathlib import Path

DEFAULT_CVM = os.environ.get("ATTEST_CVM", "https://pod.dstack.soc1024.com")
# Path the app is mounted at on the CVM. Set ATTEST_PREFIX="" to talk to a
# server running standalone, e.g. `deno run server.ts` in local development.
APP = os.environ.get("ATTEST_PREFIX", "/attest-proxy")


def post(url, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else b""
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"content-type": "application/json"})
    if token:
        req.add_header("authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def get(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def run_agent(cmd, base_url, extra=None):
    """Run the caller's agent against a witness base_url, echoing and capturing.

    The agent keeps using its own credential; only the endpoint changes. Its
    output is captured because a turn ends with a stated deliverable, and that
    deliverable is whatever the agent concluded.
    """
    if extra:
        cmd = cmd[:-1] + [cmd[-1] + extra]
        print(f"[attest] appended to the prompt: {extra.strip()}")
    # Only the endpoint changes. Claude Code sends its own subscription bearer to
    # a custom base URL unprompted (verified against a header sniffer), so setting
    # ANTHROPIC_AUTH_TOKEN here would replace the very credential being witnessed
    # and make "each party spent their own" false.
    env = dict(os.environ, ANTHROPIC_BASE_URL=base_url)
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, text=True)
    out = []
    for line in p.stdout:
        sys.stdout.write(line)
        out.append(line)
    return p.wait(), "".join(out).strip()


# --- the constructions the interposer attests (mirror of host/frames.py) ------

def commitment(host: str, redacted: bytes, response: bytes) -> bytes:
    return hashlib.sha256(b"zktls-v1\0" + host.encode() + b"\0" + redacted + b"\0" + response).digest()


def _leaf(c): return hashlib.sha256(b"\x00" + c).digest()
def _node(l, r): return hashlib.sha256(b"\x01" + l + r).digest()


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(cs):
    if not cs:
        return hashlib.sha256().digest()
    if len(cs) == 1:
        return _leaf(cs[0])
    k = _split(len(cs))
    return _node(merkle_root(cs[:k]), merkle_root(cs[k:]))


def inclusion_proof(cs, i):
    if len(cs) == 1:
        return []
    k = _split(len(cs))
    if i < k:
        return inclusion_proof(cs[:k], i) + [merkle_root(cs[k:])]
    return inclusion_proof(cs[k:], i - k) + [merkle_root(cs[:k])]


def root_from(c: bytes, i: int, n: int, pf) -> bytes:
    """Recompute the Merkle root from one commitment and its inclusion proof.

    Mirrors inclusion_proof's ordering: inner siblings come first, so recurse
    before taking this level's sibling. A proof with siblings left over is
    rejected rather than ignored.
    """
    if not 0 <= i < n:
        raise SystemExit(f"leaf index {i} outside 0..{n - 1}")
    it = iter(pf)

    def rec(m, j):
        if m == 1:
            return _leaf(c)
        k = _split(m)
        if j < k:
            left = rec(k, j)
            return _node(left, next(it))
        right = rec(m - k, j - k)
        return _node(next(it), right)

    out = rec(n, i)
    if next(it, None) is not None:
        raise SystemExit("inclusion proof longer than the tree requires")
    return out


def session_root(meta: bytes, cs) -> bytes:
    meta_hash = hashlib.sha256(b"zktls-session-v2\0" + meta).digest()
    root = merkle_root(cs) if cs else b"\x00" * 32
    return hashlib.sha256(b"zktls-root-v2\0" + meta_hash + root
                          + len(cs).to_bytes(4, "big")).digest()


def report_data(root: bytes, beacon) -> bytes:
    if not beacon:
        return root
    tag = f"{beacon['source']}:{beacon['round']}:{beacon['randomness']}".encode()
    return hashlib.sha256(b"zktls-anchor-v1\0" + root + tag).digest()


# --- commands ---------------------------------------------------------------

def _cmd_after_dashdash(a):
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        raise SystemExit("give a command after --, e.g. -- claude -p '...'")
    return cmd


def _beacon_line(s, what):
    if s.get("beacon"):
        print(f"[attest] {what}  not before drand round {s['beacon']['round']}")
    else:
        print(f"[attest] {what}  no timestamp beacon (drand unreachable)")


def cmd_run(a):
    invite = a.invite or os.environ.get("ATTEST_INVITE", "")
    if not invite:
        raise SystemExit("no invite token: set ATTEST_INVITE or pass --invite")
    cmd = _cmd_after_dashdash(a)

    s = post(f"{a.cvm}{APP}/session", {
        "purpose": a.purpose, "profile": a.profile,
        "instructed_by": a.instructed_by}, token=invite)
    sid = s["session_id"]
    _beacon_line(s, f"session {sid[:12]}…")

    t0 = time.time()
    try:
        rc, _ = run_agent(cmd, s["base_url"])
    finally:
        bundle = post(f"{a.cvm}{APP}/session/{sid}/close")
        out = Path(a.out or f"attest-{sid[:12]}.json")
        out.write_text(json.dumps(bundle, indent=2))
        n = sum(1 for c in bundle["calls"] if c.get("host") != THREAD_HOST)
        print(f"\n[attest] {n} model calls in {time.time()-t0:.1f}s "
              f"({bundle['call_count']} leaves incl. markers) -> {out}")
        if bundle.get("quote_error"):
            print(f"[attest] no quote: {bundle['quote_error']}")
            print("[attest] the project is in dev mode; promote it for real attestation")
    return rc


# --- round trip -------------------------------------------------------------

def _handle(a, path=None):
    p = Path(path or a.handle)
    if not p.exists():
        raise SystemExit(f"no such thread handle: {p}")
    return json.loads(p.read_text())


def _end_turn(cvm, token, text, role):
    if not text:
        raise SystemExit(f"the {role} produced no output, so there is nothing to commit "
                         "as a turn; pass --text to state the deliverable explicitly")
    r = post(f"{cvm}{APP}/s/{token}/turn", {"text": text})
    print(f"[attest] turn {r['turn_closed']} closed — {r['leaves']} leaves, "
          f"now {r['now']}'s move")


def cmd_ask(a):
    """Open a thread about a document, take the first turn, hand over an invite."""
    invite = a.invite or os.environ.get("ATTEST_INVITE", "")
    if not invite:
        raise SystemExit("no invite token: set ATTEST_INVITE or pass --invite")
    cmd = _cmd_after_dashdash(a)
    doc = Path(a.doc)
    t = post(f"{a.cvm}{APP}/thread", {
        "purpose": a.purpose, "profile": a.profile,
        "instructed_by": a.instructed_by,
        "responder_label": a.responder,
        "doc": {"name": doc.name, "text": doc.read_text()}}, token=invite)
    tid = t["thread_id"]
    _beacon_line(t, f"thread {tid[:12]}…")
    print(f"[attest] document {t['doc']['name']}  sha256 {t['doc']['sha256'][:16]}…  "
          f"{t['doc']['bytes']} bytes")

    brief = Path(f"attest-thread-{tid[:8]}.doc-{doc.name}")
    brief.write_text(doc.read_text())
    rc, out = run_agent(cmd, t["asker"]["base_url"],
                        extra=f"\n\nThe document under discussion is at {brief}.")
    _end_turn(a.cvm, t["asker"]["token"], a.text or out, "asker")

    h = Path(a.out or f"attest-thread-{tid[:8]}.json")
    h.write_text(json.dumps({"cvm": a.cvm, "thread_id": tid, "role": "asker",
                             "token": t["asker"]["token"],
                             "invite_url": t["responder"]["invite_url"]}, indent=2))
    print(f"\n[attest] handle  {h}")
    print(f"[attest] invite  {t['responder']['invite_url']}")
    print("[attest] send that URL. The token after the # is never sent to the server "
          "on a page load.")
    return rc


def cmd_join(a):
    """Take a turn in someone else's thread, on your own subscription."""
    cmd = _cmd_after_dashdash(a)
    base, _, frag = a.url.partition("#")
    token = a.token or frag
    if not token:
        raise SystemExit("no invite token: it is the part of the URL after the #, "
                         "or pass --token")
    j = post(base, token=token)
    if j["turn"] != "yours":
        raise SystemExit(f"it is not your turn yet (waiting on the {j['turn']} side)")
    print(f"[attest] joined as {j['party']} — {j['purpose']!r}")
    print(f"[attest] document {j['doc']['name']}  sha256 {j['doc']['sha256'][:16]}…")

    tid = base.rstrip("/").split("/")[-2]
    stem = f"attest-thread-{tid[:8]}"
    docf = Path(f"{stem}.doc-{j['doc']['name']}")
    docf.write_text(j["doc"]["text"])
    if hashlib.sha256(j["doc"]["text"].encode()).hexdigest() != j["doc"]["sha256"]:
        raise SystemExit("the document does not match the hash the thread committed to")
    print(f"[attest] document hash matches what was committed before you joined")

    askf = Path(f"{stem}.asked.md")
    askf.write_text("\n\n".join(f"## turn {t['seq']} — {t['role']}\n\n{t['text']}"
                               for t in j["prior_turns"]) or "(nothing committed yet)")
    cvm = base.split(f"{APP}/t/" if APP else "/t/")[0]
    rc, out = run_agent(cmd, j["base_url"],
                        extra=f"\n\nThe document is at {docf} and what they asked is "
                              f"at {askf}. Read both first.")
    _end_turn(cvm, token, a.text or out, "responder")

    h = Path(a.out or f"{stem}.responder.json")
    h.write_text(json.dumps({"cvm": cvm, "thread_id": tid, "role": j["party"],
                             "token": token}, indent=2))
    print(f"\n[attest] handle {h}  —  receipt available once they close the thread")
    return rc


def cmd_close(a):
    h = _handle(a)
    if h["role"] != "asker":
        raise SystemExit("only the party that opened the thread may close it")
    r = post(f"{h['cvm']}{APP}/s/{h['token']}/close")
    out = Path(a.out or str(Path(a.handle).with_suffix("")) + ".receipt.json")
    out.write_text(json.dumps(r, indent=2))
    print(f"[attest] closed — {r['call_count']} leaves -> {out}")
    if r.get("quote_error"):
        print(f"[attest] no quote: {r['quote_error']}")


def cmd_receipt(a):
    h = _handle(a)
    r = get(f"{h['cvm']}{APP}/s/{h['token']}/receipt")
    out = Path(a.out or str(Path(a.handle).with_suffix("")) + ".receipt.json")
    out.write_text(json.dumps(r, indent=2))
    print(f"[attest] {r['for_party']} receipt, {r['call_count']} leaves -> {out}")


def _usage_of(bundle):
    """Token counts and model as the provider reported them, inside responses
    this witness received over TLS against a pinned root — the provider's own
    figures, not the holder's.

    Handles both shapes: a single JSON body, and the SSE stream agents actually
    use, where usage arrives split across message_start and message_delta.
    """
    tin = tout = tcache = 0
    models = set()
    for c in bundle.get("calls", []):
        if "response_b64" not in c or c.get("host") == THREAD_HOST:
            continue      # withheld from this receipt, or a structural marker
        body = base64.b64decode(c["response_b64"]).split(b"\r\n\r\n", 1)[-1]
        text = body.decode("utf-8", "replace")
        events = []
        if text.lstrip().startswith("{"):
            try:
                events = [json.loads(text)]
            except Exception:
                events = []
        else:
            for line in text.splitlines():
                if line.startswith("data: "):
                    try:
                        events.append(json.loads(line[6:]))
                    except Exception:
                        pass
        for e in events:
            msg = e.get("message") if isinstance(e.get("message"), dict) else e
            if isinstance(msg, dict) and msg.get("model"):
                models.add(msg["model"])
            u = (msg.get("usage") if isinstance(msg, dict) else None) or e.get("usage") or {}
            if isinstance(u, dict):
                tin += u.get("input_tokens", 0) or 0
                tout += u.get("output_tokens", 0) or 0
                tcache += (u.get("cache_creation_input_tokens", 0) or 0) \
                    + (u.get("cache_read_input_tokens", 0) or 0)
    return tin, tout, tcache, sorted(models)


THREAD_HOST = "edge-tee.thread"


def _index(c):
    return c["index"] if "index" in c else c["n"] - 1


def _events(b):
    """The structural leaves, decoded. They are ordinary leaves of the same tree,
    committed with the same construction — only the host differs."""
    out = []
    for c in b["calls"]:
        if c.get("host") != THREAD_HOST or "request_redacted" not in c:
            continue
        out.append((_index(c), json.loads(c["request_redacted"].encode("latin-1").decode())))
    return out


def _replay(b):
    """Derive the turn structure from the marker leaves, refusing anything
    ill-formed. Nothing here reads a party label off a leaf — there is none. A
    span is a party's because only the turn holder could relay into it, and the
    markers that delimit it are committed at fixed, dense indices.
    """
    ev = _events(b)
    if not ev:
        return None                      # a single-party session, not a thread
    n = b["call_count"]
    # Every structural claim below — turn spans, per-span call counts, who moved
    # when — assumes the leaves are all here. Drop one and the span it sat in
    # silently shrinks, which is exactly the understatement the count binding is
    # supposed to prevent. Inclusion proofs alone do NOT catch this: the ones that
    # remain still verify. So density is checked, and a partial disclosure gets no
    # structural reading at all rather than a quietly wrong one.
    if {_index(c) for c in b["calls"]} != set(range(n)):
        return {"partial": True}
    i0, opened = ev[0]
    if i0 != 0 or opened["event"] != "open":
        # A single-party session also carries a marker (its credential
        # fingerprint), so "there are markers" does not mean "this is a thread".
        # Only an open marker at leaf 0 does. A thread with its open marker
        # removed fails the density check above, so nothing escapes by this path.
        return None
    roles = [p["role"] for p in opened["parties"]]
    spans, fps, served, holder, prev, closed = [], {}, {}, 0, 0, False
    for i, e in ev[1:]:
        k = e["event"]
        if closed:
            raise SystemExit(f"leaf {i}: a marker follows the close marker")
        if k == "turn":
            if e["role"] != roles[holder]:
                raise SystemExit(f"leaf {i}: {e['role']} ended a turn that belonged "
                                 f"to {roles[holder]}")
            if hashlib.sha256(e["text"].encode()).hexdigest() != e["text_sha256"]:
                raise SystemExit(f"leaf {i}: turn text does not match its committed hash")
            spans.append({"role": e["role"], "seq": e["seq"], "lo": prev + 1, "hi": i,
                          "text": e["text"]})
            prev, holder = i, (holder + 1) % len(roles)
        elif k == "cred":
            if e["role"] in fps:
                raise SystemExit(f"leaf {i}: a second credential fingerprint for {e['role']}")
            fps[e["role"]] = e["fingerprint"]
        elif k == "serve":
            served[e["to"]] = e["doc_sha256"]
        elif k == "close":
            if i != n - 1:
                raise SystemExit(f"close marker at leaf {i}, but the tree has {n} leaves")
            if e["turns"] != len(spans):
                raise SystemExit(f"close says {e['turns']} turns; "
                                 f"{len(spans)} turn markers are present")
            closed = True
        elif k != "join":
            raise SystemExit(f"leaf {i}: unknown marker {k!r}")
    if not closed:
        raise SystemExit("no close marker — this thread was never sealed")
    if prev < n - 2:                      # calls made after the last committed turn
        spans.append({"role": roles[holder], "seq": None, "lo": prev + 1, "hi": n - 2,
                      "text": None})

    # Every model call must fall inside exactly one span, or attribution has a hole.
    covered = {i for s in spans for i in range(s["lo"], s["hi"] + 1)}
    for c in b["calls"]:
        i = _index(c)
        if c.get("host") not in (None, THREAD_HOST) and i not in covered:
            raise SystemExit(f"leaf {i} is a model call outside every turn span")
    return {"roles": roles, "spans": spans, "fps": fps, "served": served, "open": opened}


def _report_thread(b, count):
    """Render the round trip, having derived it rather than been told it."""
    t = _replay(b)
    if not t:
        return
    print()
    if t.get("partial"):
        print("round trip  leaves are missing from this file, so NO turn structure is")
        print("            established: a deleted leaf shrinks the span it sat in and")
        print("            every remaining inclusion proof still verifies. What holds")
        print("            is per-leaf membership and the total count, nothing more.")
        print()
        return "partial"
    turns = [s for s in t["spans"] if s["seq"]]
    print(f"round trip  {len(turns)} turns, {count} leaves, sealed")
    for s in t["spans"]:
        calls = [c for c in b["calls"] if s["lo"] <= _index(c) <= s["hi"]
                 and c.get("host") != THREAD_HOST]
        shown = [c for c in calls if "request_redacted" in c]
        tin, tout, tcache, models = _usage_of({"calls": shown})
        tag = f"turn {s['seq']}" if s["seq"] else "open  "
        usage = (f"{tin} in / {tout} out / {tcache} cached   {', '.join(models) or 'n/a'}"
                 if shown else "[content withheld from this receipt]")
        print(f"  {tag}  {s['role']:<10} leaves {s['lo']}..{s['hi']:<4} "
              f"{len(calls)} calls   {usage}")

    fps = t["fps"]
    missing = [r for r in t["roles"] if r not in fps]
    if len(set(fps.values())) == len(fps) and not missing:
        print("parties     " + "  ".join(f"{r} fp {fps[r][:12]}…" for r in t["roles"])
              + "  — distinct credentials")
    elif missing:
        print(f"parties     no credential fingerprint for {', '.join(missing)} "
              "— they committed no model call")
    else:
        print("parties     SAME credential fingerprint on both sides — this is one "
              "party talking to itself")

    doc = b.get("doc")
    if doc:
        want = t["open"]["doc"]["sha256"]
        if hashlib.sha256(doc["text"].encode()).hexdigest() != want:
            raise SystemExit("the document in this receipt is not the one committed at open")
        served = [r for r, h in t["served"].items() if h == want]
        print(f"document    {doc['name']}  sha256 {want[:16]}…  matches the hash "
              f"committed at leaf 0")
        print(f"            served by the witness to: {', '.join(served) or 'nobody'}")
    print("attribution no leaf carries a party label; spans are derived from the")
    print("            markers, and only the turn holder could relay into one")
    print()
    return "thread"


def cmd_check(a):
    b = json.loads(Path(a.bundle).read_text())
    meta = base64.b64decode(b["session_meta_b64"])
    cs = [bytes.fromhex(c["commitment"]) for c in b["calls"]]

    for c in b["calls"]:
        if "request_redacted" not in c:
            continue          # a zero-content stub has nothing to recompute
        want = commitment(c.get("host", "api.anthropic.com"),
                          c["request_redacted"].encode("latin-1"),
                          base64.b64decode(c["response_b64"]))
        if want.hex() != c["commitment"]:
            raise SystemExit(f"leaf {_index(c)}: content does not match its commitment")
        if "merkle_root" not in b:      # otherwise the proof loop reports it
            kind = "marker" if c.get("host") == THREAD_HOST else "call  "
            print(f"  ok {kind} {_index(c):>3}  {c['commitment'][:16]}…")

    count = b.get("call_count", len(cs))
    if count == len(cs) and "merkle_root" not in b:
        root = session_root(meta, cs)
        if root.hex() != b["session_root"]:
            raise SystemExit(f"session root mismatch: {b['session_root']} != {root.hex()}")
        print(f"\nsession root {root.hex()} recomputes")
    else:
        # Partial disclosure: the withheld calls are absent by design, so the root
        # cannot be rebuilt from what is here. Each shown call must instead prove
        # its own membership against the attested root, and the signed count is
        # what stops the total being understated.
        mr = bytes.fromhex(b["merkle_root"]) if b.get("merkle_root") else b"\x00" * 32
        for c in b["calls"]:
            if "inclusion_proof" not in c:
                raise SystemExit(f"call {c.get('index', '?')} has no inclusion proof")
            got = root_from(bytes.fromhex(c["commitment"]), c["index"], count,
                            [bytes.fromhex(x) for x in c["inclusion_proof"]])
            if got != mr:
                raise SystemExit(f"leaf {c['index']} is not in the attested tree")
            tag = ("marker" if c.get("host") == THREAD_HOST else "call") \
                if "request_redacted" in c else "withheld"
            print(f"  ok leaf {c['index']:>3} of {count}  in tree, {tag}"
                  + ("" if tag == "withheld" else ", content matches its commitment"))
        cr = b.get("complete_range")
        if cr:
            lo, hi = cr
            shown = sorted(c["index"] for c in b["calls"])
            if shown != list(range(lo, hi + 1)):
                raise SystemExit("complete_range claimed but the shown indices are "
                                 f"not the contiguous run {lo + 1}..{hi + 1}")
            print(f"\ncomplete for calls {lo + 1}..{hi + 1} of {count}: leaf indices are "
                  f"dense,\nso no call is hidden inside that range")
        expect = hashlib.sha256(b"zktls-root-v2\0"
                                + hashlib.sha256(b"zktls-session-v2\0" + meta).digest()
                                + mr + count.to_bytes(4, "big")).digest()
        if expect.hex() != b["session_root"]:
            raise SystemExit(f"session root mismatch: {b['session_root']} != {expect.hex()}")
        print(f"\nsession root {expect.hex()} recomputes")
        content = sum(1 for c in b["calls"] if "request_redacted" in c)
        absent = count - len(b["calls"])
        print(f"{content} of {count} leaves shown with content, "
              f"{count - content} withheld but counted"
              + (f" ({absent} absent entirely)" if absent else ""))

    rd = report_data(bytes.fromhex(b["session_root"]), b.get("beacon"))
    if b.get("report_data") and rd.hex() != b["report_data"]:
        raise SystemExit("report_data does not bind this root and beacon")

    structure = _report_thread(b, count)

    tin, tout, tcache, models = _usage_of(b)
    print(f"purpose  {b['purpose']!r}")
    print(f"release  {b['release']['profile']}"
          + (f" (instructed by {b['release']['instructed_by']})"
             if b["release"].get("instructed_by") else ""))
    if b.get("beacon"):
        print(f"not before  drand round {b['beacon']['round']}")
    print(f"usage    {tin} in / {tout} out / {tcache} cached tokens"
          f"   model(s): {', '.join(models) or 'n/a'}")
    print("         [the provider's own figures, read out of responses this witness")
    print("          received over TLS against a pinned root]")
    if b.get("quote"):
        print(f"quote    present, binds report_data {b['report_data'][:16]}…")
        print(f"         verify the CVM and app measurements at "
              f"{a.cvm}/_api/verification/attest-proxy")
    else:
        print(f"quote    ABSENT ({b.get('quote_error')}) — nothing here is attested yet")
    if structure == "partial":
        print("\nrecomputations green for the leaves present — but leaves are missing,")
        print("so the turn structure is NOT established and no span count here is a count")
    elif structure == "thread":
        print("\nall recomputations green — turn structure established")
    else:
        print("\nall recomputations green")


# --- TDX v4 quote, structural parse ------------------------------------------
#
# Offsets from the Intel TDX DCAP v4 spec, matching tools/dcap/dcap_parse.py in
# teleport-computer/feedling-mcp so both readers agree. This extracts what the
# TEE measured; it does NOT verify the signature chain, so a quote from an
# untrusted source would still parse. See verify-quote's closing note.
_FIELDS = {"mrtd": (184, 48), "rtmr0": (376, 48), "rtmr1": (424, 48),
           "rtmr2": (472, 48), "rtmr3": (520, 48), "report_data": (568, 64)}


def parse_quote(raw: bytes) -> dict:
    if len(raw) < 48 + 584 + 4:
        raise SystemExit(f"quote too short: {len(raw)} bytes")
    version = int.from_bytes(raw[0:2], "little")
    tee_type = int.from_bytes(raw[4:8], "little")
    if version != 4:
        raise SystemExit(f"unexpected quote version {version}, expected 4")
    if tee_type != 0x81:
        raise SystemExit(f"not a TDX quote (tee_type 0x{tee_type:02x})")
    return {k: raw[o:o + n].hex() for k, (o, n) in _FIELDS.items()}


def cmd_verify_quote(a):
    b = json.loads(Path(a.bundle).read_text())
    q = b.get("quote")
    if not q:
        raise SystemExit(f"no quote in this bundle ({b.get('quote_error')}) "
                         "-- nothing here is attested")
    hexq = q.get("quote") if isinstance(q, dict) else None
    if not isinstance(hexq, str):
        raise SystemExit("quote field is not hex; cannot parse")
    m = parse_quote(bytes.fromhex(hexq))

    expect = report_data(bytes.fromhex(b["session_root"]), b.get("beacon"))
    got = m["report_data"][:64]
    if got != expect.hex():
        raise SystemExit(f"quote commits to {got}, not this session's {expect.hex()}")
    print("report_data binds this session: yes")

    pin = Path(a.pin) if a.pin else Path.home() / ".claude/attest-proxy-pin.json"
    current = {k: m[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    # A bare tree hash is not provenance: it says the code has some identity, not
    # which code. The verification record names the repo and commit the daemon
    # built from, so a verifier can clone that commit and read what ran. Raised by
    # a counterparty's agent, which found repo and commit_sha empty on a tarball
    # deploy and concluded — correctly — that "runs the published code" was
    # unbacked. Deploy from source, not a tarball, or this stays empty.
    try:
        with urllib.request.urlopen(f"{a.cvm}/_api/verification/attest-proxy", timeout=30) as r:
            src = (json.loads(r.read()).get("app") or {}).get("source") or {}
        for k in ("repo", "ref", "commit_sha", "tree_hash"):
            if src.get(k):
                current[k] = src[k]
    except Exception as e:
        print(f"could not read the deployment's source provenance: {e}")
    if not current.get("commit_sha"):
        print("NOTE: this deployment records no commit — nothing ties the code")
        print("      running here to any published source.")

    if not pin.exists():
        pin.parent.mkdir(parents=True, exist_ok=True)
        pin.write_text(json.dumps(current, indent=2))
        print(f"FIRST RUN -- pinned these measurements to {pin}")
        for k, v in current.items():
            print(f"  {k:10s} {v[:48]}")
        print()
        print("Nothing is verified yet. You have recorded what this deployment")
        print("measured today. Audit the source, then later runs are compared")
        print("against this pin and any change becomes visible.")
        if current.get("commit_sha"):
            print()
            print(f"  git clone {current.get('repo')} && git checkout {current['commit_sha']}")
            print("  is the code this deployment says it built from. Read it before")
            print("  the pin means anything.")
        return

    pinned = json.loads(pin.read_text())
    drift = {k: (pinned.get(k), v) for k, v in current.items() if pinned.get(k) != v}
    for k, v in current.items():
        print(f"  {k:10s} {'CHANGED' if k in drift else 'ok':8s} {v[:32]}")
    if drift:
        print()
        print("MEASUREMENTS CHANGED since you pinned them:")
        for k, (was, now) in drift.items():
            print(f"  {k}")
            print(f"    was {was}")
            print(f"    now {now}")
        raise SystemExit("this is not the code or platform you audited -- stop")
    print()
    print("matches your pin")
    print()
    print("Establishes: the quote commits to this session, and the measurements")
    print("match what you pinned. Does NOT establish: the signature chain is")
    print("unverified here. For chain verification use a DCAP verifier.")


def cmd_show(a):
    """Produce what a counterparty sees: chosen calls plus inclusion proofs.

    Three shapes, supporting different claims:
      --calls 2,5   an arbitrary subset. Each shown call is provably genuine, but
                    it says nothing about what sits between them.
      --range 2:5   a contiguous run. Leaf indices are dense, so showing every
                    index in the range proves nothing is hidden INSIDE it — a
                    qualified completeness claim over that span.
      --none        count only, no content.
    """
    b = json.loads(Path(a.bundle).read_text())
    cs = [bytes.fromhex(c["commitment"]) for c in b["calls"]]
    rng = None
    if getattr(a, "range", None):
        lo, _, hi = a.range.partition(":")
        lo, hi = int(lo), int(hi or lo)
        if not 1 <= lo <= hi <= len(cs):
            raise SystemExit(f"range {lo}:{hi} outside 1..{len(cs)}")
        keep = list(range(lo, hi + 1))
        rng = [lo - 1, hi - 1]
    else:
        keep = [] if a.none else [int(x) for x in a.calls.split(",") if x.strip()]
    disclosed = []
    for i in keep:
        c = dict(b["calls"][i - 1])
        c["index"] = i - 1
        c["inclusion_proof"] = [h.hex() for h in inclusion_proof(cs, i - 1)]
        disclosed.append(c)
    # verify_with travels with the disclosure: this is the artifact a stranger
    # receives, so it is the one that most needs to say how to check itself.
    out = {k: b[k] for k in ("verify_with", "purpose", "release", "session_meta_b64",
                             "session_root", "beacon", "report_data", "quote")
           if k in b}
    out.update(kind="edge-tee partial disclosure", call_count=len(cs),
               merkle_root=merkle_root(cs).hex() if cs else None,
               calls=disclosed, withheld=len(cs) - len(disclosed))
    if rng:
        # The claim this disclosure makes. A verifier re-derives it from the
        # indices rather than believing the label.
        out["complete_range"] = rng
    Path(a.out).write_text(json.dumps(out, indent=2))
    print(f"disclosed {len(disclosed)} of {len(cs)} calls, "
          f"{out['withheld']} withheld -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cvm", default=DEFAULT_CVM)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run"); r.add_argument("--purpose", required=True)
    r.add_argument("--profile", default="holder-only",
                   choices=["holder-only", "aggregate-only", "dual-delivery"])
    r.add_argument("--instructed-by", default="")
    r.add_argument("--invite"); r.add_argument("--out")
    r.add_argument("cmd", nargs=argparse.REMAINDER)
    r.set_defaults(fn=cmd_run)

    k = sub.add_parser("ask", help="open a witnessed thread about a document and take turn 1")
    k.add_argument("--purpose", required=True)
    k.add_argument("--doc", required=True, help="the document both parties work on")
    k.add_argument("--profile", default="holder-only",
                   choices=["holder-only", "aggregate-only", "dual-delivery"])
    k.add_argument("--responder", default="responder", help="label for the other party")
    k.add_argument("--text", help="commit this as the turn deliverable instead of "
                                  "the agent's output")
    k.add_argument("--instructed-by", default="")
    k.add_argument("--invite"); k.add_argument("--out")
    k.add_argument("cmd", nargs=argparse.REMAINDER); k.set_defaults(fn=cmd_ask)

    j = sub.add_parser("join", help="take a turn in someone else's thread")
    j.add_argument("url", help="the invite URL; the token is the part after the #")
    j.add_argument("--token", help="if your shell ate the fragment")
    j.add_argument("--text", help="commit this instead of the agent's output")
    j.add_argument("--out")
    j.add_argument("cmd", nargs=argparse.REMAINDER); j.set_defaults(fn=cmd_join)

    cl = sub.add_parser("close", help="seal the thread and collect your receipt")
    cl.add_argument("handle"); cl.add_argument("--out"); cl.set_defaults(fn=cmd_close)

    rc = sub.add_parser("receipt", help="fetch your party-scoped receipt")
    rc.add_argument("handle"); rc.add_argument("--out"); rc.set_defaults(fn=cmd_receipt)

    c = sub.add_parser("check"); c.add_argument("bundle"); c.set_defaults(fn=cmd_check)

    q = sub.add_parser("verify-quote"); q.add_argument("bundle")
    q.add_argument("--pin", help="measurement pin file (default ~/.claude/attest-proxy-pin.json)")
    q.set_defaults(fn=cmd_verify_quote)

    s = sub.add_parser("show"); s.add_argument("bundle")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--calls", help="arbitrary subset, e.g. 2,5")
    g.add_argument("--range", help="contiguous run, e.g. 2:5 — claims completeness within it")
    g.add_argument("--none", action="store_true", help="count only, no content")
    s.add_argument("-o", "--out", required=True); s.set_defaults(fn=cmd_show)

    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
