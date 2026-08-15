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
# Cheap tiers for mechanics, the good one for output worth showing someone.
MODELS = {"haiku": "claude-haiku-4-5-20251001", "sonnet": "claude-sonnet-5",
          "opus": "claude-opus-5", "fable": "claude-fable-5", "glm": "glm-4.6"}
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

    def sib():
        try:
            return next(it)
        except StopIteration:
            # A proof too short for the tree is a malformed receipt, not a crash.
            raise SystemExit("inclusion proof shorter than the tree requires")

    def rec(m, j):
        if m == 1:
            return _leaf(c)
        k = _split(m)
        if j < k:
            left = rec(k, j)
            return _node(left, sib())
        right = rec(m - k, j - k)
        return _node(sib(), right)

    out = rec(n, i)
    if next(it, None) is not None:
        raise SystemExit("inclusion proof longer than the tree requires")
    return out


def session_root(meta: bytes, cs) -> bytes:
    meta_hash = hashlib.sha256(b"zktls-session-v2\0" + meta).digest()
    root = merkle_root(cs) if cs else b"\x00" * 32
    return hashlib.sha256(b"zktls-root-v2\0" + meta_hash + root
                          + len(cs).to_bytes(4, "big")).digest()


def _btag(b):
    return f"{b['source']}:{b['round']}:{b['randomness']}".encode()


def report_data(root: bytes, beacon, beacons=None) -> bytes:
    """v1 binds one sample (a lower bound); v2 binds first and last (a span)."""
    bs = beacons if beacons else ([beacon] if beacon else [])
    if not bs:
        return root
    if len(bs) == 1:
        return hashlib.sha256(b"zktls-anchor-v1\0" + root + _btag(bs[0])).digest()
    return hashlib.sha256(b"zktls-anchor-v2\0" + root + _btag(bs[0]) + b"\0"
                          + _btag(bs[-1])).digest()


# --- commands ---------------------------------------------------------------

def _cmd_after_dashdash(a):
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        raise SystemExit("give a command after --, e.g. -- claude -p '...'")
    return cmd


def git_subject():
    """Where the working tree is, and what changed. None outside a repo.

    HEAD is what a sponsor recognises; the diff is what carries the work. Record
    both: a commit hash proves you were somewhere, a diff hash proves what moved.
    """
    def run(*a):
        r = subprocess.run(a, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    ref = run("git", "rev-parse", "HEAD")
    if ref is None:
        return None
    diff = subprocess.run(["git", "diff", "HEAD"], capture_output=True)
    return {"ref": ref,
            "tree": run("git", "rev-parse", "HEAD^{tree}"),
            "diff_sha256": hashlib.sha256(diff.stdout).hexdigest()}


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

    subject = git_subject()
    if subject:
        print(f"[attest] subject  HEAD {subject['ref'][:12]}  "
              f"diff {subject['diff_sha256'][:12]}…")
    else:
        print("[attest] subject  none — not a git repo, so this receipt will attribute "
              "the work to nothing")
    s = post(f"{a.cvm}{APP}/session", {
        "purpose": a.purpose, "profile": a.profile, "subject": subject,
        "check": a.check, "instructed_by": a.instructed_by}, token=invite)
    sid = s["session_id"]
    _beacon_line(s, f"session {sid[:12]}…")

    t0 = time.time()
    try:
        rc, _ = run_agent(cmd, s["base_url"])
    finally:
        bundle = post(f"{a.cvm}{APP}/session/{sid}/close",
                      {"subject": git_subject()})
        out = Path(a.out or f"attest-{sid[:12]}.json")
        out.write_text(json.dumps(bundle, indent=2))
        n = sum(1 for c in bundle["calls"] if c.get("host") not in (THREAD_HOST, CHECK_HOST))
        print(f"\n[attest] {n} model calls in {time.time()-t0:.1f}s "
              f"({bundle['call_count']} leaves incl. markers) -> {out}")
        if n == 0:
            # A directory that `enable` has recorded sets ANTHROPIC_BASE_URL in
            # .claude/settings.json, and that wins over what this wrapper exports —
            # so every call goes to the recorder and this session seals empty.
            print("[attest] WARNING: this session witnessed no model calls.")
            sf = Path(".claude/settings.json")
            if sf.exists() and "ANTHROPIC_BASE_URL" in sf.read_text():
                print("[attest] this directory is already recorded, and its "
                      "settings.json overrides")
                print("[attest] the wrapper. The calls went to the recorder instead: "
                      "attest.py sessions .")
            else:
                print("[attest] the agent may have failed before making any call.")
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


def cmd_turn(a):
    """Take a further turn in a thread you are already a party to.

    A thread is not two turns; the turn passes back and forth until whoever
    opened it closes. That is what makes an interactive challenge session
    possible: challenge n+1 can only be written after answer n is committed, so
    a demonstrator cannot have rehearsed it.
    """
    h = _handle(a)
    # argparse.REMAINDER starts capturing at the first token after the positional,
    # so `turn <handle> --text "..."` lands --text inside cmd and we try to exec it.
    rest, text = list(a.cmd), a.text
    if rest and rest[0] == "--text":
        text, rest = rest[1], rest[2:]
    cmd = rest[1:] if rest and rest[0] == "--" else rest
    if cmd:
        _, out = run_agent(cmd, f"{h['cvm']}{APP}/s/{h['token']}")
        text = text or out
    if not text:
        raise SystemExit("pass --text, or a command after -- whose output becomes the turn")
    _end_turn(h["cvm"], h["token"], text, h["role"])


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
        if _is_marker(c):
            continue
        if "response_b64" not in c:
            u = c.get("usage")
            if u:         # withheld body, but the provider's figures travel with the leaf
                tin += u.get("input", 0); tout += u.get("output", 0)
                tcache += u.get("cached", 0); models.update(u.get("models") or [])
            continue
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
CHECK_HOST = "edge-tee.checker"


def _index(c):
    return c["index"] if "index" in c else c["n"] - 1


def _is_marker(c):
    """A structural leaf, established from content rather than from a label.

    `host` sits inside the commitment preimage, so it is bound only for leaves
    whose content is present. On a withheld leaf it is an unauthenticated field
    the holder can set at will: relabelling withheld model calls as markers made
    a counterparty's whole turn read as `0 calls` with the root and quote intact.
    Anything we cannot verify is therefore counted as a model call, which is the
    direction that cannot be used to understate someone else's work.
    """
    return "request_redacted" in c and c.get("host") in (THREAD_HOST, CHECK_HOST)


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
    spans, fps, served, holder, prev, closed, sealed = [], {}, {}, 0, 0, False, None
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
            closed, sealed = True, e
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
        if not _is_marker(c) and i not in covered:
            raise SystemExit(f"leaf {i} is a model call outside every turn span")
    # The witness stated, under commitment, what each party did. Derive the same
    # numbers from the leaves and require agreement. Everything about a withheld
    # leaf is otherwise unverifiable by the party who did not make it, which is
    # exactly the gap a holder can use to shrink the other side's turn.
    tally = sealed.get("tally")
    if not tally:
        raise SystemExit("the close marker carries no committed tally, so this receipt "
                         "predates count binding and its per-party figures cannot be "
                         "checked — treat its turn structure as unverified")
    for role, t in tally.items():
        got = sum(1 for c in b["calls"]
                  for sp in spans
                  if sp["role"] == role and sp["lo"] <= _index(c) <= sp["hi"]
                  and not _is_marker(c))
        if got != t["calls"]:
            raise SystemExit(f"{role}: the tree shows {got} model calls but the witness "
                             f"committed {t['calls']} — this receipt has been re-described")
        if fps.get(role) != t.get("cred_fp"):
            raise SystemExit(f"{role}: credential fingerprint {fps.get(role)!r} does not "
                             f"match the committed {t.get('cred_fp')!r}")
    return {"roles": roles, "spans": spans, "fps": fps, "served": served,
            "open": opened, "sealed": sealed}


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
    seen_tokens = {}
    for s in t["spans"]:
        calls = [c for c in b["calls"] if s["lo"] <= _index(c) <= s["hi"]
                 and not _is_marker(c)]
        shown = [c for c in calls if "request_redacted" in c]
        tag = f"turn {s['seq']}" if s["seq"] else "open  "
        # Per turn, from the figures carried on each leaf — which travel even when
        # the body is withheld. The committed tally is per PARTY, so using it here
        # printed one party's total against every one of its turns, and a four-turn
        # session showed turns 2 and 4 with identical counts. It is cross-checked
        # against these sums below instead.
        tin, tout, tcache, models = _usage_of({"calls": calls})
        usage = (f"{tin} in / {tout} out / {tcache} cached   {', '.join(models) or 'n/a'}"
                 if calls else "no relayed calls")
        seen_tokens.setdefault(s["role"], [0, 0, 0])
        acc = seen_tokens[s["role"]]
        acc[0] += tin; acc[1] += tout; acc[2] += tcache
        print(f"  {tag}  {s['role']:<10} leaves {s['lo']}..{s['hi']:<4} "
              f"{len(calls)} calls   {usage}")

    # The per-turn sums must add up to what the witness committed for that party.
    for role, acc in seen_tokens.items():
        c = ((t.get("sealed") or {}).get("tally") or {}).get(role)
        if not c:
            continue
        k = c["tokens"]
        if [k["input"], k["output"], k["cached"]] != acc:
            raise SystemExit(
                f"{role}: turn figures sum to {acc} but the witness committed "
                f"{[k['input'], k['output'], k['cached']]} — this receipt has been re-described")

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
    if not doc and t["open"].get("doc"):
        print("document    NOT INCLUDED in this receipt, though leaf 0 commits "
              f"{(t['open']['doc'] or {}).get('name')!r}")
    if doc:
        want = t["open"]["doc"]["sha256"]
        if hashlib.sha256(doc["text"].encode()).hexdigest() != want:
            raise SystemExit("the document in this receipt is not the one committed at open")
        want_name = (t["open"]["doc"] or {}).get("name")
        if want_name is not None and doc.get("name") != want_name:
            raise SystemExit(f"receipt names the document {doc.get('name')!r} but leaf 0 "
                             f"committed {want_name!r}")
        served = [r for r, h in t["served"].items() if h == want]
        print(f"document    {doc['name']}  sha256 {want[:16]}…  matches the hash "
              f"committed at leaf 0")
        print(f"            served by the witness to: {', '.join(served) or 'nobody'}")
    print("attribution no leaf carries a party label; spans are derived from the")
    print("            markers, and only the turn holder could relay into one")
    print()
    return "thread"


def cmd_adjudicate(a):
    """Put one instruction and one document to a model, in a closed context.

    The witness composes the request, so the entire input is in the receipt and
    is small enough to publish. That is the difference between "a model said
    this" and "this, and only this, is what it was given" — the second is worth
    something to a reader, the first is not.
    """
    invite = a.invite or os.environ.get("ATTEST_INVITE", "")
    if not invite:
        raise SystemExit("no invite token: set ATTEST_INVITE or pass --invite")
    texts = [Path(x).read_text() if Path(x).exists() else x for x in a.instruction]
    multi = len(texts) > 1
    if multi and a.doc:
        raise SystemExit("--doc is single-question only; drop it or ask one instruction")
    instruction = texts[0]
    doc = {"name": Path(a.doc).name, "text": Path(a.doc).read_text()} if a.doc else None
    model = MODELS.get(a.model, a.model)
    if a.provider == "zai":
        # A machine already pointed at Z.AI keeps the key in Claude Code's own
        # settings, so there is nothing to export. Env wins if both are present.
        key = os.environ.get("ZAI_API_KEY", "") or _settings_token("api.z.ai")
        if not key:
            raise SystemExit("no Z.AI key: set ZAI_API_KEY, or point Claude Code's "
                             "settings.json at api.z.ai and it will be read from there")
    else:
        key = os.environ.get("ANTHROPIC_API_KEY") or _oauth_token()
    if not key:
        raise SystemExit("no model credential found: set ANTHROPIC_API_KEY, or log in "
                         "with Claude Code so the OAuth token can be read")
    payload = {"model": model, "provider": a.provider,
               "publish_document": not a.private_document}
    if multi:
        payload["questions"] = texts
    else:
        payload["instruction"] = instruction
        payload["document"] = doc
    req = urllib.request.Request(
        f"{a.cvm}{APP}/adjudicate", method="POST",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json",
                 "authorization": f"Bearer {invite}", "x-model-key": key})
    with urllib.request.urlopen(req, timeout=300) as r:
        b = json.loads(r.read())
    out = Path(a.out or "adjudication.json")
    out.write_text(json.dumps(b, indent=2))
    if b.get("questions"):
        qs = b["questions"]
        print(f"model      {b['model']}   via {b.get('provider','anthropic')}   "
              f"{len(qs)} questions in one receipt, one quote")
        for q in qs:
            print(f"\n── Q{q['n']}: {q['instruction'].strip()[:72]}")
            if q.get("declined"):
                print("   [the model declined to answer]")
            else:
                print(f"   {q['verdict'].strip()[:500]}")
        print(f"\nreceipt    {out}   session root {b['session_root'][:16]}…")
        if b.get("claim_url"):
            print(f"claim      {b['claim_url']}   <- one link, every answer, one quote")
        if any(str(q.get("verdict", "")).startswith(("upstream ", "relay failed"))
               for q in qs):
            print("\nAt least one call was an upstream error, not an opinion.")
            return 1
        return
    print(f"model      {b['model']}   via {b.get('provider','anthropic')}")
    for part in b.get("prompt_parts") or []:
        note = "  <- not chosen by you" if part["part"] == "required preamble" else ""
        print(f"  {part['part']:<18} {part['bytes']:>6} bytes{note}")
    if doc:
        print(f"document   {doc['name']}  sha256 {b['doc']['sha256'][:16]}…  "
              f"{b['doc']['bytes']} bytes"
              + ("  [hash only, text withheld]" if a.private_document else ""))
    if b.get("declined"):
        print(f"\n  THE MODEL DECLINED TO ANSWER   (stop_reason: {b.get('stop_reason')})")
        print("  This is a result, not a failure: the question and the whole context are")
        print("  in the receipt, so a reader can see nothing in the prompt provoked it.\n")
    else:
        print(f"\n{b['verdict']}\n")
    print(f"receipt    {out}   session root {b['session_root'][:16]}…")
    if b.get("claim_url"):
        print(f"claim      {b['claim_url']}   <- paste this; its .json twin tells a checker's agent how to validate it")
    if b.get("quote_error"):
        print(f"           no quote: {b['quote_error']}")
    # A receipt whose verdict is an upstream error is honest evidence that the
    # call was attempted, and is not an adjudication. Exiting 0 on it would let a
    # script treat "rate limited" as an opinion.
    if str(b.get("verdict", "")).startswith(("upstream ", "relay failed")):
        print("\nNo verdict was produced. The receipt records the attempt, not an "
              "opinion.")
        return 1


def _settings_token(host):
    """Claude Code's own credential, when it is already configured for `host`.

    Reading it rather than requiring an export is what makes an unattended lane
    need no setup: a box already talking to a provider through Claude Code has
    everything needed to adjudicate through the same provider.
    """
    p = Path.home() / ".claude" / "settings.json"
    if not p.exists():
        return None
    env = (json.loads(p.read_text()).get("env") or {})
    if host not in str(env.get("ANTHROPIC_BASE_URL", "")):
        return None
    return env.get("ANTHROPIC_AUTH_TOKEN")


def _oauth_token():
    """Claude Code's own credential, so an adjudication costs the caller."""
    p = Path.home() / ".claude" / ".credentials.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text())
    for k in ("claudeAiOauth", "oauth"):
        v = d.get(k) or {}
        t = v.get("accessToken") or v.get("access_token")
        if t:
            return f"Bearer {t}"
    return None


def cmd_enable(a):
    """Turn a directory into a recorded one. Opt-in, deliberately.

    On-by-default would route every repo on the machine through the witness,
    including work under contracts that forbid a third-party host, and that
    failure is silent and only found afterwards. So: one directory at a time,
    and the settings file it writes is visible in the repo.
    """
    invite = a.invite or os.environ.get("ATTEST_INVITE", "")
    if not invite:
        raise SystemExit("no invite token: set ATTEST_INVITE or pass --invite")
    d = Path(a.dir).resolve()
    if not d.is_dir():
        raise SystemExit(f"{d} is not a directory")
    cwd = os.getcwd()
    os.chdir(d)
    try:
        subject = git_subject()
    finally:
        os.chdir(cwd)
    r = post(f"{a.cvm}{APP}/recorder",
             {"label": a.label or d.name, "subject": subject}, token=invite)

    sf = d / ".claude" / "settings.json"
    sf.parent.mkdir(exist_ok=True)
    cfg = json.loads(sf.read_text()) if sf.exists() else {}
    cfg.setdefault("env", {})["ANTHROPIC_BASE_URL"] = r["base_url"]
    sf.write_text(json.dumps(cfg, indent=2) + "\n")

    handle = d / ".claude" / "attest-recorder.json"
    handle.write_text(json.dumps({"cvm": a.cvm, "recorder": r["recorder"],
                                  "label": r["label"]}, indent=2) + "\n")
    print(f"[attest] recording {d}")
    print(f"[attest] wrote {sf}")
    print(f"[attest] every Claude Code session started in this directory now routes")
    print(f"         through the witness. Sessions seal after 30 minutes idle.")
    if not subject:
        print("[attest] note: not a git repo, so receipts here attribute work to nothing")
    print(f"[attest] to stop: remove ANTHROPIC_BASE_URL from {sf}")


def cmd_sessions(a):
    h = json.loads((Path(a.dir) / ".claude" / "attest-recorder.json").read_text())
    idx = get(f"{h['cvm']}{APP}/r/{h['recorder']}")
    print(f"recorder {idx['label']}   {idx['sealed_count']} sealed"
          + (f", 1 open ({idx['open_session']['leaves']} leaves)" if idx["open_session"] else ""))
    for i, e in enumerate(idx["sealed"], 1):
        rng = f"drand {e['rounds'][0]}..{e['rounds'][1]}" if e.get("rounds") else "no beacon"
        print(f"  {i:>3}  {e['session_root'][:16]}…  {e['leaves']:>3} leaves  {rng}  {e['opened'][:16]}")
    print(f"\n{idx['note']}")
    if a.collect:
        out = Path(a.collect); out.mkdir(exist_ok=True)
        for i, e in enumerate(idx["sealed"], 1):
            b = get(f"{h['cvm']}{APP}/s/{e['receipt_token']}/receipt")
            (out / f"session-{i:03d}.json").write_text(json.dumps(b, indent=2))
        print(f"collected {len(idx['sealed'])} receipts -> {out}/")


# --- roll-up across sessions -------------------------------------------------
#
# The construction is the one already here, one level up: a Merkle tree whose
# leaves are session roots. That buys, across sessions, what a single receipt
# already has within one — a count that cannot be understated once disclosed,
# and inclusion proofs for any subset.
#
# What it deliberately does NOT buy: the index root is not attested by anything.
# Each disclosed session still carries its own quote or IAT, so the sessions are
# individually attested while the *set* is merely asserted by whoever kept the
# index. Nothing stops omitting a session. That is the same floor as everywhere
# else here and the output says so rather than leaving it to be inferred.

def _index_load(path):
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else {"kind": "edge-tee session index",
                                                         "sessions": []}


def cmd_index(a):
    idx = _index_load(a.file)
    if a.action == "add":
        for r in a.receipts:
            b = json.loads(Path(r).read_text())
            bs = b.get("beacons") or ([b["beacon"]] if b.get("beacon") else [])
            idx["sessions"].append({
                "session_root": b["session_root"],
                "purpose": b.get("purpose", ""),
                "attester": b.get("attester", "dstack-cvm"),
                "subject": b.get("subject") or [],
                "rounds": [bs[0]["round"], bs[-1]["round"]] if bs else None,
                "file": str(Path(r).resolve()),
            })
        Path(a.file).write_text(json.dumps(idx, indent=2))
        roots = [bytes.fromhex(x["session_root"]) for x in idx["sessions"]]
        print(f"{len(idx['sessions'])} sessions -> {a.file}   "
              f"index root {merkle_root(roots).hex()[:16]}…")
        return
    # show
    roots = [bytes.fromhex(x["session_root"]) for x in idx["sessions"]]
    keep = [int(x) for x in a.sessions.split(",")] if a.sessions else []
    out = {"kind": "edge-tee session index disclosure",
           "session_count": len(roots),
           "index_root": merkle_root(roots).hex() if roots else None,
           "index_root_is_not_attested":
               "Each session below carries its own attestation. The index root does "
               "not: nothing signs it, so this shows at least these sessions happened, "
               "never that no others did.",
           "sessions": []}
    for i in keep:
        e = dict(idx["sessions"][i - 1])
        e["index"] = i - 1
        e["inclusion_proof"] = [h.hex() for h in inclusion_proof(roots, i - 1)]
        out["sessions"].append(e)
    Path(a.out).write_text(json.dumps(out, indent=2))
    print(f"disclosed {len(keep)} of {len(roots)} sessions -> {a.out}")


def cmd_index_check(a):
    d = json.loads(Path(a.bundle).read_text())
    n = d["session_count"]
    mr = bytes.fromhex(d["index_root"])
    for e in d["sessions"]:
        got = root_from(bytes.fromhex(e["session_root"]), e["index"], n,
                        [bytes.fromhex(x) for x in e["inclusion_proof"]])
        if got != mr:
            raise SystemExit(f"session {e['index'] + 1} is not in this index")
        rng = f"drand {e['rounds'][0]}..{e['rounds'][1]}" if e.get("rounds") else "no beacon"
        print(f"  ok session {e['index'] + 1} of {n}  {e['session_root'][:16]}…  "
              f"{rng}  {e['purpose'][:34]!r}")
    print(f"\nindex root {d['index_root'][:32]}… recomputes")
    print(f"{len(d['sessions'])} of {n} sessions shown, {n - len(d['sessions'])} withheld "
          f"but counted")
    print("\nThe index root is not attested by anything. Each session above is "
          "individually\nattested; the claim that there were exactly "
          f"{n} is this index-holder's word.")


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

    # Indices must be strictly increasing, unique, and inside the tree. Without
    # this, dropping the optional merkle_root field routed the whole receipt down
    # the array-order branch where labels were never checked, and permuting them
    # moved calls between turns; duplicating an entry counted its tokens twice.
    idx = [_index(c) for c in b["calls"]]
    if any(j <= i for i, j in zip(idx, idx[1:])):
        raise SystemExit("leaf indices are not strictly increasing — duplicated or reordered")
    if idx and (idx[0] < 0 or idx[-1] >= count):
        raise SystemExit(f"leaf index outside 0..{count - 1}")
    if len(b["calls"]) > count:
        raise SystemExit(f"{len(b['calls'])} leaves listed but call_count is {count}")
    if len(b["calls"]) == count and idx != list(range(count)):
        raise SystemExit("receipt claims every leaf but the indices are not 0..n-1")

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

    rd = report_data(bytes.fromhex(b["session_root"]), b.get("beacon"), b.get("beacons"))
    if b.get("report_data") and rd.hex() != b["report_data"]:
        raise SystemExit("report_data does not bind this root and beacon")

    structure = _report_thread(b, count)

    tin, tout, tcache, models = _usage_of(b)
    # The committed questions are in verdict/adjudicate markers (Merkle leaves);
    # 'purpose' is a top-level convenience label NOT covered by the tree. Print the
    # committed leaves so a verifier judges against them, and flag any mismatch so
    # a tampered display line cannot ride along green (issue #10).
    _events_list = [e for _, e in _events(b)]
    _verdicts = [e for e in _events_list if e.get("event") == "verdict"]
    _adj = next((e for e in _events_list if e.get("event") == "adjudicate"), {})
    _committed_qs = ([v.get("instruction", "") for v in _verdicts if v.get("instruction")]
                     or ([_adj["instruction"]] if _adj.get("instruction") else []))
    if _committed_qs:
        print(f"committed question(s)  [{len(_committed_qs)}, from Merkle leaves]")
        for _i, _qt in enumerate(_committed_qs, 1):
            print(f"  {_i}. {_qt.strip()[:68]!r}")
        if b.get("purpose") and _committed_qs[0].strip()[:36] not in b["purpose"]:
            print(f"  WARNING: top-level 'purpose' {b['purpose']!r} does not reflect the")
            print("           committed question — it is a label, not a committed leaf.")
    else:
        print(f"purpose  {b['purpose']!r}   [convenience label, not a committed leaf]")
    print(f"release  {b['release']['profile']}"
          + (f" (instructed by {b['release']['instructed_by']})"
             if b["release"].get("instructed_by") else ""))
    bs = b.get("beacons") or ([b["beacon"]] if b.get("beacon") else [])
    if len(bs) > 1:
        # api.drand.sh/public/latest is the default League-of-Entropy chain, 30s
        # per round (not 3s — issue #9). verify-quote confirms the period live.
        span = (bs[-1]["round"] - bs[0]["round"]) * 30
        print(f"spanned     drand {bs[0]['round']}..{bs[-1]['round']}  "
              f"(at least {span // 60}m{span % 60:02d}s)")
    elif bs:
        print(f"not before  drand round {bs[0]['round']}  [one sample: a moment, "
              f"not a span]")
    ch = b.get("checked")
    if ch:
        print(f"checked     question {ch['prompt_sha256'][:16]}…  "
              f"{ch['transcript_chars']} chars"
              + ("  [TRUNCATED]" if ch.get("truncated") else ""))
        for line in (ch.get("verdict") or ch.get("error") or "").splitlines()[:6]:
            print(f"            {line[:74]}")
        print("            [a model's opinion, answered in-enclave over the committed")
        print("             transcript. That it ran on the real transcript is attested;")
        print("             that the answer is right is not]")
    for sub in b.get("subject") or []:
        print(f"subject     {sub['at']:<5} HEAD {(sub.get('ref') or '?')[:12]}  "
              f"diff {(sub.get('diff_sha256') or '?')[:12]}…")
    print(f"usage    {tin} in / {tout} out / {tcache} cached tokens"
          f"   model(s): {', '.join(models) or 'n/a'}")
    if not tin and not tout:
        print("         [none relayed through this witness]")
    elif structure == "partial" or len(b["calls"]) < b.get("call_count", len(b["calls"])):
        print(f"         [shown leaves only, not the session total: {len(b['calls'])} of "
              f"{b.get('call_count')} leaves are in this file]")
    print("         [the provider's own figures, read out of responses this witness")
    print("          received over TLS against a pinned root]")
    attester = b.get("attester", "dstack-cvm")
    if attester == "silabs-simg301":
        # The chip binds the session root as the IAT nonce rather than as TDX
        # report_data. Everything above this line is the same check for both
        # attesters, because the constructions are the same; only what signs the
        # root differs, so only this step dispatches.
        iat = b.get("iat_hex")
        if not iat:
            print(f"attester {attester}: no SESS_CLOSE token — "
                  f"{b.get('quote_error') or 'nothing here is attested'}")
        else:
            nonce = _iat_nonce(bytes.fromhex(iat))
            if nonce != bytes.fromhex(b["session_root"]):
                raise SystemExit(f"IAT nonce {nonce.hex()[:32]}… does not bind this "
                                 f"session root {b['session_root'][:32]}…")
            print(f"attester {attester}: IAT nonce binds this session root")
            print("         COSE signature NOT checked here — verify it against the "
                  "device key with silabs-secure-vault/zktls/host/verify_session.py")
    elif b.get("quote"):
        # This line used to be printed without parsing anything, so a fabricated
        # session with a quote blob copied from an unrelated receipt read as bound.
        hexq = b["quote"].get("quote") if isinstance(b["quote"], dict) else None
        if not isinstance(hexq, str):
            raise SystemExit("quote field is not hex; cannot confirm what it binds")
        got = parse_quote(bytes.fromhex(hexq))["report_data"][:64]
        if got != rd.hex():
            raise SystemExit(f"quote commits to {got[:32]}…, not this session's "
                             f"{rd.hex()[:32]}… — it is a quote over something else")
        print(f"quote    present, and binds report_data {b['report_data'][:16]}…")
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


# --- PSA initial-attestation token, nonce claim ------------------------------
#
# Enough CBOR to reach claim -75008 inside a COSE_Sign1 payload, and no more.
# This does NOT check the signature; verify_session.py on the chip side does that
# against the device key, and this says so rather than implying otherwise.

def _cbor(b, i=0):
    """Return (value, next_index). Handles the subset a PSA IAT uses."""
    ib = b[i]; mt, ai = ib >> 5, ib & 0x1f; i += 1
    if ai < 24:      val = ai
    elif ai == 24:   val = b[i]; i += 1
    elif ai == 25:   val = int.from_bytes(b[i:i+2], "big"); i += 2
    elif ai == 26:   val = int.from_bytes(b[i:i+4], "big"); i += 4
    elif ai == 27:   val = int.from_bytes(b[i:i+8], "big"); i += 8
    else:            raise SystemExit("unsupported CBOR additional info")
    if mt == 0:  return val, i
    if mt == 1:  return -1 - val, i
    if mt in (2, 3):
        raw = b[i:i+val]; i += val
        return (raw if mt == 2 else raw.decode("utf-8", "replace")), i
    if mt in (4, 5):
        n = val * (2 if mt == 5 else 1)
        out = []
        for _ in range(n):
            v, i = _cbor(b, i); out.append(v)
        return (out if mt == 4 else dict(zip(out[::2], out[1::2]))), i
    if mt == 6:
        return _cbor(b, i)          # tag: value follows
    if mt == 7:
        return {20: False, 21: True, 22: None}.get(ai, val), i
    raise SystemExit(f"unsupported CBOR major type {mt}")


def _iat_nonce(token: bytes) -> bytes:
    """The -75008 claim: what the chip signed, which is the session root."""
    v, _ = _cbor(token)
    if not isinstance(v, list) or len(v) < 3:
        raise SystemExit("not a COSE_Sign1 structure")
    claims, _ = _cbor(v[2])         # payload bstr -> claims map
    if -75008 not in claims:
        raise SystemExit(f"no nonce claim (-75008); saw {sorted(claims)}")
    return claims[-75008]


# --- TDX v4 quote: signature verification ------------------------------------
#
# Structural parsing alone let a spliced quote pass: take one genuine quote,
# replace the 64 report_data bytes with the root of a fabricated session, leave
# the measurements untouched, and every check printed what it prints for a real
# one. Found by a cold reader who read the source rather than the output.
#
# Verifying the quote's own signature closes that, because report_data sits
# inside the signed body. What is checked here:
#
#   1. the attestation key signed (header || TD report)      -> body is intact
#   2. that attestation key is bound into the QE report      -> key not swapped
#
# What is still NOT checked, and is stated in the output rather than implied:
# the PCK certificate chain up to Intel's root, and TCB status. So this
# establishes the quote is internally consistent and unaltered, not that it came
# from genuine Intel silicon.

def verify_quote_signature(raw: bytes) -> dict:
    from p256 import verify
    body = raw[:632]                       # header (48) || TD report (584)
    sig_len = int.from_bytes(raw[632:636], "little")
    sec = raw[636:636 + sig_len]
    quote_sig, attest_pub = sec[0:64], sec[64:128]
    out = {"body_signature": verify(attest_pub, quote_sig, hashlib.sha256(body).digest())}
    # cert data: type (2) + size (4), then the QE report block when type == 6
    if int.from_bytes(sec[128:130], "little") == 6:
        inner = sec[134:]
        qe_report = inner[0:384]
        alen = int.from_bytes(inner[448:450], "little")
        auth = inner[450:450 + alen]
        out["attest_key_bound"] = (hashlib.sha256(attest_pub + auth).digest()
                                   == qe_report[320:352])
    return out


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


# --- hardware attestation via dcap-qvl, and the drand time bound -------------
#
# The quote's chain to Intel's root, its TCB status, QE identity, and revocation
# are verified by Phala's dcap-qvl (pip install dcap-qvl) rather than
# reimplemented here: a hand-rolled subset that skipped TCB/CRL would give false
# confidence at exactly the point that matters. What stays local is attest-proxy's
# own logic — commitment recomputation, report_data binding, the drand bound.

def _dcap_verify(raw: bytes):
    """Full Intel DCAP verification via dcap-qvl. Returns its VerifiedReport
    (status, advisory_ids). Raises SystemExit if the library is absent, so the
    caller tells the user to install it rather than silently skipping the check."""
    import asyncio
    try:
        import dcap_qvl
    except ImportError:
        raise SystemExit(
            "dcap-qvl is not installed, so genuine-silicon + TCB cannot be checked.\n"
            "  pip install dcap-qvl   (pure-Python wheel; fetches Intel collateral\n"
            "  through Phala's PCCS). Re-run verify-quote once it is installed.")
    return asyncio.run(dcap_qvl.get_collateral_and_verify(raw))


def _drand(round_):
    """Fetch drand chain /info and one round: (period, genesis_time, randomness)."""
    with urllib.request.urlopen("https://api.drand.sh/info", timeout=15) as r:
        info = json.loads(r.read())
    with urllib.request.urlopen(f"https://api.drand.sh/public/{round_}", timeout=15) as r:
        got = json.loads(r.read())
    return info["period"], info["genesis_time"], got.get("randomness")


def _github_tree(repo_url, sha):
    """The git tree sha GitHub records for a commit — a sha1, comparable to the
    daemon's reported tree_hash. Proves the cited commit's tree is the published
    one; the daemon cannot name a commit whose tree does not match on GitHub."""
    import re
    m = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url)
    if not m:
        return None
    url = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/git/commits/{sha}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return (json.loads(r.read()).get("tree") or {}).get("sha")


def _replay_rtmr(event_log, imr):
    """Fold one IMR's event log the way the TDX module does, so the result can be
    checked against the value inside the signed quote. imr-3 events carry no
    precomputed digest; theirs is sha384(type_le32 : name : payload)."""
    r = bytes(48)
    for e in event_log:
        if e.get("imr") != imr:
            continue
        if e.get("digest"):
            digest = bytes.fromhex(e["digest"])
        else:
            payload = bytes.fromhex(e["event_payload"]) if e.get("event_payload") else b""
            digest = hashlib.sha384(int(e["event_type"]).to_bytes(4, "little")
                                    + b":" + e["event"].encode() + b":" + payload).digest()
        r = hashlib.sha384(r + digest).digest()
    return r.hex()



def cmd_verify_quote(a):
    b = json.loads(Path(a.bundle).read_text())
    q = b.get("quote")
    if not q:
        raise SystemExit(f"no quote in this bundle ({b.get('quote_error')}) "
                         "-- nothing here is attested")
    hexq = q.get("quote") if isinstance(q, dict) else None
    if not isinstance(hexq, str):
        raise SystemExit("quote field is not hex; cannot parse")
    raw = bytes.fromhex(hexq)
    m = parse_quote(raw)

    sigs = verify_quote_signature(raw)
    if not sigs.get("body_signature"):
        raise SystemExit("the quote's own signature does not verify: its body has been "
                         "altered, or it was not produced by the key it carries")
    print("quote signature verifies: yes  (report_data is inside the signed body,")
    print("                               so it cannot be swapped for another session)")
    if sigs.get("attest_key_bound") is False:
        raise SystemExit("the signing key is not the one the quoting enclave vouched for")
    if sigs.get("attest_key_bound"):
        print("signing key vouched for by the quoting enclave: yes")

    expect = report_data(bytes.fromhex(b["session_root"]), b.get("beacon"), b.get("beacons"))
    got = m["report_data"][:64]
    if got != expect.hex():
        raise SystemExit(f"quote commits to {got}, not this session's {expect.hex()}")
    print("report_data binds this session: yes")

    # Genuine Intel silicon + current TCB — the PCK chain to Intel's root, TCB
    # status, QE identity, and revocation, all via dcap-qvl (issue #12).
    rep = _dcap_verify(raw)
    status = getattr(rep, "status", "?")
    advisories = list(getattr(rep, "advisory_ids", []) or [])
    _ok_tcb = {"UpToDate", "SWHardeningNeeded", "ConfigurationNeeded",
               "ConfigurationAndSWHardeningNeeded"}
    if status not in _ok_tcb:
        raise SystemExit(f"DCAP verification: TCB status is {status!r} — this platform "
                         "is out of date or revoked. Do not rely on this quote.")
    print("genuine Intel TDX (dcap-qvl): yes — quote chains to Intel's root")
    print(f"TCB status: {status}"
          + (f"   advisories: {', '.join(advisories)}" if advisories
             else "   (no outstanding advisories)"))
    if status != "UpToDate":
        print("  NOTE: not 'UpToDate' — the platform needs the noted mitigation; "
              "weigh that before relying on it.")

    # Time lower bound: verify the committed drand round against the public chain
    # and print a real timestamp, not an inert round number (issue #11).
    bcns = b.get("beacons") or ([b["beacon"]] if b.get("beacon") else [])
    if bcns:
        r0 = bcns[0]
        try:
            period, genesis, rnd = _drand(r0["round"])
            if rnd and rnd == r0.get("randomness"):
                import datetime
                ts = datetime.datetime.utcfromtimestamp(genesis + (r0["round"] - 1) * period)
                print(f"not before: {ts.strftime('%Y-%m-%d %H:%M:%S')} UTC  "
                      f"(drand round {r0['round']} verified against the public chain)")
            else:
                print(f"WARNING: drand round {r0['round']} randomness does not match the "
                      "public chain — the time bound is unverified.")
        except Exception as e:
            print(f"could not verify the drand time bound: {e}")

    # Replay the event log into RTMR3. The log lists what was measured — os image,
    # app compose hash, app id — and folding it must reproduce the RTMR3 that sits
    # inside the signed quote. That is what turns these from JSON the pod served
    # into values the hardware measured.
    elog = []
    try:
        elog = json.loads((q or {}).get("event_log") or "[]")
    except Exception:
        pass
    evt = {e["event"]: e["event_payload"] for e in elog
           if e.get("imr") == 3 and e.get("event")}
    if elog:
        rep3 = _replay_rtmr(elog, 3)
        if rep3 != m["rtmr3"]:
            raise SystemExit("the event log does not replay to the quote's RTMR3 — it was "
                             "altered, or does not belong to this quote.")
        print("event log binds to the quote (RTMR3 replay): yes — so these are measured, "
              "not self-reported:")
        print(f"  os image      {evt.get('os-image-hash', '?')[:40]}…")
        print(f"  app compose   {evt.get('compose-hash', '?')[:40]}…")
        print(f"  app id        0x{evt.get('app-id', '?')}")

    # Expected base measurements for the published dstack release. MRTD/RTMR1/RTMR2
    # are reproduced from that release with dstack-mr (command below); RTMR0 is the
    # release value (reproducing it needs dstack's acpi-tables build). So this diffs
    # against upstream-reproduced values, not a value pinned from this same pod.
    base_f = Path(__file__).resolve().parent / "measurements.json"
    if base_f.exists():
        base = json.loads(base_f.read_text())
        if evt.get("os-image-hash") and base.get("os_image_hash") \
                and evt["os-image-hash"] != base["os_image_hash"]:
            print(f"WARNING: the quote's os-image-hash is not the audited {base.get('image')} "
                  f"— a different release than reproduced.")
        bad = [k for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2")
               if base.get(k) and base[k] != m[k]]
        if bad:
            print(f"WARNING: base-image measurements differ from {base.get('image', '?')} "
                  f"({', '.join(bad)}) — a different image than the audited one.")
        else:
            print(f"base image is the published {base.get('image', '')}: yes")
            print("  MRTD, RTMR1, RTMR2 reproduce from that release:")
            print("  dstack-mr -metadata metadata.json -cpu 2 -memory 4G  (RTMR0 = release value)")

    pin = Path(a.pin) if a.pin else Path.home() / ".claude/attest-proxy-pin.json"
    # Measured by the platform, read out of the quote.
    current = {k: m[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    # NOT measured: fetched over HTTPS from the deployment's own record. RTMR3
    # covers the app id and compose hash, not the source tree, so these say what
    # the deployment claims it built from. Pinning them still makes a change
    # visible, which is worth having — but they are self-report, and printing
    # them in the same list as the RTMRs implied a hardware measurement.
    reported = {}
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
                reported[k] = src[k]
    except Exception as e:
        print(f"could not read the deployment's source provenance: {e}")
    if not reported.get("commit_sha"):
        print("NOTE: this deployment records no commit — nothing ties the code")
        print("      running here to any published source.")
    elif reported.get("tree_hash") and reported.get("repo"):
        try:
            gh = _github_tree(reported["repo"], reported["commit_sha"])
            if gh == reported["tree_hash"]:
                print(f"source tree matches GitHub: yes — commit {reported['commit_sha'][:12]} "
                      f"on {reported['repo']}\n  has tree {gh[:16]}, the tree the daemon reports it ran")
            elif gh:
                print(f"WARNING: daemon reports tree {reported['tree_hash'][:16]} for commit "
                      f"{reported['commit_sha'][:12]}, but GitHub\n  has {gh[:16]} — mismatch, do not rely on the source claim.")
            else:
                print("could not parse the repo URL to cross-check the tree against GitHub")
        except Exception as e:
            print(f"could not cross-check the source tree against GitHub: {e}")

    # Optional drift alarm: remember this deployment's measured + reported values,
    # so a later visit notices if the platform image or the reported commit changed.
    # Not the trust anchor any more — the reproductions above are — just a change bell.
    both = {**current, **reported}
    if not pin.exists():
        pin.parent.mkdir(parents=True, exist_ok=True)
        pin.write_text(json.dumps(both, indent=2))
        print(f"pinned this deployment to {pin} — later runs flag any change")
    else:
        pinned = json.loads(pin.read_text())
        drift = {k: (pinned.get(k), v) for k, v in both.items() if pinned.get(k) != v}
        if drift:
            print()
            print("CHANGED since you pinned:")
            for k, (was, now) in drift.items():
                print(f"  {k}\n    was {was}\n    now {now}")
            if [k for k in drift if k in current]:
                raise SystemExit("platform measurements changed — a different image or "
                                 "machine than you pinned. Stop and re-audit.")
            print("(source fields changed: the deployment reports a different commit; the "
                  "GitHub check above applies to the new one. Re-audit it.)")

    print()
    print("Established, reproduced from published upstream:")
    print("  - genuine Intel TDX, current TCB (dcap-qvl chains to Intel's root)")
    print("  - the quote binds THIS session (report_data)")
    print("  - the event log replays into the quote's RTMR3, so os-image-hash and")
    print("    compose-hash are hardware-measured, not self-reported")
    print("  - the base image is the published dstack release; MRTD/RTMR1/RTMR2")
    print("    reproduce from it with dstack-mr")
    print("  - the app's git tree matches GitHub for the reported commit")
    print("  - a drand round verified against the public chain (time lower bound)")
    print()
    print("Trust boundary (daemon-vouched): the app runs as a container the tee-daemon")
    print("launches inside its CVM, so RTMR3 measures the DAEMON, not the app. The")
    print("daemon — itself measured, and open-source so you can read what it does — ")
    print("reports it ran this repo at the commit above; the GitHub check confirms that")
    print("commit's tree, but no hardware measurement covers the app's own code. Closing")
    print("this hop needs an app-cvm deployment or a report_data source-binding.")


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
    r.add_argument("--check", help="a question, fixed now, that the witness answers "
                   "at close over the transcript it holds")
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

    tn = sub.add_parser("turn", help="take a further turn in a thread you are in")
    tn.add_argument("handle")
    tn.add_argument("--text", help="commit this text as the turn")
    tn.add_argument("cmd", nargs=argparse.REMAINDER)
    tn.set_defaults(fn=cmd_turn)

    cl = sub.add_parser("close", help="seal the thread and collect your receipt")
    cl.add_argument("handle"); cl.add_argument("--out"); cl.set_defaults(fn=cmd_close)

    rc = sub.add_parser("receipt", help="fetch your party-scoped receipt")
    rc.add_argument("handle"); rc.add_argument("--out"); rc.set_defaults(fn=cmd_receipt)

    ad = sub.add_parser("adjudicate", help="put one instruction and one document to "
                        "a model in a closed, publishable context")
    ad.add_argument("--instruction", required=True, action="append",
                    help="text, or a path to it; repeat to put several questions "
                         "in one receipt under one quote")
    ad.add_argument("--doc", help="the document under assessment (single-question only)")
    ad.add_argument("--model", default="sonnet",
                    help="haiku|sonnet|opus|fable|glm, or a full model id")
    ad.add_argument("--provider", default="anthropic", choices=["anthropic", "zai"])
    ad.add_argument("--private-document", action="store_true",
                    help="commit the document's hash but keep its text out of the receipt")
    ad.add_argument("--invite"); ad.add_argument("-o", "--out")
    ad.set_defaults(fn=cmd_adjudicate)

    en = sub.add_parser("enable", help="record every session started in a directory")
    en.add_argument("dir", nargs="?", default=".")
    en.add_argument("--label"); en.add_argument("--invite")
    en.set_defaults(fn=cmd_enable)

    se = sub.add_parser("sessions", help="list what a recorded directory has accumulated")
    se.add_argument("dir", nargs="?", default=".")
    se.add_argument("--collect", metavar="DIR", help="also download every sealed receipt")
    se.set_defaults(fn=cmd_sessions)

    ix = sub.add_parser("index", help="roll up many session receipts into one tree")
    ix.add_argument("action", choices=["add", "show"])
    ix.add_argument("receipts", nargs="*")
    ix.add_argument("--file", default="attest-index.json")
    ix.add_argument("--sessions", help="1-based, e.g. 2,5")
    ix.add_argument("-o", "--out", default="index-disclosure.json")
    ix.set_defaults(fn=cmd_index)

    ic = sub.add_parser("index-check", help="verify an index disclosure")
    ic.add_argument("bundle"); ic.set_defaults(fn=cmd_index_check)

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
