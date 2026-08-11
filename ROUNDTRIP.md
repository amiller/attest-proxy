# Attested round trip

Two people, two subscriptions, one document, taking turns — with a receipt that
neither of them could have forged and neither has to trust the other to redact.

The single-party product proves *you* spent what you say you spent. This proves
*we each did*, on the same thing, in that order.

---

## What a round trip is

A **thread** is one witnessed workspace with a shared document and more than one
party. Every model call either side makes is a leaf of one RFC 6962 tree, in
order. Turn boundaries are leaves too. One root, one quote.

```
0  OPEN     purpose, sha256 of the document, the policy
1  CRED     asker's credential fingerprint
2  call     asker's agent, on the asker's subscription
3  call
4  TURN     asker ends turn 1, question committed
5  JOIN     responder joins with the invite token
6  SERVE    the witness served the document to the responder — these exact bytes
7  CRED     responder's credential fingerprint — a different one
8  call     responder's agent, on the responder's subscription
9  call
10 TURN     responder ends turn 2, answer committed
11 CLOSE    2 turns, 12 leaves
```

Only the party whose turn it is may relay. That single rule is what makes
attribution provable rather than asserted: leaves 8–9 sit between the
responder's JOIN and the responder's TURN, indices are dense, and the witness
would have refused a call from anyone else in that span. Nobody has to believe a
label on a leaf — the position *is* the label.

## The two things that are new

**Turn order is provable.** Leaf indices are dense and the tree binds the count,
so "the responder answered after seeing the question" is a structural fact, not a
timestamp anyone can move. Neither party can retroactively insert work, reorder
turns, or claim more turns than the tree holds.

**Cross-party redaction is done by the attested code.** Each party's receipt
carries the shared structure, both turn deliverables, and *their own* transcript
in full — the other party's model calls are present only as commitments with
inclusion proofs. The asker never receives the responder's transcript, so there
is nothing for the responder to have to trust the asker to have deleted. In the
single-party product the holder redacts; here the witness does, and the quote
covers the code that did it.

## What it proves

- Two distinct credentials were used, one per party (fingerprints differ)
- Both parties were served the same document, by sha256
- Turn order, and that each party's calls fall inside its own turn
- Each party's token spend and model, from the provider's own responses
- Neither party can understate its call count, having disclosed nothing

## What it does not prove

- **That the two credentials are two people.** One person can hold two
  subscriptions. The fingerprint distinguishes credentials, nothing more.
- **That either side read anything.** SERVE proves the witness handed over those
  bytes. A party can *choose* to prove it read them, by disclosing the leaf whose
  request body contains the document.
- **That the advice was any good, or was about the contract.** No checker runs
  here ([#1](https://github.com/amiller/attest-proxy/issues/1)).
- **Confidentiality from the operator.** Both transcripts and both credentials
  pass through the witness. Attestation says which code ran; it does not blind
  the operator.

## The asymmetry a responder should notice

The asker opens the thread, and in the simple deployment the asker also runs the
witness. So the responder is being asked to route their own credential and their
own transcript through a service operated by the party across the table.

A fresh agent, given nothing but the invite URL and told to act for the Client,
worked this out and declined:

> I did not set `ANTHROPIC_BASE_URL` and forwarded no credential. Sending a
> long-lived key to an unattested endpoint supplied by a negotiating counterparty
> is not a trade worth making for a call-count metric.

That is the correct call against a **dev-mode** deployment, and it is the reason
the mode is reported before anything else. Three things bear on it:

- **Attestation is the whole answer, and only when checked.** A verified quote
  plus a pinned source hash establishes that the code handling the credential is
  the published code. Unpinned, or in dev mode, there is nothing.
- **Declining to relay is a supported outcome, not a failure.** A party can
  commit a turn deliverable without relaying a single call. The thread then
  evidences *what was said and in what order*, but not how much work went into
  it, and `check` shows that side with no credential fingerprint and no calls.
  That is a weaker claim, honestly rendered, rather than a broken one.
- **A neutral operator removes the problem** and nothing in the protocol assumes
  otherwise: the witness is addressed by URL, and both parties are equally
  clients of it.

The same agent also observed that only the asker may close, so a stalling asker
could leave the responder with no receipt after doing the work. Threads now seal
themselves at expiry, which makes the responder's receipt unilateral.

---

## Journey 1 — the asker

You have a contract and a counterparty. You want advice on it, you want their
advice on it, and you want a record that both happened without publishing either
side's thinking.

```bash
export ATTEST_CVM=https://pod.dstack.soc1024.com
export ATTEST_INVITE=<your invite token>

./attest.py ask --purpose "Acme MSA — IP clause" --doc msa.md \
  -- claude -p "read the doc and draft the three questions I should put to them"
```

Your agent runs on your own subscription against the witness. When it finishes,
its output becomes the committed question ending your turn, and you get a URL:

```
[attest] thread eb0c576a8d0a…  not before drand round 6367735
[attest] document msa.md  sha256 d0b09a9001a87129…  678 bytes
[attest] turn 1 closed — 7 leaves, now responder's move
[attest] handle  attest-thread-eb0c576a.json
[attest] invite  http://…/t/eb0c576a…/join#19db8da1…
```

Send the URL. It is safe to paste: it carries a call cap, it expires, and it
grants nothing but a turn in this thread.

When they are done:

```bash
./attest.py close attest-thread-9f2c8d1e.json
./attest.py check attest-thread-9f2c8d1e.receipt.json
```

```
  ok leaf   5 of 15  inclusion proof verified
  ok leaf  10 of 15  inclusion proof verified   [content withheld]

session root 4f1e…  recomputes
11 of 15 leaves shown with content, 4 withheld but counted

round trip  2 turns, 15 leaves, sealed
  turn 1  asker      leaves 1..6    4 calls   1588 in / 692 out / 328614 cached   claude-opus-5
  turn 2  responder  leaves 7..13   3 calls   [content withheld from this receipt]
parties     SAME credential fingerprint on both sides — this is one party talking to itself
document    msa.md  sha256 d0b09a9001a87129…  matches the hash committed at leaf 0
            served by the witness to: responder
attribution no leaf carries a party label; spans are derived from the
            markers, and only the turn holder could relay into one

all recomputations green — turn structure established
```

That fingerprint line is from a real run with both sides on one machine. With two
subscriptions it reads `asker fp …  responder fp …  — distinct credentials`; the
check reports what it found rather than what the layout implies.

## Journey 2 — the responder

You get a link from someone you are negotiating with. You are not installing
their software and you are not sending them your transcript.

Hand the URL to your agent:

```
Read https://pod.dstack.soc1024.com/attest-proxy/t/9f2c…/join and follow it.
Tell me what this is and what it does and does not prove before doing any work.
```

Your agent fetches a manifest describing the protocol and pointing at
`skill-roundtrip.md`. It reports back what mode the deployment is in, joins, and
is served the document. Then it works — **on your subscription, with your
credential**; the witness holds no key and forwards yours upstream.

```bash
./attest.py join "https://…/t/9f2c…/join#a41b…" \
  -- claude -p "answer their questions about the IP clause"
```

Ending your turn commits your answer. You then hold a receipt of your own:

```bash
./attest.py receipt attest-thread-9f2c8d1e.responder.json
```

It shows the same root, the same turn structure, the same document hash — and
*your* transcript in full, with the asker's calls as commitments only. You can
disclose from it exactly as in the single-party product: an arbitrary subset, a
contiguous range with its completeness claim, or `--none`.

The asymmetry worth noticing: you can prove you did the work without showing it,
and you can prove they asked before you answered. Neither of you had to agree in
advance to trust the other's redaction, because neither of you performed it.

---

## Verify it rather than trust it

Same as the single-party path, and it is the same verifier:

```bash
python3 attest.py check <receipt>          # commitments, proofs, root, turn structure
python3 attest.py verify-quote <receipt>   # bind the quote, diff against your pin
python3 verify/check.py --diff             # the constructions themselves
```

`check` replays the marker leaves as a state machine and derives the turn spans
itself. It does not read a party label off a leaf; there is none to read.
