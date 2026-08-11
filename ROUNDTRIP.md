# Evidence of AI effort on a specific matter

A client engages a firm. The firm bills for "AI-assisted review". Neither side
can currently settle the obvious question.

The client cannot tell a real investigation from someone pasting the document
into a chat window once. The firm cannot answer by handing over its working: the
transcript carries other clients' matters, its own method, and everything the
agent read along the way.

A **round trip** gives both sides the same short record instead. The client opens
a thread holding the brief and the document; the firm joins, does the work on its
own subscription routed through the witness, and commits its advice. Both end up
with:

```
turn 1  client    leaves 1..1   0 calls
turn 2  counsel   leaves 2..9   4 calls   1698 in / 2271 out / 329848 cached   claude-opus-5
document  schedule-b.md  sha256 368655a1a1d939d7…  matches the hash committed at leaf 0
not before  drand round 6368198
quote  present, and binds report_data 268fb2a63d009b5c…
```

The token figures arrive **inside Anthropic's own response**, over a TLS session
terminated inside the enclave. They are the provider's numbers, not the firm's,
so the client does not have to take the firm's word for them. They are committed
at close, so the firm cannot restate them either.

---

## Journey 1 — the client

You are paying for the work and you want to know it happened, against *your*
document, before you settle the invoice.

```bash
export ATTEST_CVM=https://pod.dstack.soc1024.com
export ATTEST_INVITE=<your invite token>

./attest.py ask --purpose "Engagement 4417 — Schedule B review before Friday" \
  --doc schedule-b.md --responder "outside counsel" \
  --text "We sign Friday. Which clauses do we push back on, in priority order?"
```

Your brief and the document are committed before anyone is invited, so the firm
cannot later answer a different question, and cannot claim it reviewed a
different draft. You get a URL to send:

```
invite  https://pod.dstack.soc1024.com/attest-proxy/t/e04dc257…/join#4a96f1a2…
```

The token is the `#fragment`. Browsers never transmit it, so the page cannot see
it and neither can anyone reading the server's logs.

When the work is delivered:

```bash
./attest.py close attest-thread-e04dc257.json
./attest.py check attest-thread-e04dc257.receipt.json
./attest.py verify-quote attest-thread-e04dc257.receipt.json
```

You see the call count, the token totals, the model, the document hash and the
ordering. You do not see the firm's transcript, and you never receive it: the
witness withholds it before your receipt is issued.

## Journey 2 — the firm

You are billing for the work and you want it evidenced, without surrendering your
working papers.

```bash
./attest.py join "https://…/t/e04dc257…/join#4a96f1a2…" \
  -- claude -p "priority order of clauses to push back on, under 120 words"
```

Your agent is served the document, rehashes it against the hash committed before
you arrived, and works on **your own subscription** — the witness holds no
credential and forwards yours. Ending your turn commits the advice.

```bash
./attest.py receipt attest-thread-e04dc257.responder.json
```

Your receipt carries your transcript in full, and the client's leaves as
commitments only. Same root, same quote, same committed figures.

### Proving you read it, without publishing what you thought

The receipt shows effort, not attention. If that becomes the argument, disclose
one call:

```bash
./attest.py show <receipt> --calls 9 -o proof-of-reading.json
```

The disclosed call carries the clause text verbatim in its prompt, with an
inclusion proof against the attested root. Your advice, and every other call,
stay out of the file. What the client can check:

```
1 of 11 leaves shown with content, 10 withheld but counted
usage  [shown leaves only, not the session total: 1 of 11 leaves are in this file]
session root 95e4b09aeef4c7c1… recomputes
```

You can refuse to show anything. You cannot show a doctored call, or understate
how many there were.

---

## Why the figures are worth anything

One mechanism, and it is the reason this is not just a log the operator writes.

Every model call from either side is a leaf of one RFC 6962 Merkle tree, and so
are the turn boundaries, committed with the same construction and differing only
in the host. Three things follow:

- **The figures are the provider's.** Usage is read out of Anthropic's response
  inside the enclave. A firm inflating its own numbers would have to forge
  Anthropic's response body, which is committed.
- **Neither side can restate them afterwards.** Per-party call counts, token
  totals and model names are committed in the closing leaf. The verifier derives
  the same numbers from the tree and refuses the receipt if they disagree.
- **Calls are attributed by position, not by a label.** Only the party holding
  the turn may relay, leaf indices are dense, and the markers delimit the spans.
  No leaf carries a party name, so there is nothing to forge.

The root is bound into a TDX quote. `verify-quote` checks the quote commits to
this session, then diffs the platform measurements and the deployment's repo and
commit against a pin on your machine, and prints the `git clone … && git checkout
…` line for the code it says it ran. First run pins and verifies nothing; a pin
is worth only the audit behind it.

## What it does not prove

- **That the advice was any good, or even on topic.** Nothing reads the
  transcript. Token counts are effort, not quality
  ([#1](https://github.com/amiller/attest-proxy/issues/1)).
- **Confidentiality from the operator.** Both transcripts and both credentials
  pass through the witness. Attestation establishes which code runs; it does not
  blind whoever runs it. Establish who operates the instance before routing
  through it. Usually it is the party you are working for, which is the intended
  shape; where it is not, that is a decision for your principal.
- **That two credentials are two people.** One person can hold two
  subscriptions. `check` reports whether the fingerprints actually differ.
- **That the firm read anything**, unless it chooses to prove it as above.
- **An upper bound on when it ran.** A drand round gives a lower bound only.

## Operational notes

A thread seals itself at expiry, so the firm's receipt does not depend on the
client ever closing it. Receipts are persisted and survive a restart; **open
threads are not** and die with the isolate, so a turn in flight when the service
restarts has to be redone.

Every redeploy resets the project to dev and must be re-promoted, so a
counterparty's pin legitimately changes whenever you ship
([dstack-webhost#105](https://github.com/amiller/dstack-webhost/issues/105)).
