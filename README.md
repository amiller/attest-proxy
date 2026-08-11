# attest-proxy

You did work for a client, on their account, and now you have to bill for it. You
want to prove what you spent and roughly what on — without handing over the
transcript, which contains your thinking, your other matters, and everything your
agent happened to read along the way.

Point your agent at this instead of the model API. You get a receipt they can
verify and you can redact.

---

Precisely: token counts and the model name arrive **inside the provider's own
response**, over a TLS session terminated inside a TEE. They are the provider's
figures, not yours, so a counterparty does not have to trust you for them. The
witness commits to the exact bytes of every call and signs a Merkle root over the
session, so any part you later disclose is provably the part that happened, and
the signed count stops you understating the rest.

```
usage        1496 in / 293 out / 92636 cached tokens   model: claude-fable-5
not before   drand round 6365244
session root 10a480b0978ca53e…507c3b   bound into a TDX quote
```

## Try it

You need an invite — the endpoint is public but gated, because it forwards a real
credential. Ask the operator of an instance for one; if you are running your own,
`deploy.sh` mints the first token for you.

```bash
export ATTEST_CVM=https://pod.dstack.soc1024.com
export ATTEST_INVITE=<your invite token>

./attest.py run --purpose "Acme — contract review" \
  -- claude -p "what should I ask about the IP clause?"
```

Your agent runs normally. It keeps using **your** credential — this service has
no API key of its own; yours is forwarded upstream and stripped from the record.
Credits meter use of the witness, not model tokens; your model spend is billed to
you as usual.

```bash
./attest.py check <bundle>.json         # recompute every commitment and the root
./attest.py verify-quote <bundle>.json  # bind the quote, diff against your pin
```

Or set it once per project in `<project>/.claude/settings.json`, so everything
started in that directory is witnessed and nothing else on your machine changes.

An agent handed only an invite URL can set itself up: the payload points at
`skill-attest.md`, which describes the protocol and what the evidence supports.
Tested cold on Opus, Sonnet and Haiku.

## Disclose only what you want to

Per-call commitments are leaves of an RFC 6962 Merkle tree.

```bash
./attest.py show <bundle>.json --calls 2,5 -o subset.json  # arbitrary calls
./attest.py show <bundle>.json --range 2:4 -o range.json   # a contiguous run
./attest.py show <bundle>.json --none      -o stub.json    # proof only, no content
```

The three support different claims, and the difference matters. An arbitrary
subset proves each shown call is genuine but says nothing about what sits between
them. A **contiguous range** additionally proves nothing is hidden *inside* it —
leaf indices are dense, so there is no room for an undisclosed call between index
2 and index 3. That is the qualified "here is everything in this stretch" claim,
and a verifier re-derives it from the indices rather than trusting the label:

```
complete for calls 2..4 of 5: leaf indices are dense,
so no call is hidden inside that range
3 of 5 calls shown, 2 withheld but counted
```

What the recipient sees, running the same client against a partial disclosure:

```
ok call 2 of 2  inclusion proof verified
session root 10a480b0978ca53e…507c3b recomputes
1 of 2 calls shown, 1 withheld but counted
```

They learn that call 2 is genuine and that the session had exactly two calls, and
nothing about the other one.

> You can refuse to show anything. You cannot show a doctored subset, or
> understate how many calls there were.

**Never publish a full bundle.** One agent turn carries the whole session
context. When this was checked on the authoring machine, a bundle contained the
operator's own `CLAUDE.md`. `--none` is the form that is safe to hand out.

## Two parties, taking turns

The above proves *you* spent what you say you spent. A **round trip** proves *we
each did*, on the same document, in that order — you take a turn, hand over a
URL, and the other side's agent takes theirs on their own subscription.

```bash
./attest.py ask --purpose "Acme MSA — clause 7" --doc msa.md \
  -- claude -p "what should I put to them about the IP assignment?"
# -> invite  https://…/t/9f2c…/join#a41b…      send this
```

```bash
./attest.py join "https://…/t/9f2c…/join#a41b…" \
  -- claude -p "answer their questions"        # their machine, their credential
```

Every call from both sides is a leaf of one tree; turn boundaries are leaves too.
Only the party holding the turn may relay, so attribution comes from position and
no leaf needs a party label to forge.

What the asker's receipt checks out to — an actual run, both sides driven from
one machine, which is why the fingerprint line reads as it does:

```
round trip  2 turns, 15 leaves, sealed
  turn 1  asker      leaves 1..6    4 calls   1588 in / 692 out / 328614 cached   claude-opus-5
  turn 2  responder  leaves 7..13   3 calls   [content withheld from this receipt]
parties     SAME credential fingerprint on both sides — this is one party talking to itself
document    msa.md  sha256 d0b09a9001a87129…  matches the hash committed at leaf 0
attribution no leaf carries a party label; spans are derived from the
            markers, and only the turn holder could relay into one
```

The fingerprint distinguishes credentials, not people, and says so rather than
letting a one-sided rehearsal pass as a negotiation.

The new property is that **the witness does the cross-party redaction**. Each
side's receipt carries the shared structure, both deliverables, and only its own
transcript — the responder's is the mirror image, same root. The asker never
receives the responder's calls, so there is nothing for the responder to trust
the asker to have deleted, and the quote covers the code that redacted.

Full spec and both user journeys: [ROUNDTRIP.md](ROUNDTRIP.md), which also covers
the asymmetry a responder should notice before forwarding a credential to a
witness their counterparty operates.

## Verify it rather than trust it

```bash
./attest.py verify-quote <bundle>.json
```

Confirms the TDX quote commits to *this* session, then diffs the platform
measurements and the deployment's source hash against a pin on your machine.
First run pins and says plainly that nothing is verified yet — a pin is worth
only the audit behind it. Later runs stop on drift, which is what turns the
operator's deploy rights from an unbounded risk into a visible event.

It does not verify the DCAP signature chain; a quote from an untrusted source
would still parse. Use a DCAP verifier when the chain itself matters.

## What it does not prove

- **That any description of the work is accurate.** Nothing here reads the
  transcript. "5M tokens of `claude-fable-5`" is supportable; "…guiding questions
  about your IP contract" is not. That needs an attested checker — designed, not
  built ([#1](https://github.com/amiller/attest-proxy/issues/1)).
- **Confidentiality from the operator.** Your credential and your transcript pass
  through this service. Attestation establishes *which code* runs; it does not
  blind the operator.
- **That this is everything you spent.** You hold your own credential, so calls
  made elsewhere are not covered. The hardware sibling holds the key instead and
  does support that stronger claim.
- **An upper bound on when it ran.** There is a lower bound only; "no later than"
  needs the root published somewhere that timestamps it independently.

## How it is checked

The constructions live in `witness.ts` — 71 lines, separate from the service so
they can be read and reimplemented on their own. Three implementations must agree
byte for byte, or a bundle from one attester fails against another's verifier.

| | checked how |
|---|---|
| Merkle structure | exhaustive: all 32,896 reachable (tree, leaf) pairs |
| Turn spans | generative: 5 turn plans, spans and per-span counts match |
| Span integrity | every single-leaf deletion and out-of-turn marker rejected |
| Python ↔ TypeScript | differential, random inputs, in CI |
| Python ↔ C firmware | differential, 11 tree sizes on real hardware |
| SHA-256 | assumed |
| TEE, quote chain, TLS, operator access | out of scope, and stated as such |

Span integrity is worth singling out: inclusion proofs do **not** catch a deleted
leaf, because the ones that remain still verify. Deleting a leaf silently shrinks
the turn it sat in, which is exactly the understatement the count binding exists
to prevent, so `check` refuses to report any turn structure unless the leaf
indices are dense.

```bash
python3 verify/check.py --diff
```

## Run your own

A [dstack-webhost](https://github.com/amiller/dstack-webhost) project — one Deno
entry file, no build step.

```bash
TEE_DAEMON_TOKEN=... CVM=https://your-cvm bash deploy.sh
curl -X POST $CVM/_api/projects/attest-proxy/promote -H "Authorization: Bearer $TEE_DAEMON_TOKEN"
```

Until promoted there is no quote, and bundles say so rather than looking
attested. **Every redeploy resets the project to dev and must be re-promoted** —
correct, since new code has not earned the old code's attestation, but it means a
counterparty's pin legitimately changes whenever you ship
([dstack-webhost#105](https://github.com/amiller/dstack-webhost/issues/105)).

The session endpoint is reachable from the internet, so it refuses to open
sessions unless `SESSION_TOKEN` is set, and caps calls per session. On the daemon,
`public` controls listing, not reachability — an unlisted project is still served
at its path.

## Related

The same commitment and Merkle constructions run on a Silicon Labs SiMG301 in
`edge-tee/silabs-secure-vault/zktls`, signing a PSA token instead of a TDX quote.
There the witness holds the key, so the agent has none and cannot go around it —
which is what supports "this is everything I spent". One verifier checks bundles
from either.
