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
./attest.py show <bundle>.json --calls 2 -o partial.json   # one call, with proof
./attest.py show <bundle>.json --none    -o stub.json      # proof only, no content
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
| Python ↔ TypeScript | differential, random inputs, in CI |
| Python ↔ C firmware | differential, 11 tree sizes on real hardware |
| SHA-256 | assumed |
| TEE, quote chain, TLS, operator access | out of scope, and stated as such |

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
