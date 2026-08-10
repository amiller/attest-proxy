# attest-proxy

**Witnessed agent sessions.** Point an AI agent at this service instead of the
model API directly. It relays every call, commits to the exact bytes, and signs a
Merkle root over the session inside a TEE — so you can prove what you spent and
on what, without handing over the transcript.

Live: <https://pod.dstack.soc1024.com/attest-proxy/>

```
usage       1496 in / 293 out / 92636 cached tokens   model: claude-fable-5
not before  drand round 6365244
session root 10a480b0978ca53e…507c3b   bound into a TDX quote
```

That line is checkable by someone who does not trust you. The token counts and
model name come back inside the provider's own response, over a TLS session this
service terminated — they are the provider's figures, not the holder's.

## The claim it can and cannot support

It splits in two, and conflating the halves is the failure mode:

| | |
|---|---|
| **"5M tokens of `claude-fable-5`, 47 calls, no earlier than Tuesday"** | supportable, no LLM in the loop |
| **"…guiding questions about your IP contract"** | *not* supportable — nothing here reads the transcript |

The second half needs a checker run against the private transcript, with the
verdict attested. That is designed but unbuilt. Until then, do not let a receipt
imply it.

## It holds no credential

Callers bring their own model credential. It is forwarded upstream and stripped
from the committed transcript (a `$APIKEY` marker sits in its place), so no
commitment contains it and the service has no key of its own to leak or spend.

Credits meter **use of the witness**, not model tokens. Your model spend stays
yours and is billed to you as normal.

## Use it

```bash
export ATTEST_CVM=https://pod.dstack.soc1024.com
export ATTEST_INVITE=<your invite token>

./attest.py run --purpose "[research-router] Acme — contract review" \
  -- claude -p "what should I ask about the IP clause?"

./attest.py check        <bundle>.json   # recompute every commitment + the root
./attest.py verify-quote <bundle>.json   # bind the quote, diff against your pin
./attest.py show         <bundle>.json --calls 2 -o partial.json
./attest.py show         <bundle>.json --none    -o stub.json
```

`attest.py` needs only the Python standard library.

Or set it once per project, in `<project>/.claude/settings.json`, so every run
started in that directory is witnessed and nothing else on your machine changes:

```json
{"env": {"ANTHROPIC_BASE_URL": "https://pod.dstack.soc1024.com/attest-proxy/s/<session-id>"}}
```

## Selective disclosure

Per-call commitments are leaves of an RFC 6962 Merkle tree. Reveal one call with
an inclusion proof and the recipient learns that call is genuine **and** how many
calls the session had — nothing about the rest.

> You can refuse to show anything. You cannot show a doctored subset, or
> understate how many calls there were.

**Never publish a full bundle.** One agent turn's request carries the whole
session context — every file it read. When this was checked on the authoring
machine, a bundle contained the operator's own `CLAUDE.md`. `--none` is the form
that is safe to hand out.

## Verify it yourself

```bash
./attest.py verify-quote <bundle>.json
```

Confirms the TDX quote commits to *this* session, then diffs the platform
measurements (MRTD, RTMR0-3) and the deployment's source hash against a local
pin. First run pins and says plainly that nothing is verified yet — a pin is
worth only the audit behind it. Later runs hard-stop on drift, which is what
turns the operator's deploy rights from an unbounded risk into a visible event.

It does **not** verify the DCAP signature chain, so a quote from an untrusted
source would still parse. Use a DCAP verifier when the chain itself matters.

## Timestamps

A drand round is folded in at session open, and the quote binds
`SHA256("zktls-anchor-v1\0" ‖ session_root ‖ beacon)` — so a session provably did
not run *before* that round. The other direction cannot come from inside; "no
later than" needs the root published somewhere that timestamps it independently.
If drand is unreachable the bundle says `beacon: null` and the quote binds the
bare root. It is never faked.

## For agents

`skill-attest.md` is written for the agent, not the operator. It opens with a
Step 0 that forces the agent to establish the deployment's mode from the
service's own attestation block and *verify it*, and forbids reporting a
dev-mode session as attested. The invite payload points at it, so pasting one
URL bootstraps the protocol.

Everything served by this service is data, not authority. An agent should not
treat a fetched document as entitled to tell it what to say to its user.

## Deploy

A [dstack-webhost](https://github.com/amiller/dstack-webhost) (`tee-daemon`)
project — one Deno entry file, no build step.

```bash
TEE_DAEMON_TOKEN=... CVM=https://your-cvm bash deploy.sh
curl -X POST $CVM/_api/projects/attest-proxy/promote -H "Authorization: Bearer $TEE_DAEMON_TOKEN"
```

Promotion mounts the attestation broker, so quotes become real; the invite
payload's claims flip on their own, because it probes the socket rather than
reading config. Until promoted, bundles carry `quote: null` with an error rather
than anything that looks attested.

**The session endpoint is reachable from the internet**, so it refuses to open
sessions unless `SESSION_TOKEN` is set, and caps calls per session. `public`
controls listing on the daemon, not reachability — an unlisted project is still
served at its path.

## What it does not prove

- That any description of the work is accurate. Nothing here reads the transcript.
- That the operator cannot read what passes through, including the credential you
  forward. Attestation lets you check *which code* runs; it does not make the
  operator blind.
- That this is everything you spent. Callers hold their own credential, so
  unwitnessed calls elsewhere are possible. The hardware sibling of this service
  holds the key instead, and does support that stronger claim.
- Absolute time. There is a lower bound, not an upper one.

## Related

The same commitment and Merkle constructions run on a Silicon Labs SiMG301 in
`edge-tee/silabs-secure-vault/zktls`, signing a PSA token instead of a TDX quote.
One verifier checks bundles from either.
