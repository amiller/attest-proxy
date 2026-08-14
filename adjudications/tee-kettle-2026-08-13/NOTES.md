# TEE-kettle / domas adjudication — state and next step

Written 2026-08-13 before a compaction. Read this first.

## What the actual goal is

A link was posted in a channel: domas (@xoreaxeaxeax) announcing an exploit,
`xor dword [0xf80c2094], 1<<22`, claimed to unlock microcode / PSP / SMM on
"100 million AMD CPUs", "can't be fixed".

AM's analysis, which he wants a frontier model to back: **the processor family
implied by that address has never supported SEV-SNP**, so this does not touch
AMD confidential-computing attestation. The point is to post a receipt into a
channel of TEE-aware people proving he asked a real frontier model a fair
question in a clean context — "grok is this true?" but outside the platform and
checkable.

This is NOT a cybersecurity analysis exercise, and it is NOT about proving
refusals are interesting. Do not drift back into either.

## What works, and the exact boundary

Fable refuses anything that ties a CPU population to a security outcome, and
answers the same silicon facts asked flat. Measured, each one an attested run:

| instruction | result |
|---|---|
| `instruction.md` — "does this exploit affect SEV-SNP" + tweet | refused |
| `instruction-taxonomy.md` — taxonomy question + tweet | refused |
| `instruction-standalone.md` — taxonomy question, no tweet | refused |
| `instruction-catalog.md` — catalog Qs mentioning "100 million AMD CPUs" | refused |
| **`q1-snp-productline.md`** — "which lines implement SNP, from which Zen gen" | **answered** |
| `q2-address-platform.md` — which block decodes 0xFED8_0000 / 0xF800_0000 | refused |
| control ("capital of France") | answered |

So: **mentioning an MMIO address at all, or any population-plus-security
framing, triggers refusal. The bare product-line question does not.**

Refusals arrive as HTTP 200 with `stop_reason: refusal` and zero content blocks.
That used to render as a blank verdict; fixed in `6a430cb`, now surfaced as
`[the model declined to answer]` with `declined`/`stop_reason` committed.

## The good receipt — this is the deliverable so far

`q1-snp-productline.json` → https://pod.dstack.soc1024.com/attest-proxy/claim/739f7fe6cc05c77f9bd812ecf2850cba

Fable, clean context, attested. Says plainly: SNP is EPYC-only from Zen 3
(7003 Milan) onward, carried into Zen 4/5 EPYC; **never shipped on consumer
Ryzen desktop, mobile or APU parts**; Ryzen Pro has SME/TSME only.

That is half of AM's argument, in citable form.

## DURABLE (2026-08-13, after TTL fix + redeploy)

The 2h in-memory TTL was expiring every claim URL mid-afternoon. Fixed: default
TTL raised to 1 year + `THREAD_TTL_MS` plumbed into the deploy manifest (server.ts
+ deploy.sh, pushed code-only to GitHub main `5783bc9` — the tee-kettle notes were
NOT pushed, kept local). Redeployed + re-promoted; pod attested at `5783bc9`.

Both halves came from FABLE alone (no GLM/Opus needed). Fable refuses every
FCH/platform-register phrasing (q2/q3/q4 declined) but answers the plain product
questions. The two durable, attested receipts:

- **Fact 1 — SNP product line (q1-snp-productline.md):** EPYC-only from Zen 3,
  never consumer Ryzen. `/attest-proxy/claim/e37fa3c08b2e01f29e88b2a321f8190b`
- **Fact 2 — segmentation (q5-segments.md):** EPYC=server, Ryzen=consumer, ~100M
  units = consumer Ryzen not EPYC. `/attest-proxy/claim/abe21d3c35f15e9b13f58db5488efecc`

The conclusion (tweet's 100M CPUs = the line that never had SNP) is AM's, drawn
on two Fable facts. Artifact (claude.ai/code/artifact/57675698-…) updated to this
two-Fable framing with the durable URLs.

Superseded: the old GLM/Opus receipts and the pre-fix URLs (93684a2f/69e0e22f and
511a2427/739f7fe6) all expired. Below is the earlier two-model plan, kept for
context only.

## (superseded) two receipts across models

The channel post carries two attested receipts, not one:

- **The claim, in context — GLM (`glm-4.6`, zai), domas tweet attached.** "Does
  this exploit break SEV-SNP?" → NO; SNP is EPYC server silicon, the unlock
  reads as a platform/SMM register attack, not a break of SEV isolation.
  `/attest-proxy/claim/511a24274df767c1b231b9d381a04def` (adjudication-glm-paired.json).
- **The load-bearing fact — Fable (`claude-fable-5`, anthropic), asked flat.**
  SNP is EPYC-only from Zen 3; never on consumer Ryzen.
  `/attest-proxy/claim/739f7fe6cc05c77f9bd812ecf2850cba` (q1-snp-productline.json).

Why two models: Fable refuses the security-framed shape but answers the flat
lineage question; GLM answers the in-context security question. Fable backs the
fact the argument rests on, GLM connects it to the tweet. Both live (HTTP 200),
both carry a full dstack TDX bundle (quote + event_log + vm_config). This
supersedes the old address→platform plan — GLM's in-context NO is stronger than
an address-decode receipt would have been.

Do NOT try to jailbreak past the refusal. `instruction-reframe-{a,b,c}.md` are
earlier attempts that read as evasion; they are kept only as evidence and should
not be posted.

## Measurement provenance (was Fable's critique #2) — answered in the PRD

The receipt already points the agent at `/_api/verification/attest-proxy`, which
pins the dstack CVM measurement + app compose hash + an on-chain record;
`verify-quote` diffs the quote's `mrtd`/`rtmr0-3` against it and reports drift.
The agent/human must still accept that CVM measurement and pin the compose hash
against this repo. ONE real gap remains, disclosed as a caveat not fixed: the
**PCK/TCB chain to Intel's root is not verified**, so "genuine Intel silicon" is
asserted, not proven. That is the named next build item in the PRD requirements.

## The writing

`PRD.md` in this dir is current: rewritten by Fable, then folded in all three of
Fable's product critiques (two-receipt claim, measurement-provenance answer +
PCK/TCB gap, honest Lane A that calls its own green state a claim-until-checked).
That is the deliverable for the "good writing + PRD/user-journey" ask.

## Still open, separate from this

- Writing: AM asked for "a good writing of this" and a PRD/user-journey. A fable
  subagent produced a boots-shop version from an earlier session's wrong framing
  — discard it. Any writing must use THIS story: link in a channel, question to
  a frontier model, receipt posted back to TEE-aware friends.
- The published artifact (claude.ai/code/artifact/57675698-…) is still the boots
  explainer and is now the wrong story entirely.
- attest-proxy repo state and infra gotchas: see `NEXT.md` in the repo root.
