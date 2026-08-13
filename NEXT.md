# Where this is, and what to do next

State as of 2026-08-12. Deployed and attested at `26dfc17b`, which is `origin/main`.

## What the thing is now

The product is **adjudication**: put one instruction and one document to a named
model inside the enclave, which composes the request itself so the entire prompt
lands in the receipt and is short enough for a sceptic to read. ~2.3 KB against
~157 KB for a recorded agent turn. The claim is not "a model said this" but
"this, and only this, is what it was given".

Everything else still works and is secondary: session recording (`enable` /
`sessions`, ambient via `.claude/settings.json`), the two-party thread, the
roll-up index, and the SiLabs chip attester.

Docs are current: `ADJUDICATE.md` (walkthrough), `DASHCAM.md` (session
recording), `skill-attest.md` (leads with adjudication, covers both attesters).
The published artifact matches.

## Next, in order

1. **Get a `ZAI_API_KEY` and exercise `--provider zai`.** It is implemented and
   has never made a single call. This unblocks (2), and matters beyond cost: a
   static API key does not expire, where an OAuth session token does.
2. **Stand up the zed lane.** Verified reachable over `ssh -o BatchMode=yes zed`
   (an older note saying agents cannot ssh zed is wrong). It has python3 and can
   reach the pod. `adjudicate` needs **no Claude Code install** — stdlib python
   plus a credential. The only blocker is that zed's OAuth token is expired and
   cannot be refreshed headlessly. With a Z.AI key the lane runs unattended.
   Pass condition is easy: `attest.py check` exits 0 and a verdict is present.
   No golden outputs to maintain.
3. **[#7](https://github.com/amiller/attest-proxy/issues/7) DCAP verification.**
   `verify-quote` never checks the quote's signature, so someone holding one
   genuine quote could splice in a different `report_data` and get identical
   output. Found by a cold reader. It is the last checkable-looking thing that
   is not checked, and `automata-dcap-v3-attestation` is already in this tree.
4. **Re-pin measurements.** `~/.claude/attest-proxy-pin.json` is several commits
   stale, so `verify-quote` currently reports source drift.
5. **[#2](https://github.com/amiller/attest-proxy/issues/2)** is design-stage,
   not blocking.

## Gotchas that cost hours; do not rediscover them

- **`429 rate_limit_error` from Anthropic usually is not a rate limit.** A
  subscription OAuth credential serves Sonnet or Opus only when the first system
  block is exactly `You are Claude Code, Anthropic's official CLI for Claude.`
  Anything else gets 429. **Haiku does not enforce it**, so small-model runs pass
  and hide the problem. Check the account's real utilization before believing a
  quota story.
- **Never pipe a gate into `head`/`tail` inside an `&&` chain.** The pipeline's
  exit status is the pager's, so a failing `deno check` still deploys. This
  shipped a commit that did not typecheck.
- **`deploy.sh` deploys from GitHub `main`, not your working tree.** Push first,
  or you will deploy the previous commit and be confused by it.
- **Every redeploy resets the project to `dev`** and must be re-promoted, which
  also changes `tree_hash` and legitimately breaks a counterparty's pin.
- **Threads live in memory and die with the isolate**; receipts are persisted and
  survive. A turn in flight during a restart has to be redone.
- **When fixing a leak, check whether the new field carries the withheld data.**
  `--private-document` was fixed twice: the second fix added `full: docText` for
  hashing and republished the document through it.

## Method note

Three of the most valuable findings came from handing a receipt or an invite URL
to a fresh agent with no context and asking what it could conclude — the
document leak, the partisan-instruction detection, and the DCAP gap. It is worth
more per run than any test written from the inside, because the producer's view
cannot see what a stranger cannot check.
