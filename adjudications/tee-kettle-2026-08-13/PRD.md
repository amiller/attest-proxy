# PRD — checking a claim someone dropped in the channel

2026-08-13. The running example is real: domas's AMD exploit tweet, and two live
receipts — GLM at `/attest-proxy/claim/511a2427…` and Fable at
`/attest-proxy/claim/739f7fe6…`.

## The situation

domas (@xoreaxeaxeax) tweets that one instruction — `xor dword [0xf80c2094],
1<<22` — unlocks microcode, PSP, and SMM on "100 million AMD CPUs," and can't
be fixed. Someone posts it in a channel of TEE-aware friends. You think the
claim is overblown for confidential computing: the processor family that
address implies never supported SEV-SNP, so this doesn't touch AMD's
attestation. You want a frontier model on record about the silicon.

Asking is easy; the problem is reporting back. "I asked and it says SNP never
shipped on consumer Ryzen" carries only your word. You could have led the
model. You could have paraphrased. You could have picked the one answer out of
five that agreed with you.

This tool closes that gap. You ask the model inside an enclave and get a URL
instead of a screenshot. The enclave composed the prompt from your question
plus the article and nothing else, called the model, and sealed the result.
Anyone in the channel can open the URL and confirm the answer is real — without
trusting you, and without trusting whoever runs the enclave.

## Who this PRD is for

The person who receives the URL, and their agent. The sender's loop is a few
seconds and already built. The product succeeds or fails on whether the
recipient can check the claim quickly and come away convinced, so everything
below is written from the recipient's chair.

## The claim takes two receipts, not one

The argument has two parts, and no single model receipt covers both, so the
post carries two.

- **The claim, assessed in context — GLM (`glm-4.6`), with the domas tweet
  attached.** Question: does this exploit break SEV-SNP; which families
  implement it; should operators treat their attestation as broken? Answer:
  *NO* — SNP is EPYC server silicon, the described unlock reads as a
  platform/SMM register attack, not a break of the SEV cryptographic isolation.
  Receipt: `/attest-proxy/claim/511a24274df767c1b231b9d381a04def`.
- **The load-bearing fact — Fable (`claude-fable-5`), asked flat.** Question:
  which AMD lines implement SEV-SNP, from which Zen generation, and has it ever
  shipped on consumer Ryzen? Answer: EPYC-only from Zen 3 (Milan); never on
  consumer Ryzen desktop, mobile, or APU. Receipt:
  `/attest-proxy/claim/739f7fe6cc05c77f9bd812ecf2850cba`.

Why two models rather than one: Fable declines the security-framed version —
any prompt that ties a chip population to an exploit outcome trips a refusal —
but answers the flat hardware-lineage question. GLM answers the in-context
security question. So Fable backs the fact the whole argument rests on, and GLM
does the reading that connects it to the tweet. Both are attested, both
questions are visible, and the split is stated rather than hidden. That is more
honest than stretching one receipt to look like it covered ground it didn't.

## What a receipt proves

The one thing the recipient needs to believe is **real model, real answer**:
the named model produced this exact answer to this exact question.

- Question and answer are bound by one SHA-256 commitment, and that commitment
  is sealed into the enclave's Intel TDX quote via `report_data`. Swap the
  question or edit the answer and the seal breaks. The seal is signed up to
  Intel's roots, not the operator's.
- The model name on the receipt is what the provider's API returned, never what
  the sender typed.
- The whole prompt is on the receipt. The enclave built it from the question
  plus the article — a closed context — so "no hidden instruction steered it"
  is something the recipient reads, not something they take on faith.

## What it does not prove

Say this on the page, in one line, next to the green check.

- It does not prove the answer is *correct* — only that the model gave it, to a
  question everyone can read and judge for fairness.
- It proves the enclave sent the request to the provider's endpoint and
  recorded the real response, model field included. It does not vouch for the
  provider's honesty about which weights served the call.

The receipt proves the exchange happened, in exactly this form. Judging the
answer stays with the reader, and the receipt hands them the exact question to
judge it by.

## The recipient journey

The sender pastes two URLs. Each is its own receipt; each verifies the same way.

### Lane A — a friend opens a URL

They see, top to bottom, nothing to click:

1. **The question**, verbatim.
2. **The article** it was asked against, when there is one (the GLM claim
   receipt carries the domas tweet; the Fable fact receipt is a general silicon
   question with no document) — so they can judge whether the question was a
   fair reading of the claim.
3. **The answer**, verbatim, with the model as the API named it.
4. **A green/red state, and one line saying it is the server's own claim until
   checked.** This is the honest part: the page and its check are served by the
   operator, so a 30-second glance is trusting the domain. The page says so, and
   points at the one command that removes that trust (Lane B). Lane A's job is
   legibility and a fair reading of the question; the trust reduction lives in
   Lane B, and the page does not pretend otherwise.

### Lane B — a friend hands the URL to their agent

The friend tells their Claude Code agent "check this." The agent does not trust
the page's green state. On its own it runs the two commands the receipt itself
names (`attest.py check` and `attest.py verify-quote`) and:

1. **Recomputes every commitment.** The prompt is itemized by part — size and
   hash — and the parts sum to the whole, so the question, the document hash,
   the model name, and the answer all bind and nothing was edited after.
2. **Verifies the TDX quote's signature** and confirms its `report_data` binds
   *this* session, so a real quote from another run cannot be spliced in.
3. **Diffs the platform measurements** (`mrtd`, `rtmr0-3`) in the quote against
   the pod's published verification record at
   `/_api/verification/attest-proxy`, and reports any drift between the pod's
   self-reported commit and the published one rather than hiding it.
4. **Reports its own verdict**, carrying the caveats forward — *"genuine answer
   from `<model>` to exactly this question, closed context, measurements match
   the published record"* — or names what failed.

### What the measurement is checked against — and the gap

Step 3 is the answer to the obvious objection: verifying a quote to Intel only
proves *a real TDX enclave with measurement X* sealed this root; it says nothing
about whether the code behind X is honest. The receipt closes most of that on
its own — it points the agent at `/_api/verification/attest-proxy`, which pins
the dstack CVM measurement, the app's compose hash, and an on-chain record, and
`verify-quote` diffs the quote against it. What the agent (or its human) still
has to do, and the receipt says so in its own caveats, is **decide it accepts
that CVM measurement and that the compose hash matches this open-source repo,
then pin that hash.** Unpinned, "it ran the published code" is a claim the agent
has read, not one it has checked, and it must report it that way.

One gap is real and currently disclosed as a caveat, not fixed: **the PCK/TCB
chain from the quote up to Intel's root is not yet verified**, so "genuine Intel
silicon" is asserted, not proven. That is the next thing to build for this
audience, and until it is, the honest verdict tops out at "a TDX quote that
validates against the published measurements," not "provably Intel hardware."

## The sender (already built)

Sender has Claude Code and the skill installed. One command with the question
and the article; the enclave composes the prompt, calls the model, seals the
result, returns the URL. They paste it. That is the whole sender loop.

## Requirements

**The receipt page (Lane A):**
- shows question, article, answer, and model with no interaction;
- states the proof and the floor in one line each, in plain words;
- labels the green state as the server's own claim and links the one-command
  independent check, so it never reads as proof on its own;
- renders a refusal (`stop_reason: refusal`, no content blocks) as "the model
  declined to answer," never a blank verdict;
- carries the raw quote and the leaves in a form an agent can pull without
  scraping rendered HTML.

**The agent path (Lane B):**
- verifies the TDX quote with no external service dependency (stdlib P-256 in
  `p256.py`);
- diffs `mrtd`/`rtmr0-3` against `/_api/verification/attest-proxy` and reports
  drift instead of hiding it;
- checks the Merkle root against the question/answer commitment and rejects
  spliced or reordered leaves (the dense-index check already added);
- carries the caveats into its verdict, and states the source/compose hash as
  pinned-or-not;
- **open:** verify the PCK/TCB chain to Intel's root so "genuine Intel silicon"
  moves from asserted to checked.

**Both:** the model name comes from the provider's response, never from sender
input.

## Non-goals

- Proving the answer is correct.
- Proving a refusal happened *for a good reason*, or that it's interesting. A
  refusal is an outcome the receipt records faithfully.
- Metering, billing, token accounting.

## Open questions

1. Lane B has to work for a friend with no setup. A `/verify <url>` slash
   command in the skill, a standalone `verify.py <url>`, or a documented prompt
   they paste to their agent? Cheapest that works wins.
2. ~~One receipt or two.~~ **Decided: two.** GLM assesses the claim in context;
   Fable backs the load-bearing fact. Both attested, both questions visible.
