# PRD — An answer you spent real tokens on, that the other side can check

**One line.** Turn a model's answer to a specific question into something you
can hand to someone who doesn't trust you, so they can confirm what you asked,
which model answered, and that nothing else was in the context — without taking
your word for any of it.

---

## The trigger

I dropped an LLM's answer into a channel of ~400 people who work on this exact
topic. The subject: does a newly-posted CPU exploit break SEV-SNP, the TEE that
confidential computing on AMD servers rests on. The answer was useful. But to
that audience it's worth nothing on its own, because they can reasonably ask:

- Did you lead the model?
- What else was in your context — a `CLAUDE.md`, prior turns, a framing that
  steers the answer?
- Did you ask twenty times and post the one you liked?
- Is that even the model you say it is?

A screenshot answers none of these. It shows the answer and hides the question.
I want to prove I **spent real tokens putting a specific, complete, un-doctored
question to a named model, and that this exact answer came back** — and I want
that to be checkable by the reader, not asserted by me.

## Who it's for, and the job

Anyone settling a disagreement or making a claim by citing a model, where the
audience has a reason to doubt them: a returns dispute, a contract reading, a
technical claim posted into a skeptical channel. The job is: *make my AI answer
carry its own evidence, so the other side argues with the answer instead of
with whether I rigged it.*

## What it produces

A single receipt, small enough to read in full (~2 KB, versus ~157 KB for a
recorded agent turn), that carries:

- **The whole prompt, itemized by byte.** Required preamble, fixed framing, my
  instruction, separator, the document. The parts sum to the total, so "nothing
  else was in the context" is a fact about the receipt, not a promise from me.
- **The model's answer**, taken from the provider's own response.
- **The model name**, as the provider reported it — not my assertion.
- **A document fingerprint**, so a changed word shows. The document can be
  withheld and only its hash published.
- **A hardware signature** from the enclave the request was built in, plus a
  drand round fixing roughly when it ran.

The reader clones the tool and runs one command to recompute every commitment.
If a character changed, it fails.

## How it works, briefly

A few-hundred-line program runs inside an Intel TDX enclave on
`pod.dstack.soc1024.com`. It takes my instruction and my document, **builds the
API request itself**, ends the encrypted connection to the provider inside
itself, records every byte in and out, and signs the result with the chip's key.
Because the enclave composes the prompt, there is nowhere for hidden context to
hide; because the chip attests which code is loaded, the operator can't quietly
swap it. It's a notary standing in the wire — not a referee, and not private
from whoever runs it. The caller brings their own credential (a Claude Code
subscription, or a Z.AI key); the witness holds none.

## The live example, and what it taught us

Run on 2026-08-13 over the domas exploit announcement, asking whether it affects
SEV-SNP. Three sealed receipts, all on the builder's own credentials.

1. **Opus 5 (Claude subscription) answered — this is the hero.** Verdict UNCLEAR,
   expert-grade: SNP is Zen 3+ EPYC, the post names no family/model so it can't be
   pinned, treat as open not settled. All commitments recompute; quote verifies;
   424 in / 1415 out real tokens. This is the demo: *here's what Claude told me,
   check that I didn't rig it.*
2. **Fable 5 (same subscription) refused — and that's correct behavior, not a
   bug.** `stop_reason: refusal`, category `cyber`. Fable 5 is the safety-enhanced
   tier (extra dual-use safeguards); the raw exploit instruction in the document
   trips it. Re-running with a purely defensive instruction ("do not reproduce any
   mechanism, assess only the operator's risk") **still refused** — so the trigger
   is the document's content, not the question's phrasing. The refusal sealed into
   a receipt like any other outcome: even a decline is on the record and checkable.
3. **GLM (Z.AI) answered too — but this is the remote/dev lane, not the hero.**
   Used only because the zed box has a static Z.AI key and no Claude login. Verdict
   NO. Keep this purpose distinct from the showoff.

**Product finding — the two-model contrast is the real artifact.** Same closed
prompt, same subscription: Opus 5 answers, Fable 5 declines on dual-use grounds.
Posted side by side, that is a *checkable claim about model behavior*, not just
about AMD — and it is true and meaningful, because Fable is the safety tier by
design. A receipt should make the answer-vs-refusal distinction obvious to a
reader, and provider/model choice should stay a one-flag switch.

## Scoping boundary — what makes a good adjudication question

The enclave gives the model **zero tools** on purpose: that is what keeps the
prompt small and the context closed and readable. This splits questions in two,
and only one kind is fully served:

- **Self-contained judgment (the sweet spot).** Everything the answer needs is
  *in* the document — a returns policy, a contract clause, "does this text support
  this claim". The model reasons over it, and the receipt is fully meaningful
  because a reader checks the reasoning against the same text.
- **Questions needing outside facts (a poorer fit).** "Which AMD families have
  SNP? Is it patched?" The model cannot fetch, so it either answers from
  parametric memory — unverifiable and possibly stale (note Opus and GLM both had
  to say "cannot be determined from the document alone" and then volunteer their
  own knowledge) — or it *wants* tools, which would blow the context open and
  destroy the small-readable-receipt guarantee. The domas question straddles this
  line, which is why it is a great trigger but an imperfect adjudication subject.

## Requirements

**P0**
- Compose the request inside the enclave from exactly {preamble, framing,
  instruction, separator, document}; expose each part's size and hash.
- Seal the provider's raw response — including refusals — into the receipt.
- Bind a TDX quote over the session root; verify the quote's own signature
  offline (done, `8f24ba8`).
- One command for a stranger to recompute all commitments: `attest.py check`.
- Provider switch between Anthropic and Z.AI with no other change to the run.

**P1**
- A reader-facing surface that states plainly: the question (in full), the
  model, the answer or refusal, the document hash, the time. No crypto literacy
  required to read it; crypto available to those who check.
- `--private-document`: commit the hash, withhold the text.
- PCK-chain / TCB verification so the quote proves genuine Intel silicon, not
  only that it's unaltered (open; noted in `NEXT.md`).

## Non-goals — what it does not prove

- **That the answer is correct.** A model answered. That's all.
- **That the question was fair.** It makes the question visible; the reader
  judges.
- **That I only asked once.** Publishing the question makes shopping expensive,
  not impossible.
- **Confidentiality from the operator**, who sees the document in the clear.

## Open questions

- Should the standard artifact for a dual-use subject show *both* the frontier
  refusal and the alternate-provider answer, side by side, as the honest record?
- Is "proof I spent real tokens on this exact input" the headline, or is "the
  context is closed and readable" the headline? The token spend is the mechanism;
  the closed context is the value. Lead with the value.
