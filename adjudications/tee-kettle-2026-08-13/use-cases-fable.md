# attest-proxy use cases — surfaced by Fable subagent (2026-08-13)

Framework applied: prodmgmt.world "Generate comprehensive use cases from user
input for product strategy." Input: the attest-proxy mechanism + the TEE Kettle
/ domas / SEV-SNP trigger + the Fable-refusal finding.

## 1. Citing an LLM in an argument with people who don't trust you
- **Problem** — posted an LLM answer into a channel of experts who will assume it
  was led, cherry-picked, or fabricated; "an AI agreed with me" and a screenshot
  both prove nothing.
- **Persona** — researcher/senior engineer in an adversarial expert forum
  (security Matrix/Slack, crypto Twitter, standards list); high reputation
  stakes; audience can check a hash themselves.
- **Alternatives** — screenshots (hide the prompt), full transcript (unverifiable,
  editable, could be best-of-50), provider share links (rot, editable via
  regeneration), "run it yourself" (reader gets a different sample).
- **Frequency** — per-dispute; a few times a month for someone active, spiking on
  any big disclosure.
- **Why** — the receipt makes the *question* as inspectable as the answer; shifts
  the burden from "trust me" to "check it."
- **Consideration** — minutes; used impulsively mid-thread; must beat typing the
  rebuttal by hand.

## 2. Cherry-pick-proof claims about model behavior
- **Problem** — claiming "model X refuses / gets wrong / says damning thing Y,"
  where everyone knows such claims are the best of 30 doctored tries.
- **Persona** — AI evaluator, red-teamer, journalist, policy researcher
  publishing "model X said Y" as the claim itself.
- **Alternatives** — faked/distrusted screenshots, prompt-publishing (samples
  differ, models update), provider share links (no proof of preceding context).
- **Frequency** — weekly for professionals; per-publication otherwise.
- **Why** — binds exact input bytes, model name as provider reported it, and time.
  The domas finding: a sealed refusal is itself a publishable result, and
  side-by-side receipts (frontier refuses / GLM answers) are a provider-behavior
  claim in their own right.
- **Consideration** — days to weeks; they'll test whether the format survives
  their audience before staking a publication on it.

## 3. LLM as agreed referee between two parties
- **Problem** — two parties agree to let a model settle a bet/bounty/spec dispute,
  but whoever runs the query can rig it, so the loser rejects the result.
- **Persona** — mutually distrusting counterparties with a small-stakes,
  judgment-shaped dispute: bounty poster vs hunter, prediction-market resolution,
  DAO milestone review, colleague side bets.
- **Alternatives** — human arbiter (slow, opinionated), both run it separately and
  argue, "watch one screen" (doesn't scale or archive).
- **Frequency** — per-dispute; daily for a platform.
- **Why** — both pre-agree on instruction text + document hash *before* the run,
  then verify the receipt matches; operator can't inject, retry, or swap models
  without the check failing; drand fixes it ran after the agreement.
- **Consideration** — weeks-months for a platform; one conversation for an ad-hoc
  bet. Honesty constraint: it notarizes the run, not the quality of the judgment —
  parties must accept sampling variance or adopt a one-run convention.

## 4. Audit trail for LLM-in-the-loop decisions
- **Problem** — used a model to screen/triage/flag; months later the decision is
  disputed; need to show exactly what the model was asked and told, not
  reconstruct from self-controlled logs.
- **Persona** — team lead / compliance owner running LLM screening with appeal
  rights (moderation, claims triage, resume screening, abuse reports).
- **Alternatives** — internal logging (self-attested), provider logs (need
  cooperation, don't prove context completeness), "trust us."
- **Frequency** — continuous (a receipt per decision); disputes that consume one,
  monthly.
- **Why** — hash-only mode shares a decision receipt with an appellant without
  disclosing the document publicly. Caveat shaping adoption: operator sees
  documents in the clear, so the company must run its own enclave — which the
  design permits.
- **Consideration** — months; procurement/legal, not impulse.

## 5. Timestamped record of what a model knew or said at a moment
- **Problem** — prove an answer existed at a date — model said X before event Y,
  or a result was established before someone else published.
- **Persona** — researcher establishing priority; plagiarism/contamination
  disputes; freezing a model's position before a model update or policy change.
- **Alternatives** — notarized screenshots, Wayback (no chat sessions), tweeting a
  hash (proves you had *something*, not what produced it).
- **Frequency** — monthly at most; rare but high-value.
- **Why** — drand round + TDX quote binds model, exact input, exact output, and
  time in one artifact; the only alternative binding all four is a human notary
  watching you type.
- **Consideration** — immediate when the need hits; unpredictable, so being
  already-installed matters more than persuasion.

## 6. Provenance disclosure for AI-assisted published work
- **Problem** — published an AI-produced summary/translation/analysis; want readers
  to see it came from exactly this source with exactly this instruction, no spin
  hidden in the prompt.
- **Persona** — newsletter writer, transcript summarizer, OSS maintainer
  publishing AI changelogs/triage where readers suspect a smuggled prompt.
- **Alternatives** — publishing the prompt (unverifiable it was the real one),
  methodology footnotes, no disclosure.
- **Frequency** — per-publication.
- **Why** — upgrades a disclosure norm from courtesy claim to checkable fact at
  near-zero marginal cost, on the author's own subscription.
- **Consideration** — days; a standing habit after one trial, or not at all.

## Where the domas example lands
Use case **1** (citing an LLM to a distrusting expert audience), with the refusal
pulling in a slice of use case **2**: the honest artifact for a dual-use security
question is *two* receipts — the frontier model's sealed refusal next to GLM's
sealed answer — which is itself a checkable claim about provider behavior, not
just about AMD.

**Core use case, one sentence:** this turns "an AI agreed with me" from a claim
about your honesty into evidence anyone can check — it proves you asked a fair,
complete, one-shot question of a named model and posted exactly what came back,
refusal included.
