# attest-proxy — Checker Step

## 1. User Journey

The checker is a member of a 399-person expert TEE channel. The producer just posted a model's answer to a contested question ("does the domas AMD exploit affect SEV-SNP?") plus a pod URL. The checker knows exactly how this could be faked, because faking it is their field. The journey is theirs, though most of the mechanical work is done by their AI agent.

### State 1: Skepticism. "He rigged this."

**Feeling:** This channel exists because these people don't take claims on faith. The default read is: he asked a leading question, or cherry-picked one answer out of twenty, or wrote the "receipt" by hand. An LLM answer pasted into chat is a screenshot with extra steps.

**What they do:** Click the URL, or more likely paste it to their agent with "is this real?"

**What the product must show:** Within the first screenful: the exact question that was asked, the answer, the model name as the provider reported it, and a single line saying how to check all of it yourself — the receipt file, the tool, the two commands. No pitch, no adjectives. A skeptic who sees marketing before mechanism closes the tab with their prior confirmed.

### State 2: Willing to check, unwilling to work. "I'm not spending an hour on this."

**Feeling:** They'd verify it if verifying costs five minutes. If the path is "read our docs, understand our format, write a script," they won't do it — and an unverified receipt is worth nothing to them, so they revert to State 1.

**What they do:** Hand the URL to their agent (Claude Code or similar) and go back to what they were doing.

**What the product must show:** A machine-readable twin of the page (same URL with `.json`) that the agent can fetch without special headers, containing the receipt link and the exact steps as commands: clone `github.com/amiller/attest-proxy`, run `python3 attest.py check <receipt>`, run `python3 attest.py verify-quote <receipt>`. The agent should never have to guess. Every point where it would have to guess is a point where the checker gives up.

### State 3: Fear of a forgery. "A JSON file proves nothing."

**Feeling:** They can write JSON too. Two specific fears: the receipt was edited after the fact, and the hardware quote — even if real — was lifted from some other session and stapled onto this answer.

**What they do (via their agent):** Run `check`, which recomputes every commitment: each part of the prompt is itemized by size and hash, the parts sum to the whole, and the question, document hash, model name, and answer all bind together. Change one byte anywhere and it fails. Then run `verify-quote`, which verifies the TDX quote's own signature, confirms the quote's report_data binds this specific session (so a quote can't be spliced in from elsewhere), and diffs the platform measurements (mrtd, rtmr0–3) against the measurements the pod publishes at `pod.dstack.soc1024.com/_api/verification/attest-proxy`.

**What the product must show:** Tool output that says in plain words what each passing step just ruled out — "the receipt was not edited," "this quote belongs to this session, not another one," "the code that ran is the code that was published." A wall of hashes with no interpretation leaves the checker unsure whether they verified anything, which feels the same as not verifying.

### State 4: Fear of a rigged question. "The crypto holds. Was the question fair?"

**Feeling:** This is the fear no tool can discharge. A perfectly attested answer to "explain why SEV-SNP is unaffected" would be a perfectly attested con.

**What they do:** Read the actual question text with their own eyes and judge it.

**What the product must show:** The full instruction text, verbatim, plus the fixed framing line and the byte itemization proving those parts — and nothing else — were the entire context. The product's job here is to guarantee that the text the checker is judging is the text the model saw. The judging itself stays with the checker; the product must not editorialize about its own question.

### State 5: Confidence — bounded, and safe to repeat in public. "I checked it myself."

**Feeling:** Convinced, but wary of one last trap: repeating the claim in the channel and getting corrected by someone sharper. "You said it's proven? The Intel root chain isn't even checked." In this crowd, overclaiming once costs more than never checking at all.

**What they do:** Report back to the channel what they verified.

**What the product must show:** The caveats, stated plainly at the entry point, so the checker's summary is already correctly bounded:

- The quote proves the code is unaltered, but the chain to Intel's root (PCK/TCB) is not yet checked — genuine-silicon is not yet proven.
- The live pod self-reports a published-but-not-latest commit; the tool reports this drift rather than hiding it, and the measurements still match.
- The operator can read the document in the clear.
- The receipt proves what was asked and what was answered — not that the answer is correct.
- It does not prove the producer only asked once.

The checker leaves saying "I verified the question, the answer, the model, and that nothing else was in the prompt — here's what that does and doesn't cover." That sentence, said by a skeptic in the channel, is the product working.

---

## 2. PRD: Checker Step

### Problem

The producer step works: real receipts exist, and one is about to be posted into a channel of 399 TEE experts who will assume it was rigged. Without a checker path, the receipt is "trust me" with extra JSON. The value of the entire system is realized only at the moment a skeptic validates a receipt independently — and today there is no entry point that takes them from URL to verdict.

### Who the checker is

A technically expert skeptic who will not read docs or trust the producer, paired with their AI agent (e.g. Claude Code), which does the fetching, cloning, and running. The agent executes the checks; the human reads the question and judges the substance. Design for the agent's constraints: it fetches URLs (it cannot set an Accept header), runs shell commands, and follows explicit written steps.

### The job

From one URL, with no other context, move a skeptic from "he could have faked this" to "I checked it myself — and I know precisely what remains unproven."

### Requirements

**P0**

1. **Entry-point URL with two faces.** A human-readable HTML view and an agent-fetchable `.json` twin at a linked, predictable path. Same content, two forms; the twin exists because agent web-fetch tools cannot negotiate content types.
2. **The `.json` twin spells out the validation steps exactly**: link to the receipt JSON, the clone URL (`github.com/amiller/attest-proxy`), and the literal commands (`python3 attest.py check <receipt>`, `python3 attest.py verify-quote <receipt>`). An agent following it verbatim must succeed with zero inference.
3. **The HTML view leads with the claim, verbatim**: question text, answer, model name as the provider reported it, document fingerprint, drand round. Verification instructions directly below.
4. **`attest.py check`** recomputes all Merkle commitments: per-part size+hash itemization summing to the whole prompt, binding question, document hash, model name, and answer. Any edited byte fails loudly.
5. **`attest.py verify-quote`** verifies the TDX quote signature, confirms report_data binds this session (closes splicing), and diffs mrtd/rtmr0–3 against the pod's published measurements at `pod.dstack.soc1024.com/_api/verification/attest-proxy`. Source drift between the pod's self-reported commit and latest is reported, never suppressed.
6. **Honest caveats surfaced, not buried**, in both HTML and `.json`: (a) PCK/TCB chain to Intel's root not yet checked, so genuine-silicon is unproven; (b) pod runs a published-but-not-latest commit; (c) operator can read the document; (d) receipt proves question and answer, not correctness; (e) no proof the producer asked only once.
7. **Tool output in plain language**: each passing check states what it just ruled out, not just a hash comparison.

**P1**

1. PCK/TCB chain verification to Intel's root, retiring caveat (a).
2. A machine-readable summary verdict from the tool (pass/fail per check plus the caveat list) so an agent can report without parsing prose.
3. Withheld-document flow: when only the hash is published, the entry point explains what the fingerprint does and doesn't let the checker confirm.

### Non-goals

- Does not referee: it makes question and answer inspectable, it does not judge either.
- Does not prove the answer is correct.
- Does not prove the producer asked only once.
- Not private from the operator.

### Success / dogfood criterion

A fresh agent given only the entry-point URL — no repo access, no chat context, no coaching — fetches the receipt, obtains and runs the tool, and produces a report that correctly states both what it confirmed (prompt bytes, binding, model identity, session-bound quote, matching measurements) and the residual caveats. If the agent overclaims or gets stuck, the entry point failed.

### The checker step in one sentence

The checker step is one URL that lets a skeptic's own agent replace trust in the producer with checks it ran itself.
