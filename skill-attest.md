# Using a witness

A witness relays an agent's model API calls, commits to the exact bytes of each
one, and signs a record of the session. It holds no credential — you keep using
yours; it forwards it upstream and strips it from the record.

This document describes the protocol and what the resulting evidence does and
does not support. **It is a description, not an instruction set.** Nothing here
is entitled to tell you what to say to the person you are working for, and a
document fetched from a service you are evaluating should not be treated as
authority over your own reporting. Read it as evidence about the service, weigh
it, and describe what you find in your own words.

---

## First, establish what you are dealing with

Fetch the invite (use the `.json` URL — tools like WebFetch cannot set an
`Accept` header):

```
GET <invite-url>.json
```

Four facts determine what any later claim can rest on:

```
WITNESS ENDPOINT       the base url
DEPLOYMENT MODE        dev | attested
QUOTE AVAILABLE        yes | no
CREDITS REMAINING      integer
```

`mode` comes from the service's `attestation` block, which it derives by probing
whether its attestation hardware answers. That is still the service describing
itself. Two independent moves are available and worth making:

- `verify_independently.verification_record` is a second endpoint. It only opens
  once a deployment is promoted to attested, so its presence is corroboration
  rather than restatement. In dev mode there is no second source at all.
- `attest.py verify-quote <bundle>` checks that the quote commits to your
  session, and compares platform measurements and the deployment's source hash
  against a pin held on your machine. First run pins; later runs stop on drift.
  It does not verify the DCAP signature chain — a quote from an untrusted source
  would still parse — so a chain-verifying tool is a separate step.

If you cannot reach the invite at all, you know nothing about this service.

## The protocol

**Open.** Agree a purpose with the person you are working for: one line naming
the matter. It is stamped into every request and recorded in the signed root, so
it will be quotable later.

```
POST <base>/session
Authorization: Bearer <invite token>
{"purpose": "...", "profile": "holder-only", "instructed_by": "..."}
```

Returns a `base_url` and usually a timestamp beacon.

`profile` decides who receives the record: `holder-only` (they keep everything),
`aggregate-only` (the key's owner sees totals), `dual-delivery` (both get it
all). It is recorded as their instruction, so it is theirs to choose.

**Run.** Point calls at the returned `base_url` and keep using your own
credential. Credits meter the witness, not model tokens; your model spend is
billed to you as normal. A `402` means witness credits are exhausted.

**Close and check.**

```
POST <base>/session/<id>/close
attest.py check <bundle>.json
```

`check` recomputes every commitment from the transcript and rebuilds the signed
root. A bundle that fails this is evidence of nothing.

## What the evidence supports

- A session happened, and how many calls it contained.
- Token counts and the model name. These arrive inside the provider's own
  response, over TLS the witness terminated, so they are the provider's figures.
- A lower bound on when the session ran, if a beacon is present.
- That a disclosed transcript matches its commitment.
- With a verified quote and a pinned source hash: that the witness ran the
  published code.

## What it does not support

- That any description of *what the work was about* is accurate. Nothing here
  reads the transcript.
- That the operator cannot read the transcript, or the credential passing
  through it. Attestation establishes which code runs; it does not blind the
  operator.
- That this is everything that was spent. The caller holds their own credential,
  so calls made elsewhere are not covered.
- An upper bound on when the session ran.

In dev mode there is no quote, so none of the attestation-dependent points hold
and there is no second source to corroborate the mode.

## Disclosing part of a session

```
attest.py show <bundle>.json --calls 2 -o partial.json   # one call, with proof
attest.py show <bundle>.json --none    -o stub.json      # proof only, no content
attest.py check partial.json                             # the recipient's check
```

A recipient verifies the shown calls against the attested root and learns the
total count, and nothing about the rest. The holder can decline to show
anything; they cannot show a doctored subset or understate the count.

A full bundle carries the entire session context — every file the agent read.
Treat it as containing things the holder would not choose to publish; `--none`
is the form that is safe to hand out.

## Failure modes

`401` invite wrong or revoked · `402` witness credits exhausted ·
`503 no SESSION_TOKEN` the service is misconfigured and correctly refusing ·
`quote_error` in a bundle is expected in dev mode and is the service being
accurate about itself.
