# Recording what you did, for whoever asks later

You do contracted work for several sponsors. You spin up throwaway private repos
with demos and notes, and occasionally merge some of them into a deliverable
that ends up copyrighted to one of them. Months later someone asks a question
about a boundary — what was made when, and for whom.

A local log does not answer it. It is yours, it is editable, and its timestamps
come from your own machine, which is exactly the thing in dispute. You also
cannot hand the whole log over: it spans several clients' confidential work.

A recorder gives you an ordered, selectively-disclosable record of your agent
sessions, with timestamps from a public beacon rather than your clock, and each
session bound to the repo state it worked on.

## Turn it on for a directory

```bash
export ATTEST_CVM=https://pod.dstack.soc1024.com
export ATTEST_INVITE=<invite token>

attest.py enable ~/work/acme --label sponsor-acme
```

That writes `ANTHROPIC_BASE_URL` into `~/work/acme/.claude/settings.json`. From
then on every Claude Code session started in that directory routes through the
witness, with no wrapper command and nothing to remember. To stop, delete the
line.

**It is opt-in per directory on purpose.** On-by-default would route every repo
on the machine through a third-party host, including work under contracts that
forbid exactly that, and that failure is silent and only discovered afterwards.
One directory at a time, and the settings file sits in the repo where you can
see it.

## What accumulates

A session opens on the first call and seals after 30 minutes idle, so the unit
is a stretch of work rather than an arbitrary slice of clock.

```bash
attest.py sessions ~/work/acme
attest.py sessions ~/work/acme --collect ./receipts   # pull them down
```

```
recorder sponsor-acme   1 sealed, 1 open (4 leaves)
    1  252d1fb8c784b1ca…    6 leaves  drand 6370635..6370702  2026-08-12T15:54
```

Each sealed session is a receipt you can check offline:

```
subject     open  HEAD 1a78890755cb  diff e3b0c44298fc…
spanned     drand 6370635..6370702  (at least 3m21s)
usage       2906 in / 47 out / 202382 cached tokens   claude-opus-5
quote       present, and binds report_data 8078d1fb176974fa…
```

The `subject` line is what makes this attribute anything. `HEAD` is what a
sponsor recognises; the diff hash is what carries the work. Both are recorded at
open and at close, so the pair is the evidence of what moved.

The `spanned` line comes from drand rounds sampled through the session, not from
your clock. A single sample is a lower bound only and is labelled as a moment
rather than a span.

## Showing someone a fragment

Never hand over a whole receipt: it carries the entire session context,
including everything the agent read. Disclose parts.

```bash
attest.py show <receipt> --range 3:7 -o span.json   # contiguous: nothing hidden inside
attest.py show <receipt> --none     -o stub.json    # count and totals only
```

Across sessions, the same construction one level up:

```bash
attest.py index add receipts/*.json
attest.py index show --sessions 2,5 -o disclosure.json
attest.py index-check disclosure.json
```

```
ok session 2 of 40  6927a3a6d632e162…  drand 6368549..6368611  '[recorder sponsor-acme]'
index root e1f7e905… recomputes
2 of 40 sessions shown, 38 withheld but counted
```

## What it establishes, and what it does not

**Establishes:** that at least this much inference, of this named model, ran
against this repo state, no earlier than this beacon round, and that any
fragment you disclose is provably the fragment that happened.

**Does not establish** that this is *everything*. You hold your own credential,
so work done outside the witness is not covered, and nothing stops a session
being left out of an index. This is a floor by design and every claim built on
it should be phrased as one: *at least this much, on this artifact, in this
window*. That is also the shape an attribution question actually takes — nobody
needs you to prove you did nothing else.

It says nothing about whether the work was any good. Nothing reads the
transcript.

And the operator of the witness can read what passes through. For this use you
are the operator, which is the point; if you are not, know it before you enable
a directory.

## If you want the stronger claim

The edge attester holds the credential itself, so the agent has none and cannot
route around it. That is the configuration where a receipt can speak to
everything spent rather than everything routed. It costs you a board and a
serial cable. See `skill-attest.md` for choosing between them.
