# verify

Three implementations of the same constructions must agree byte for byte, or a
bundle produced by one attester will not verify against another's verifier.

| implementation | where | checked by |
|---|---|---|
| TypeScript | `witness.ts` | `check.py --diff`, in CI |
| Python | `attest.py`, `check.py` | `check.py`, in CI |
| C, on-chip | `edge-tee/silabs-secure-vault/zktls/fw/app_process.c` | `diff_firmware.py`, needs the board |

## In CI

```bash
python3 verify/check.py --diff
```

Decides five structural properties over **every** reachable case — 1..256 leaves
by every leaf index, 32,896 pairs — rather than sampling: round-trip, soundness
against a forged commitment, proof-length bound with trailing siblings refused,
count binding, and leaf/node domain separation. Then runs the TypeScript on the
same inputs and requires identical output.

Assumed and not shown: SHA-256. Out of scope: the TEE, the quote's signature
chain, TLS, and whether the operator can read plaintext.

## Before flashing firmware

Not a CI job — it needs the board attached, and each tree size costs a session of
that many live calls.

```bash
# on the board host
python3 host/diff_firmware.py
```

Sweeps tree sizes that straddle the RFC 6962 split (1,2,3,4,5,7,8,9,15,16,17),
which is where a recursive implementation goes wrong. Run it after any
`fw/build.sh`, before trusting a new image — otherwise the C side can drift from
the other two silently, and the failure mode is a bundle that verifies for the
holder and not for the counterparty.
