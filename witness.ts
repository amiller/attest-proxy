// The constructions a verifier has to agree with, byte for byte — and nothing
// else. Kept separate from the service so it can be read, reimplemented, and
// checked on its own; verify/check.py exercises every one of these exhaustively
// over the deployed leaf bound.
//
// Siblings that must produce identical output:
//   edge-tee/silabs-secure-vault/zktls/host/{frames,merkle}.py   (Python)
//   edge-tee/silabs-secure-vault/zktls/fw/app_process.c          (C, on-chip)
//   attest.py                                                     (Python client)

export const MAX_LEAVES = 256;

// --- byte helpers -----------------------------------------------------------

const enc = new TextEncoder();

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(new ArrayBuffer(n));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concat(...parts)));
}

export const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

// latin-1: one byte per code unit, so raw bytes survive a round-trip through a
// string. The Python side stores request_redacted the same way.
export const latin1 = (b: Uint8Array) => String.fromCharCode(...b);
export const unlatin1 = (s: string): Uint8Array<ArrayBuffer> =>
  concat(Uint8Array.from([...s].map((c) => c.charCodeAt(0))));

export function b64(b: Uint8Array): string {
  return btoa(latin1(b));
}

// --- commitment + RFC 6962 Merkle (must match host/frames.py and host/merkle.py)

export async function commitment(host: string, redacted: Uint8Array, response: Uint8Array) {
  return await sha256(enc.encode("zktls-v1\0"), enc.encode(host), new Uint8Array([0]),
                      redacted, new Uint8Array([0]), response);
}

export function sessionMeta(profile: string, purpose: string): Uint8Array {
  const p = enc.encode(profile);
  if (p.length > 255) throw new Error("profile too long");
  return concat(new Uint8Array([p.length]), p, enc.encode(purpose));
}

export const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array<ArrayBuffer>> {
  if (leaves.length === 0) return await sha256();
  if (leaves.length === 1) return await sha256(concat(new Uint8Array([0])), leaves[0]);
  const k = split(leaves.length);
  return await sha256(new Uint8Array([1]),
                      await merkleRoot(leaves.slice(0, k)),
                      await merkleRoot(leaves.slice(k)));
}

export async function sessionRoot(meta: Uint8Array, leaves: Uint8Array[]): Promise<Uint8Array<ArrayBuffer>> {
  const metaHash = await sha256(enc.encode("zktls-session-v2\0"), meta);
  const root = leaves.length ? await merkleRoot(leaves) : new Uint8Array(32);
  const count = new Uint8Array(new ArrayBuffer(4));
  new DataView(count.buffer).setUint32(0, leaves.length, false);
  return await sha256(enc.encode("zktls-root-v2\0"), metaHash, root, count);
}
