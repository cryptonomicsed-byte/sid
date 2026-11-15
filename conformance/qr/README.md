# `helix-qr/1` conformance

`vectors.json` holds 111 self-contained cases (subject, trust anchors, clock, expected verdict) for
[`spec/helix-qr-1.md`](../../spec/helix-qr-1.md). `generate.py` produces them (deterministic; test keys only, never
trust them); every expectation in it is written by hand, not copied from an implementation's output.

| kind | what it runs | Python | TypeScript | Go (gateway resolver) |
|---|---|---|---|---|
| `reference` (59) | verify a scanned URL | all | all | all but 2 (bare document, BIP-340 issuer) |
| `resolution-envelope` (24) | who signed it, which reference, from where, how fresh, what status | all | all | all |
| `resolution` (28) | the certificate, runtime, typed endpoints, pins | all | all | none, by design: a resolver is untrusted for content and does not verify sid certificates |

```
python3 conformance/qr/generate.py        # regenerate
python3 conformance/run_vectors_qr.py     # Python reference
(cd implementations/typescript && npm test)   # TypeScript, with the sid/0.2 suite
# Go: agent-os/gateway/internal/qr (vendors vectors.json, hash-pinned)
```
