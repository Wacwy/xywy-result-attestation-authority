# PGK-FAILCLOSED-001 v35 authority-observed result-attestation candidate

v35 repairs v33's decisive constructor defect: the exact reviewed workflow no
longer terminates in an unconditional `UNPROVISIONED` exception. Its reviewed
connector invokes `run_external.py` with a closed, digest-pinned deployment
bundle. The runner itself verifies threshold authorization, consumes the nonce,
advances both checkpoint services, executes a verified snapshot, and constructs
`external-run.json` only from bytes it directly observed. The workflow validates
the complete record before attesting it.

Acceptance requires all of the following:

1. canonical `PGKv35AuthorityObservedExternalRun` bytes;
2. strict authorization, nonce receipt, monotonic checkpoint and distinct-service semantics;
3. exact stdout, stderr, result artifact, snapshot map and entrypoint bytes;
4. policy-pinned Cosign verification of exact GitHub OIDC workflow/ref/commit;
5. Rekor transparency verification and a two-authority roster published by an externally pinned 1-of-1 TUF custodian.

v35 gives the two manifest representations distinct, closed identities instead
of overloading one field. `manifest_sha256` and
`bindings.candidate_manifest_sha256` are the externally pinned canonical
`SHA256SUMS.txt` byte digest used by the custodian authorization and nonce
ledger. `execution_manifest_sha256` is the canonical
`execution-manifest.json` byte digest used to transport the exact file map.
The authority-owned runner recomputes both from observed bytes, requires the
maps to be identical, and the verifier checks both digests independently.

`github-attest-result.template.yml` fetches one digest-pinned input archive with
two fixed children: `candidate/` and `deployment/`. It invokes the reviewed
connector and never signs a pre-existing operator-selected record. Third-party
Actions are commit-pinned. The connector is executable now; the trust-root and
service constants in `run_external.py` deliberately remain `UNPROVISIONED_*`
until real independent operators freeze them. No local fallback exists.

`attestation_record.py` rejects recomputed but invalid manifests, null authorization, rollback/equal checkpoints, empty/same-custodian services, malformed receipts and failed execution. `promotion_gate.py` is the sole promotion entrypoint and requires Sigstore plus the matching TUF roster.
`tuf_roster.py` additionally verifies digest-pinned canonical TUF root **and
targets** metadata with exact 1-of-1 Ed25519 root/targets roles and live
expirations, then validates
the exact roster target containing two distinct result authorities. The TUF
publication custodian is not the result-authorization threshold.
It does not generate keys or signatures. `tuf-root.template.json` and
`authority-roster.template.json` are non-authoritative hand-off templates.

## Required external provisioning

A fresh independently reviewed verifier generation must replace
`TRUSTED_RESULT_ATTESTATION_POLICY_SHA256` with the SHA-256 of a canonical,
externally published policy. The exact repository/workflow/ref/commit policy
and Cosign binary digest must already be frozen. Then an external GitHub
Actions OIDC run can publish the signed Sigstore bundle to Rekor.

Example verification after provisioning:

```powershell
python .\result_attestation.py `
  --record X:\immutable\external-run.json `
  --evidence-dir X:\immutable\evidence `
  --manifest X:\immutable\execution-manifest.json `
  --bundle X:\immutable\external-run.sigstore.json `
  --policy X:\immutable\result-attestation-policy.json `
  --cosign E:\XYWY\.tools\bin\cosign.exe
```

The policy, record, evidence, bundle and Cosign binary must all resolve outside
this candidate directory. An unauthenticated recomputed success record, even
with internally consistent hashes, is therefore insufficient.

## Operator order

1. One designated publication custodian generates and retains one Ed25519 TUF key and
   publishes only its public key.
2. That custodian reviews the two-authority roster, creates `targets.json`, and signs the canonical
   root and targets `signed` objects. Publish root/targets/roster to storage the
   builder cannot rewrite; independently anchor both metadata digests and their
   generation. A monotonic external clock/anchor remains mandatory because a
   desktop clock controlled by the builder cannot establish durable freshness.
3. Protect the GitHub environment with non-builder reviewers. Freeze its record
   URL/digest variables, protected branch and exact workflow commit.
4. Run the OIDC workflow, retrieve the record and Sigstore bundle by immutable
   artifact/run identity, publish the canonical result policy externally, and
   regenerate the verifier with the exact policy and TUF root digests.
5. A fresh hostile reviewer executes whole-root replacement, missing-signature,
   rollback, split-view, replay, concurrency and crash/recovery controls.

This requested 1-of-1 TUF publication policy is an explicit security downgrade:
compromise or loss of the sole publication key can replace or halt roster
publication. It does not reduce the separately enforced 2-of-2 result
authorization or the two checkpoint-service identities. The checked-in
positive TUF test is only a cryptographic fixture.

## Remaining fail-closed state

The single TUF publication custodian, two result authorities, two checkpoint services, nonce ledger and
monotonic anchor remain `UNPROVISIONED_*`. The same Windows administrator
cannot legitimately instantiate the independent checkpoint services. Consequently
this candidate is **not a PASS**, does not authorize promotion, and does not
claim to unblock `WP-GOV-001`. It provides a reviewable implementation and
operator hand-off for one blocker without fabricating external independence.
