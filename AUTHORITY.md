# XYWY Result Attestation Authority

This repository hosts the reviewed v35 GitHub OIDC result-attestation workflow. It remains fail-closed until independently administered external authorities are provisioned. Repository setup is not an official release PASS.

## Immutable input transport

`build_immutable_inputs.py` deterministically packages a manifest-verified
candidate and, separately, a deployment bundle supplied by the independent
custodians. The workflow accepts only exact GitHub release database and asset
IDs, checks that the release is immutable and non-draft, and then checks each
archive SHA-256 before extraction. Mutable URLs and tag-only lookup are not
accepted.

Operator sequence after the real deployment bundle exists:

1. Build both archives twice and require identical SHA-256 values.
2. Enable immutable releases with
   `gh api --method PUT repos/Wacwy/xywy-result-attestation-authority/immutable-releases`.
3. Create a draft release, upload exactly
   `pgk-v35-candidate-input.tar` and `pgk-v35-deployment-input.tar`, then publish.
4. Record the immutable release ID and both asset IDs from the GitHub API.
5. Set the protected repository variables `PGK_V35_INPUT_RELEASE_TAG`,
   `PGK_V35_INPUT_ARCHIVE_ASSET_ID`, `PGK_V35_INPUT_ARCHIVE_SHA256`,
   `PGK_V35_DEPLOYMENT_ARCHIVE_ASSET_ID`, and
   `PGK_V35_DEPLOYMENT_ARCHIVE_SHA256`; dispatch with the exact release ID.

This resolves the mutable workflow-input transport mechanism but does not
manufacture independent custodians, their deployment bundle, or an external
monotonic anchor. Those remain mandatory and fail closed when absent.

