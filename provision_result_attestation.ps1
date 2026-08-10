[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OwnerRepository,
    [Parameter(Mandatory=$true)][string]$WorkflowName,
    [Parameter(Mandatory=$true)][string]$ProtectedRef,
    [Parameter(Mandatory=$true)][ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')][string]$WorkflowSha,
    [Parameter(Mandatory=$true)][string]$CertificateIdentity,
    [Parameter(Mandatory=$true)][string]$CosignPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$here = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output -eq $here -or $output.StartsWith($here + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be outside the candidate directory'
}
if (Test-Path -LiteralPath $output) {
    throw 'Refusing to overwrite an existing provisioning directory'
}
$cosign = (Resolve-Path -LiteralPath $CosignPath).Path
if (-not ($CertificateIdentity -match '^https://github\.com/.+/.+/\.github/workflows/.+@refs/heads/.+$')) {
    throw 'CertificateIdentity must be one exact GitHub workflow identity URI'
}
if (-not ($OwnerRepository -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')) {
    throw 'OwnerRepository must be OWNER/REPOSITORY'
}
if (-not ($ProtectedRef -match '^refs/heads/.+$')) {
    throw 'ProtectedRef must be an exact protected branch ref'
}
$identityPrefix = 'https://github.com/' + $OwnerRepository + '/.github/workflows/'
if (-not $CertificateIdentity.StartsWith($identityPrefix, [StringComparison]::Ordinal) -or
    -not $CertificateIdentity.EndsWith('@' + $ProtectedRef, [StringComparison]::Ordinal)) {
    throw 'CertificateIdentity must bind the same repository and protected ref'
}

New-Item -ItemType Directory -Path $output | Out-Null
try {
    $policy = [ordered]@{
        candidate_generation = 'v35'
        certificate_identity = $CertificateIdentity
        cosign_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $cosign).Hash.ToLowerInvariant()
        github_workflow_name = $WorkflowName
        github_workflow_ref = $ProtectedRef
        github_workflow_repository = $OwnerRepository
        github_workflow_sha = $WorkflowSha
        github_workflow_trigger = 'workflow_dispatch'
        initiative_id = 'PGK-FAILCLOSED-001'
        oidc_issuer = 'https://token.actions.githubusercontent.com'
        predicate_type = 'https://xywy.example/attestation/pgk-result/v1'
        rekor_url = 'https://rekor.sigstore.dev'
        schema_version = 1
    }
    # ConvertTo-Json preserves insertion order; keys above are ordinal sorted,
    # matching the verifier's canonical JSON representation.
    $json = ($policy | ConvertTo-Json -Compress) + "`n"
    $policyPath = Join-Path $output 'result-attestation-policy.json'
    [IO.File]::WriteAllText($policyPath, $json, [Text.UTF8Encoding]::new($false))
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $policyPath).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $output 'TRUSTED_POLICY_SHA256.txt'),
        $digest + "`n", [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath (Join-Path $here 'github-attest-result.template.yml') `
        -Destination (Join-Path $output 'github-attest-result.template.yml')
    $handoff = [ordered]@{
        official_pass = $false
        promotion_allowed = $false
        external_operator_action_required = $true
        policy_sha256 = $digest
        next_action = 'Publish policy outside builder control, provision immutable record transport, run external OIDC workflow, then regenerate verifier with the frozen digest.'
    }
    [IO.File]::WriteAllText((Join-Path $output 'handoff.json'),
        (($handoff | ConvertTo-Json) + "`n"), [Text.UTF8Encoding]::new($false))
    Write-Output $digest
} catch {
    Remove-Item -LiteralPath $output -Recurse -Force
    throw
}
