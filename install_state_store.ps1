param([switch]$Install)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path + '\authoritative-state\pgk-v8'
if ($Install) {
  New-Item -ItemType Directory -Force -Path $Root | Out-Null
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls $Root /inheritance:r /grant:r "${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }
  $marker = [ordered]@{schema_version=1;authority='PGK-V8';absolute_root=$Root.Replace('\','/')} | ConvertTo-Json -Compress
  [IO.File]::WriteAllText((Join-Path $Root '.pgk-authority-v8.json'), $marker + "`n", [Text.UTF8Encoding]::new($false))
}
$item = Get-Item -LiteralPath $Root -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'state root is a reparse point' }
$acl = Get-Acl -LiteralPath $Root
$risky = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
foreach ($ace in $acl.Access) {
  $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  if ($sid -in $risky -and ($ace.FileSystemRights.ToString() -match 'FullControl|Modify|Write')) { throw "broad principal is writable: $sid" }
}
$markerPath = Join-Path $Root '.pgk-authority-v8.json'
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'authority marker missing' }
[ordered]@{status='PREFLIGHT_OK';root=$Root;owner=$acl.Owner;reparse=$false;marker_sha256=(Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
