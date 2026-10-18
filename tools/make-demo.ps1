$ErrorActionPreference = 'Stop'

# Build the committed demo report from the synthetic captures in tests\fixtures.
#
# Why a demo exists: the interesting half of this tool is what a report looks
# like *after* something changed, and that state cannot be shown on a clean
# machine or described in a screenshot of one. So the demo replays the fixture
# the same way the contract test does - baseline on the capture as designed,
# then a scan on a capture where the repaired profile has been re-infected -
# which puts NEW, CHANGED, RESOLVED and PERSIST on one page at once.
#
# This never invokes a probe. No browser profile, no registry key and no file
# outside out\demo + demo\index.html is read or written, so it is safe to run on
# any Windows box and is run in CI to keep the build path honest.
#
# ASCII only: a CJK literal in a BOM-less .ps1 breaks PowerShell 5.1 parsing.
# All user-facing wording lives in render\template.html.

$root = Split-Path $PSScriptRoot -Parent
$engine = Join-Path $root 'engine.ps1'
$report = Join-Path $root 'report.ps1'
$fxBrowser = Join-Path $root 'tests\fixtures\facts-browser.json'
$fxPers = Join-Path $root 'tests\fixtures\facts-persistence.json'
$work = Join-Path $root 'out\demo'
$dst = Join-Path $root 'demo\index.html'
if ($env:WP_DEMO_OUT) { $dst = $env:WP_DEMO_OUT }

function Load([string]$p) {
    return [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8) | ConvertFrom-Json
}
function Save($obj, [string]$p) {
    [IO.File]::WriteAllText($p, ($obj | ConvertTo-Json -Depth 24), (New-Object Text.UTF8Encoding $false))
}
function Find-File($facts, $brand, $profile, $doc) {
    foreach ($f in $facts.files) {
        if ($f.brand -eq $brand -and $f.profile -eq $profile -and $f.doc -eq $doc) { return $f }
    }
    return $null
}

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null

# --- 1. baseline: the fixture exactly as committed ----------------------------
& $engine -Mode baseline -FactsFile @($fxBrowser, $fxPers) `
    -StoreDir (Join-Path $work 'store') -OutFile (Join-Path $work 'baseline.json')

# --- 2. the next scan: the profile that had stayed repaired is dirty again ----
# Edge / Profile 2 is the fixture's BR-07 subject (a repair backup whose content
# was malicious, live value clean). Re-injecting one startup URL does four things
# at once, and that is the whole point of the page: it opens BR-01 and BR-05 as
# NEW, retires BR-07 as RESOLVED, and moves BR-09 to CHANGED because its evidence
# cites the startup page alongside the engine fields.
$fb = Load $fxBrowser
$inj = Find-File $fb 'Edge' 'Profile 2' 'Secure Preferences'
if ($null -eq $inj) { throw 'fixture subject Edge / Profile 2 / Secure Preferences is missing' }
# The probe flattens session.* onto the file record, so the flat field is what a
# fixture has to rewrite; a nested session object would be ignored by the engine.
Add-Member -InputObject $inj -MemberType NoteProperty -Name 'startup_urls' `
    -Value @('http://2345.pbgia.com/win23') -Force
$next = Join-Path $work 'facts-next.json'
Save $fb $next

& $engine -Mode scan -FactsFile @($next, $fxPers) `
    -StoreDir (Join-Path $work 'store') -OutFile (Join-Path $work 'findings.json')

# --- 3. render ---------------------------------------------------------------
& $report -FindingsFile (Join-Path $work 'findings.json') -OutFile $dst -Demo

$doc = Load (Join-Path $work 'findings.json')
$states = @{}
foreach ($f in @($doc.findings)) {
    $k = [string]$f.state
    if ($states.ContainsKey($k)) { $states[$k] = $states[$k] + 1 } else { $states[$k] = 1 }
}
# Retired conclusions are not findings with state=RESOLVED: they move to their own
# list, because "this is gone" is a statement about the baseline, not about today.
$resolved = @($doc.resolved).Count
$order = @('NEW', 'CHANGED', 'PERSIST')
$parts = @()
foreach ($k in $order) { if ($states.ContainsKey($k)) { $parts += ($k + '=' + $states[$k]) } }
$parts += ('RESOLVED=' + $resolved)
Write-Output ('demo: ' + $dst + '  findings=' + @($doc.findings).Count +
    '  ' + ($parts -join ' ') + '  (' + [int]((Get-Item $dst).Length / 1024) + ' KB)')

# A sidecar of the counts only. The HTML carries a scan timestamp, so a byte diff
# of demo\index.html is meaningless; these numbers are a pure function of
# tests\fixtures + rules\*.json, which is what lets CI fail on a stale demo.
$side = [ordered]@{
    findings = @($doc.findings).Count
    states   = [ordered]@{}
    resolved = $resolved
}
foreach ($k in @('NEW', 'CHANGED', 'PERSIST', 'KNOWN', 'UNBASELINED')) {
    if ($states.ContainsKey($k)) { $side.states[$k] = $states[$k] }
}
Save $side (Join-Path (Split-Path $dst) 'build.json')

# The demo is only worth committing if it actually shows the states a clean
# machine cannot, so fail loudly rather than ship a page full of PERSIST.
if (-not $states.ContainsKey('NEW')) { throw 'demo lost its NEW rows' }
if ($resolved -lt 1) { throw 'demo lost its RESOLVED rows' }
if (-not $states.ContainsKey('CHANGED')) { throw 'demo lost its CHANGED rows' }
