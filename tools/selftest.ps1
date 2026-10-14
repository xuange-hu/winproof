$ErrorActionPreference = 'Stop'

# State machine test. The baseline diff is the product's whole claim ("what
# changed"), so it gets exercised on fabricated fixtures rather than hoped for.
# Nothing here writes outside out\selftest, and no real browser profile is read
# a second time - the fixtures are clones of an already captured facts file.

$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path $root 'out\selftest'
$engine = Join-Path $root 'engine.ps1'

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$realFacts = Join-Path $root 'out\facts-browser.json'
if (-not (Test-Path $realFacts)) { throw 'run the probe first' }
$realPers = Join-Path $root 'out\facts-persistence.json'
if (-not (Test-Path $realPers)) { throw 'run the persistence probe first' }
$store = $work

$pass = 0
$fail = 0
function Expect([string]$label, $cond) {
    if ($cond) {
        Write-Output ('  PASS | ' + $label)
        $script:pass++
    } else {
        Write-Output ('  FAIL | ' + $label)
        $script:fail++
    }
}

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
function Run-Engine($params) {
    # hashtable splatting: the keys become -Mode / -FactsFile / -StoreDir / -OutFile
    $res = & $engine @params 2>&1
    foreach ($line in @($res)) { Write-Output ('     > ' + [string]$line) }
}
function StateMap([string]$p) {
    $j = Load $p
    $m = @{}
    foreach ($f in $j.findings) { $m[[string]$f.key] = [string]$f.state }
    return @{ doc = $j; map = $m }
}

# --- fixture B: Chrome gets a hijacked startup URL back ----------------------
# Chrome/Default currently holds a repair backup whose contents were dirty, so
# BR-07 (repair held) is true for it today. Re-injecting the URL must therefore
# do two things at once: open BR-01 as NEW and retire BR-07 as RESOLVED.
$fb = Load $realFacts
$c = Find-File $fb 'Chrome' 'Default' 'Secure Preferences'
if ($null -eq $c) { throw 'fixture target missing' }
# The probe already flattened session.* onto the file record, so a fixture has
# to rewrite the flat field - editing a nested session object would be ignored.
Add-Member -InputObject $c -MemberType NoteProperty -Name 'startup_urls' `
    -Value @('http://2345.pbgia.com/win23') -Force
Save $fb (Join-Path $work 'facts-B.json')

# --- fixture C: Edge Profile 1 file gets rewritten again ---------------------
# Same findings, different evidence values: this is the CHANGED path, and it
# must not be confused with NEW.
$fc = Load $realFacts
$e = Find-File $fc 'Edge' 'Profile 1' 'Secure Preferences'
if ($null -eq $e) { throw 'fixture target missing' }
$e.mtime = '2026-10-16 08:12:30'
$e.bytes = 149001
Save $fc (Join-Path $work 'facts-C.json')

Write-Output '[1] establish baseline from the live capture'
Run-Engine @{ Mode = 'baseline'; FactsFile = @($realFacts); StoreDir = $store; OutFile = (Join-Path $work 'base.json') }
$base = Load (Join-Path $work 'base.json')
Expect 'baseline captured 11 findings' (@($base.findings).Count -eq 11)
Expect 'baseline file written' (Test-Path (Join-Path $store 'baseline.json'))

Write-Output '[2] rescan the same facts: nothing may report as changed'
Run-Engine @{ Mode = 'scan'; FactsFile = @($realFacts); StoreDir = $store; OutFile = (Join-Path $work 'scan-same.json') }
$r0 = StateMap (Join-Path $work 'scan-same.json')
Expect 'all 11 PERSIST' (@($r0.doc.findings | Where-Object { $_.state -eq 'PERSIST' }).Count -eq 11)
Expect 'zero NEW' ([int]$r0.doc.counts.NEW -eq 0)
Expect 'zero RESOLVED' ([int]$r0.doc.counts.RESOLVED -eq 0)

Write-Output '[3] fixture B: Chrome gets the URL back'
Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-B.json'); StoreDir = $store; OutFile = (Join-Path $work 'scan-B.json') }
$rB = StateMap (Join-Path $work 'scan-B.json')
Expect 'BR-01 Chrome/Default is NEW' ($rB.map['BR-01|Chrome / Default'] -eq 'NEW')
Expect 'BR-07 Chrome/Default retired' (@($rB.doc.resolved | Where-Object { $_.key -eq 'BR-07|Chrome / Default' }).Count -gt 0)
Expect 'BR-04 Chrome/Default still PERSIST (unrelated evidence)' ($rB.map['BR-04|Chrome / Default'] -eq 'PERSIST')
Expect 'BR-06 Chrome/Default still PERSIST' ($rB.map['BR-06|Chrome / Default'] -eq 'PERSIST')
Expect 'Edge Profile 1 untouched by fixture B' ($rB.map['BR-01|Edge / Profile 1'] -eq 'PERSIST')
# The engine infers recurrence on its own: Chrome also holds a repair backup
# whose content was dirty, so a re-injected URL satisfies BR-05's evidence too.
# Two new findings from one injected value is correct, not double counting.
Expect 'BR-05 Chrome/Default is NEW as well (recurrence inferred)' ($rB.map['BR-05|Chrome / Default'] -eq 'NEW')
Expect 'counts.NEW == 2' ([int]$rB.doc.counts.NEW -eq 2)
Expect 'counts.RESOLVED == 1' ([int]$rB.doc.counts.RESOLVED -eq 1)

Write-Output '[4] fixture C: the hijacked file is rewritten again'
Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-C.json'); StoreDir = $store; OutFile = (Join-Path $work 'scan-C.json') }
$rC = StateMap (Join-Path $work 'scan-C.json')
Expect 'BR-01 Edge P1 is CHANGED (not NEW)' ($rC.map['BR-01|Edge / Profile 1'] -eq 'CHANGED')
Expect 'BR-05 Edge P1 is CHANGED (timeline moved)' ($rC.map['BR-05|Edge / Profile 1'] -eq 'CHANGED')
Expect 'BR-02 Edge P1 stays PERSIST (seal keys unchanged)' ($rC.map['BR-02|Edge / Profile 1'] -eq 'PERSIST')
# BR-03 only shows startup_mode and startup_urls. Neither moved in fixture C, so
# it must stay PERSIST even though the file changed. A finding is only reported
# as changed when the evidence it actually cites changed - otherwise every file
# write would light up every rule on that profile.
Expect 'BR-03 Edge P1 stays PERSIST (its own evidence did not change)' ($rC.map['BR-03|Edge / Profile 1'] -eq 'PERSIST')
Expect 'no finding lost' (@($rC.doc.findings).Count -eq 11)

Write-Output '[5] acknowledge demotes without deleting the rule'
Run-Engine @{ Mode = 'ack'; AckKey = 'BR-06|Chrome / Default'; StoreDir = $store }
Run-Engine @{ Mode = 'scan'; FactsFile = @($realFacts); StoreDir = $store; OutFile = (Join-Path $work 'scan-ack.json') }
$rA = StateMap (Join-Path $work 'scan-ack.json')
Expect 'BR-06 Chrome/Default is KNOWN' ($rA.map['BR-06|Chrome / Default'] -eq 'KNOWN')
Expect 'other BR-06 still PERSIST' ($rA.map['BR-06|Edge / Profile 1'] -eq 'PERSIST')
Expect 'finding still present after ack (11 total)' (@($rA.doc.findings).Count -eq 11)
Expect 'low severity count excludes acknowledged' ([int]$rA.doc.severity_counts.low -eq 1)

# --- [6] persistence oracle --------------------------------------------------
# The expected hit set here is recomputed from the raw facts by independent
# filtering, not pasted from a snapshot. A machine that gains or loses autostart
# entries tomorrow therefore does not break this test, while a rule whose logic
# drifts from its stated predicate does.
Write-Output ''
Write-Output '[6] persistence rules must agree with the same predicate recomputed from raw facts'
$sp = Join-Path $work 'store-p'
Run-Engine @{ Mode = 'baseline'; FactsFile = @($realFacts, $realPers); StoreDir = $sp; OutFile = (Join-Path $work 'p-base.json') }
$pb = Load (Join-Path $work 'p-base.json')
$pf = Load $realPers
$ents = @($pf.entries)

Expect ('subjects = browser 4 + persistence ' + $ents.Count) ([int]$pb.subjects_total -eq (4 + $ents.Count))

function SubjectSet($doc, $rid) {
    return @($doc.findings | Where-Object { $_.rule_id -eq $rid } | ForEach-Object { [string]$_.subject } | Sort-Object)
}
function SetEq($a, $b) {
    $x = @($a | Sort-Object -Unique)
    $y = @($b | Sort-Object -Unique)
    if ($x.Count -ne $y.Count) { return $false }
    for ($i = 0; $i -lt $x.Count; $i++) { if ($x[$i] -ne $y[$i]) { return $false } }
    return $true
}
function PersSubject($e) { return [string]$e.kind + ' / ' + [string]$e.name }

# PS-01: autostart registered, target binary gone.
$want01 = @($ents | Where-Object {
    $_.exe_exists -eq $false -and [string]$_.exe -ne '' -and
    @('run_key', 'startup_folder', 'scheduled_task', 'service', 'elam_driver', 'ifeo_debugger') -contains $_.kind
} | ForEach-Object { PersSubject $_ })
Expect ('PS-01 == independently computed residue set (' + $want01.Count + ')') (SetEq (SubjectSet $pb 'PS-01') $want01)

# PS-02: exists, outside the OS tree, signature not valid.
$want02 = @($ents | Where-Object {
    $_.exe_exists -eq $true -and $_.in_windows -eq $false -and
    @('NotSigned', 'HashMismatch', 'NotTrusted') -contains [string]$_.sig_status
} | ForEach-Object { PersSubject $_ })
Expect ('PS-02 == independently computed unsigned set (' + $want02.Count + ')') (SetEq (SubjectSet $pb 'PS-02') $want02)

# PS-07: resident in a user-writable location, and not shipped by Microsoft.
# This is the rule that would flag Defender against itself if the signer filter
# were missing, so the exclusion is asserted positively as well as by set size.
$MS = @('Microsoft Windows', 'Microsoft Windows Publisher', 'Microsoft Corporation')
$want07 = @($ents | Where-Object {
    $_.exe_exists -eq $true -and $_.in_writable -eq $true -and (-not ($MS -contains [string]$_.signer))
} | ForEach-Object { PersSubject $_ })
Expect ('PS-07 == independently computed writable-resident set (' + $want07.Count + ')') (SetEq (SubjectSet $pb 'PS-07') $want07)
# The exclusion has to be asserted against a non-empty set or it proves nothing:
# Defender's own binaries live under C:\ProgramData, so without the signer filter
# WinDefend and MDCoreSvc would be reported as suspicious residents of this box.
$msWr = @($ents | Where-Object {
    $_.exe_exists -eq $true -and $_.in_writable -eq $true -and ($MS -contains [string]$_.signer)
} | ForEach-Object { PersSubject $_ })
Expect ('there are Microsoft-signed writable residents to exclude (' + $msWr.Count + ')') ($msWr.Count -gt 0)
$leaked = @($msWr | Where-Object { (SubjectSet $pb 'PS-07') -contains $_ })
Expect 'no Microsoft-signed resident leaks into PS-07' ($leaked.Count -eq 0)

# PS-03 / PS-04 / PS-05 / PS-06 are the high-severity surface. Each must fire
# exactly when its own stated condition holds on this machine - which today it
# does not, so zero hits is the correct result rather than an untested rule.
Expect ('PS-03 fires iff Early-Launch holds more than WdBoot (members=' + (@($pf.elam_members) -join ',') + ')') `
    ((SubjectSet $pb 'PS-03').Count -eq @($pf.elam_members | Where-Object { $_ -ne 'WdBoot' }).Count)
$hostsEnt = @($ents | Where-Object { $_.kind -eq 'hosts_file' })
$hEff = 0
if ($hostsEnt.Count -gt 0) { $hEff = [int]$hostsEnt[0].host_effective }
Expect ('PS-04 fires iff hosts has an effective override (host_effective=' + $hEff + ')') `
    ((SubjectSet $pb 'PS-04').Count -eq $(if ($hEff -ge 1) { 1 } else { 0 }))
Expect 'PS-05 fires iff an IFEO entry exists' `
    ((SubjectSet $pb 'PS-05').Count -eq @($ents | Where-Object { $_.kind -eq 'ifeo_debugger' }).Count)
Expect 'PS-06 fires iff a non-OS LSP provider exists' `
    ((SubjectSet $pb 'PS-06').Count -eq @($ents | Where-Object { $_.kind -eq 'winsock_lsp' -and $_.in_windows -eq $false }).Count)

# --- [7] countGte on a scalar, the operator bug this suite caught -------------
# host_effective is a count stored as a number. Reading a scalar as a one-element
# list made every machine report a hosts override, so both directions are pinned.
$fg = Load $realPers
$gh = @($fg.entries | Where-Object { $_.kind -eq 'hosts_file' })
if ($gh.Count -eq 0) { throw 'no hosts entry in facts' }
$gh[0].host_effective = 3
$gh[0].host_count = 4
Save $fg (Join-Path $work 'facts-hosts.json')
Run-Engine @{ Mode = 'baseline'; FactsFile = @($realFacts, (Join-Path $work 'facts-hosts.json')); StoreDir = (Join-Path $work 'store-h'); OutFile = (Join-Path $work 'hosts.json') }
$hd = Load (Join-Path $work 'hosts.json')
Expect 'PS-04 fires when host_effective is raised to 3' ((SubjectSet $hd 'PS-04').Count -eq 1)
Expect 'PS-04 advice survived rendering' (@($hd.findings | Where-Object { $_.rule_id -eq 'PS-04' -and $_.advice -ne '' }).Count -eq 1)

# --- [8] a planted autostart residue is classified NEW, not merged -------------
$fp = Load $realPers
$planted = $fp.entries[0] | ConvertTo-Json -Depth 8 | ConvertFrom-Json
$planted.kind = 'run_key'
$planted.name = 'ZZSelfTestResidue'
$planted.location = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$planted.command = 'C:\Windows\Temp\zzselftest.exe'
$planted.exe = 'C:\Windows\Temp\zzselftest.exe'
$planted.exe_exists = $false
$planted.signer = ''
$planted.sig_status = ''
$planted.in_windows = $false
$planted.in_writable = $false
$fp.entries = @($fp.entries) + @($planted)
Save $fp (Join-Path $work 'facts-planted.json')
Run-Engine @{ Mode = 'scan'; FactsFile = @($realFacts, (Join-Path $work 'facts-planted.json')); StoreDir = $sp; OutFile = (Join-Path $work 'scan-planted.json') }
$pd = StateMap (Join-Path $work 'scan-planted.json')
Expect 'planted residue opens PS-01 as NEW' ($pd.map['PS-01|run_key / ZZSelfTestResidue'] -eq 'NEW')
Expect 'existing PS-01 rows stay PERSIST' ($pd.map['PS-01|service / AndrowsSvr'] -eq 'PERSIST')
Expect 'nothing disappeared from the baseline' ([int]$pd.doc.counts.RESOLVED -eq 0)
Expect 'subject count grew by exactly 1' ([int]$pd.doc.subjects_total -eq (4 + $ents.Count + 1))

# --- [9] an unknown probe name must fail loudly --------------------------------
$fu = Load $realPers
$fu.probe = 'browser prefs (renamed by hand)'
Save $fu (Join-Path $work 'facts-badprobe.json')
$threw = $false
try {
    Run-Engine @{ Mode = 'scan'; FactsFile = @($realFacts, (Join-Path $work 'facts-badprobe.json')); StoreDir = $sp; OutFile = (Join-Path $work 'bad.json') }
} catch { $threw = $true }
Expect 'unknown probe name throws instead of silently dropping facts' $threw

# --- [9b] rule metadata must survive into the payload -------------------------
# A group title that silently arrives empty is invisible in the engine's own
# summary line and only shows up as a blank subtitle on every report card, so it
# is asserted here rather than eyeballed in a screenshot.
Write-Output ''
Write-Output '[9b] every finding carries its group label and a renderable title'
$badGroup = @($pb.findings | Where-Object {
    [string]::IsNullOrWhiteSpace([string]$_.group_title) -or
    [string]$_.group_title -like '*@{*}' -or
    [string]::IsNullOrWhiteSpace([string]$_.group)
})
Expect ('group_title populated and sane on all ' + @($pb.findings).Count + ' findings') ($badGroup.Count -eq 0)
Expect 'both rule groups are represented' `
    (@($pb.findings | ForEach-Object { $_.group } | Select-Object -Unique).Count -eq 2)
$badTitle = @($pb.findings | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.title) -or [string]::IsNullOrWhiteSpace([string]$_.why) })
Expect 'every finding has a title and a why' ($badTitle.Count -eq 0)
$badFp = @($pb.findings | Where-Object { [string]$_.fingerprint -notmatch '^[0-9A-F]{16}$' })
Expect 'every fingerprint is a 16 hex char digest' ($badFp.Count -eq 0)

# --- [10] residue claims must be real, not a PATH-resolution artifact ---------
# The first version of PS-01 also fired on a scheduled task running
# `rasdial <connection> <user> <password>`. A bare command name is not a missing
# file: CreateProcess resolves it against the PATH. Any row the engine calls a
# residue is therefore re-confirmed absent here, so the rule cannot quietly decay
# back into reporting healthy Windows commands as leftovers.
Write-Output ''
Write-Output '[10] every residue claim is independently re-confirmed absent'
$res01 = SubjectSet $pb 'PS-01'
$unconfirmed = @()
foreach ($e in $ents) {
    if (-not ($res01 -contains (PersSubject $e))) { continue }
    $x = [string]$e.exe
    if ($x -notmatch '[\\/]') { $unconfirmed += ((PersSubject $e) + ' bare name, should have resolved') }
    elseif (Test-Path -LiteralPath $x) { $unconfirmed += ((PersSubject $e) + ' file actually exists') }
}
Expect ('PS-01 rows (' + $res01.Count + ') all confirmed absent, none a bare name') ($res01.Count -gt 0 -and $unconfirmed.Count -eq 0)
$ras = @($ents | Where-Object { [string]$_.command -match '^rasdial\s' })
if ($ras.Count -gt 0) {
    Expect 'the bare-command dial task resolves to an existing binary' ($ras[0].exe_exists -eq $true)
    Expect 'and lands inside the OS tree' ($ras[0].in_windows -eq $true)
}

Write-Output ''
Write-Output ('SELFTEST: ' + $pass + ' PASS, ' + $fail + ' FAIL')
if ($fail -gt 0) { exit 1 }
exit 0
