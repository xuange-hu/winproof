$ErrorActionPreference = 'Stop'

# Contract test. The baseline diff is the product's whole claim ("what changed"),
# and the rule files are the product's whole judgement, so both are exercised
# against committed synthetic captures rather than hoped for.
#
# Sections [1]-[12] run on tests/fixtures/*.json and therefore give the same
# verdict on any machine, including one that has never been hijacked and one with
# no browser installed at all. Sections [13]-[14] re-run the same rules against
# the real capture on this box and skip cleanly when it is absent.
#
# Nothing here writes outside out\selftest, and no real browser profile is read.

$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path $root 'out\selftest'
$engine = Join-Path $root 'engine.ps1'
$fxBrowser = Join-Path $root 'tests\fixtures\facts-browser.json'
$fxPers = Join-Path $root 'tests\fixtures\facts-persistence.json'
$realFacts = Join-Path $root 'out\facts-browser.json'
$realPers = Join-Path $root 'out\facts-persistence.json'

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$pass = 0
$fail = 0
$skip = 0
function Expect([string]$label, $cond) {
    if ($cond) {
        Write-Output ('  PASS | ' + $label)
        $script:pass++
    } else {
        Write-Output ('  FAIL | ' + $label)
        $script:fail++
    }
}
function Skip([string]$label) {
    Write-Output ('  SKIP | ' + $label)
    $script:skip++
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
function KeysOf($doc) {
    return @($doc.findings | ForEach-Object { [string]$_.rule_id + '|' + [string]$_.subject } | Sort-Object)
}

# The manifest IS the test: each rule is mapped to the exact subjects the fixture
# rows were built to trigger. Writing the fixture and the expectation from the
# same reading of the predicate is what makes a drift in either one visible.
$wantBrowser = [ordered]@{
    'BR-01' = @('Edge / Profile 1', 'Chrome / Default', 'Chrome / Profile 3')
    'BR-02' = @('Edge / Default', 'Edge / Profile 1')
    'BR-03' = @('Edge / Profile 1', 'Chrome / Default', 'Chrome / Profile 3')
    'BR-04' = @('Edge / Default')
    'BR-05' = @('Chrome / Default', 'Edge / Profile 1')
    'BR-06' = @('Chrome / Profile 3', 'Edge / Profile 1')
    'BR-07' = @('Edge / Profile 2')
}
$wantPers = [ordered]@{
    'PS-01' = @('run_key / ZzResidueGhost', 'service / ZzSvcGone', 'scheduled_task / \ZzTaskGone')
    'PS-02' = @('scheduled_task / \ZzHashDrift', 'startup_folder / ZzOld Helper.lnk')
    'PS-03' = @('elam_driver / ZzThirdPartyElam')
    'PS-04' = @('hosts_file / hosts')
    'PS-05' = @('ifeo_debugger / notepad.exe')
    'PS-06' = @('winsock_lsp / ZzNetFilter')
    'PS-07' = @('service / ZzWritableResident')
}
function Check-Manifest($doc, $want) {
    $extra = @()
    $total = 0
    foreach ($rid in $want.Keys) {
        $total += @($want[$rid]).Count
        if (-not (SetEq (SubjectSet $doc $rid) $want[$rid])) {
            $extra += ($rid + ' set mismatch: got [' + ((SubjectSet $doc $rid) -join ', ') + ']')
        }
    }
    $declared = @()
    foreach ($rid in $want.Keys) { foreach ($s in $want[$rid]) { $declared += ($rid + '|' + $s) } }
    $undeclared = @( @(KeysOf $doc) | Where-Object { -not ($declared -contains $_) })
    Expect ('every rule fires on exactly its documented subjects (' + $total + ' findings)') `
        ($extra.Count -eq 0 -and @($doc.findings).Count -eq $total)
    Expect ('no finding outside the manifest (undeclared=' + $undeclared.Count + ')') ($undeclared.Count -eq 0)
    if ($extra.Count -gt 0) { foreach ($x in $extra) { Write-Output ('     ! ' + $x) } }
}

foreach ($f in @($fxBrowser, $fxPers)) {
    if (-not (Test-Path $f)) { throw ('fixture missing: ' + $f) }
}

Write-Output '[1] browser fixture: the rule set must equal the manifest'
Run-Engine @{ Mode = 'baseline'; FactsFile = @($fxBrowser); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'b0.json') }
$browserBase = Load (Join-Path $work 'b0.json')
Check-Manifest $browserBase $wantBrowser
Expect 'fixture exposes 5 profiles' ([int]$browserBase.subjects_total -eq 5)

Write-Output '[2] live capture and fixture must not be confusable: all 7 browser rules exercised'
$brIds = @($browserBase.findings | ForEach-Object { $_.rule_id } | Select-Object -Unique)
Expect ('all 7 browser rules fire on the fixture (' + ($brIds -join ',') + ')') ($brIds.Count -eq 7)

Write-Output '[3] rescan the same facts: nothing may report as changed'
Run-Engine @{ Mode = 'scan'; FactsFile = @($fxBrowser); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-same.json') }
$r0 = StateMap (Join-Path $work 'scan-same.json')
Expect 'all 14 PERSIST' (@($r0.doc.findings | Where-Object { $_.state -eq 'PERSIST' }).Count -eq 14)
Expect 'zero NEW' ([int]$r0.doc.counts.NEW -eq 0)
Expect 'zero RESOLVED' ([int]$r0.doc.counts.RESOLVED -eq 0)

# --- [4] fixture B: a profile that stayed repaired gets the URL back ----------
# Edge / Profile 2 is the repair-held subject: its backup contains a blocklisted
# URL and its live value does not. Re-injecting must do two things at once -
# open BR-01 as NEW and retire BR-07 as RESOLVED - without disturbing neighbours.
$fb = Load $fxBrowser
$b = Find-File $fb 'Edge' 'Profile 2' 'Secure Preferences'
if ($null -eq $b) { throw 'fixture target missing' }
# The probe already flattened session.* onto the file record, so a fixture has
# to rewrite the flat field - editing a nested session object would be ignored.
Add-Member -InputObject $b -MemberType NoteProperty -Name 'startup_urls' `
    -Value @('http://2345.pbgia.com/win23') -Force
Save $fb (Join-Path $work 'facts-B.json')

Write-Output '[4] fixture B: repair-held profile gets the hijack back'
Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-B.json'); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-B.json') }
$rB = StateMap (Join-Path $work 'scan-B.json')
Expect 'BR-01 Edge/Profile 2 is NEW' ($rB.map['BR-01|Edge / Profile 2'] -eq 'NEW')
Expect 'BR-07 Edge/Profile 2 retired' (@($rB.doc.resolved | Where-Object { $_.key -eq 'BR-07|Edge / Profile 2' }).Count -gt 0)
# The engine infers recurrence on its own: this profile holds a repair backup whose
# content was dirty, so a re-injected URL satisfies BR-05's evidence too. Two new
# findings from one injected value is correct, not double counting.
Expect 'BR-05 Edge/Profile 2 is NEW as well (recurrence inferred)' ($rB.map['BR-05|Edge / Profile 2'] -eq 'NEW')
Expect 'counts.NEW == 2' ([int]$rB.doc.counts.NEW -eq 2)
Expect 'counts.RESOLVED == 1' ([int]$rB.doc.counts.RESOLVED -eq 1)
Expect 'neighbour Edge/Profile 1 unaffected' ($rB.map['BR-01|Edge / Profile 1'] -eq 'PERSIST')
Expect 'neighbour Chrome/Default unaffected' ($rB.map['BR-05|Chrome / Default'] -eq 'PERSIST')
Expect 'finding set is 14 - 1 resolved + 2 new' (@($rB.doc.findings).Count -eq 15)

# --- [5] fixture C: the hijacked file is rewritten again ----------------------
# Same findings, different evidence values: this is the CHANGED path, and it must
# not be confused with NEW.
$fc = Load $fxBrowser
$e = Find-File $fc 'Edge' 'Profile 1' 'Secure Preferences'
if ($null -eq $e) { throw 'fixture target missing' }
$e.mtime = '2026-10-16 08:12:30'
$e.bytes = 149001
Save $fc (Join-Path $work 'facts-C.json')

Write-Output '[5] fixture C: the hijacked file is rewritten again'
Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-C.json'); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-C.json') }
$rC = StateMap (Join-Path $work 'scan-C.json')
Expect 'BR-01 Edge P1 is CHANGED (not NEW)' ($rC.map['BR-01|Edge / Profile 1'] -eq 'CHANGED')
Expect 'BR-05 Edge P1 is CHANGED (timeline moved)' ($rC.map['BR-05|Edge / Profile 1'] -eq 'CHANGED')
Expect 'BR-02 Edge P1 stays PERSIST (seal keys unchanged)' ($rC.map['BR-02|Edge / Profile 1'] -eq 'PERSIST')
# BR-03 only shows startup_mode, startup_urls and doc_role. None moved in fixture
# C, so it must stay PERSIST even though the file changed. A finding is only
# reported as changed when the evidence it actually cites changed - otherwise
# every file write would light up every rule on that profile.
Expect 'BR-03 Edge P1 stays PERSIST (its own evidence did not change)' ($rC.map['BR-03|Edge / Profile 1'] -eq 'PERSIST')
Expect 'no finding lost' (@($rC.doc.findings).Count -eq 14)
Expect 'zero NEW on a metadata rewrite' ([int]$rC.doc.counts.NEW -eq 0)
# Exactly three rows move, and they are the three whose cited evidence moved:
# BR-01 and BR-05 show bytes/mtime, and BR-06 shows mtime as well - a rewrite
# after a crash is real information, not noise. Pinning the number is what stops
# the scoping from degrading back into "every rule on a touched file lights up".
Expect 'only the three mtime-citing rules are CHANGED' ([int]$rC.doc.counts.CHANGED -eq 3)
Expect 'BR-06 Edge P1 is CHANGED (its evidence cites mtime)' ($rC.map['BR-06|Edge / Profile 1'] -eq 'CHANGED')
Expect 'Chrome/Default rows are untouched by an Edge rewrite' (@($rC.doc.findings | Where-Object { $_.subject -eq 'Chrome / Default' -and $_.state -ne 'PERSIST' }).Count -eq 0)

# --- [6] fixture D: a value change, isolated from the other rules -------------
# Edge / Default is clean but sealed and carries orphan signatures. Injecting a
# URL must open the rules that cite startup_urls, leave BR-04 (which cites only
# signature key lists) on PERSIST, and move BR-02 to CHANGED rather than PERSIST:
# BR-02 shows startup_urls_bad alongside seal_keys, because how dangerous a
# sealed copy is depends on what the plaintext now says.
$fd = Load $fxBrowser
$d = Find-File $fd 'Edge' 'Default' 'Secure Preferences'
if ($null -eq $d) { throw 'fixture target missing' }
Add-Member -InputObject $d -MemberType NoteProperty -Name 'startup_urls' -Value @('http://duba.com/hp') -Force
Add-Member -InputObject $d -MemberType NoteProperty -Name 'startup_mode' -Value 4 -Force
Save $fd (Join-Path $work 'facts-D.json')

Write-Output ''
Write-Output '[6] fixture D: a value change lights up only the rules that cite it'
Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-D.json'); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-D.json') }
$rD = StateMap (Join-Path $work 'scan-D.json')
Expect 'BR-01 Edge/Default is NEW' ($rD.map['BR-01|Edge / Default'] -eq 'NEW')
Expect 'BR-03 Edge/Default is NEW (mode became 4)' ($rD.map['BR-03|Edge / Default'] -eq 'NEW')
Expect 'BR-02 Edge/Default is CHANGED (it cites startup_urls_bad)' ($rD.map['BR-02|Edge / Default'] -eq 'CHANGED')
Expect 'BR-04 Edge/Default stays PERSIST (signatures untouched)' ($rD.map['BR-04|Edge / Default'] -eq 'PERSIST')
Expect 'no BR-05 without a repair backup' ($null -eq $rD.map['BR-05|Edge / Default'])
Expect 'exactly the three cited-evidence rows move' ([int]$rD.doc.counts.NEW + [int]$rD.doc.counts.CHANGED -eq 3)

# --- [7] acknowledge ----------------------------------------------------------
Write-Output '[7] acknowledge demotes without deleting the rule'
Run-Engine @{ Mode = 'ack'; AckKey = 'BR-06|Chrome / Profile 3'; StoreDir = (Join-Path $work 'store') }
Run-Engine @{ Mode = 'scan'; FactsFile = @($fxBrowser); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-ack.json') }
$rA = StateMap (Join-Path $work 'scan-ack.json')
Expect 'BR-06 Chrome/Profile 3 is KNOWN' ($rA.map['BR-06|Chrome / Profile 3'] -eq 'KNOWN')
Expect 'the other BR-06 stays PERSIST (ack is per-subject)' ($rA.map['BR-06|Edge / Profile 1'] -eq 'PERSIST')
Expect 'finding still present after ack (14 total)' (@($rA.doc.findings).Count -eq 14)
# low severity on this fixture is exactly the two BR-06 rows, so the count is the
# proof that KNOWN rows are excluded from the severity histogram rather than the
# list - the report must not still show "2 low" for something the user owns.
Expect 'low severity count drops to 1' ([int]$rA.doc.severity_counts.low -eq 1)

# --- [8] persistence fixture: coverage a clean machine cannot give -------------
# On an uninfected box PS-03/04/05/06 legitimately hit zero, which means a real
# scan never exercises them and a broken predicate would go unnoticed until the
# day one of them matters. The fixture fires all seven on purpose.
Write-Output ''
Write-Output '[8] persistence fixture: all 7 rules exercised, including the four that are idle on a clean box'
$sp = Join-Path $work 'store-p'
Run-Engine @{ Mode = 'baseline'; FactsFile = @($fxPers); StoreDir = $sp; OutFile = (Join-Path $work 'p0.json') }
$persBase = Load (Join-Path $work 'p0.json')
Check-Manifest $persBase $wantPers
$pf = Load $fxPers
$ents = @($pf.entries)
Expect ('fixture exposes one row per surface (15 subjects, ' + $ents.Count + ' entries)') ([int]$persBase.subjects_total -eq $ents.Count)
$psIds = @($persBase.findings | ForEach-Object { $_.rule_id } | Select-Object -Unique)
Expect ('all 7 persistence rules fire (' + ($psIds -join ',') + ')') ($psIds.Count -eq 7)

# The Microsoft-signer exclusion has to be asserted against a row that would
# otherwise be reported, or it proves nothing. On a real box this is Defender's
# own binary under C:\ProgramData; here it is a clone of that shape.
$MS = @('Microsoft Windows', 'Microsoft Windows Publisher', 'Microsoft Corporation')
$msWr = @($ents | Where-Object {
    $_.exe_exists -eq $true -and $_.in_writable -eq $true -and ($MS -contains [string]$_.signer)
} | ForEach-Object { PersSubject $_ })
Expect ('a Microsoft-signed writable resident exists in the fixture to exclude (' + $msWr.Count + ')') ($msWr.Count -gt 0)
Expect 'and it does not leak into PS-07' (@( @(SubjectSet $persBase 'PS-07') | Where-Object { $msWr -contains $_ }).Count -eq 0)

# High severity must come only from the four hard surfaces, not from residue or
# signature noise - that ordering is the report's whole prioritisation.
$hi = @($persBase.findings | Where-Object { $_.severity -eq 'high' } | ForEach-Object { $_.rule_id } | Select-Object -Unique)
Expect ('high severity rows are only PS-03/04/05/06 (' + ($hi -join ',') + ')') (SetEq $hi @('PS-03', 'PS-04', 'PS-05', 'PS-06'))

# --- [9] countGte on a scalar -------------------------------------------------
# host_effective is a count stored as a number. Reading a scalar as a one-element
# list made every machine report a hosts override, so BOTH directions are pinned
# here rather than only the firing one.
Write-Output ''
Write-Output '[9] countGte must measure a scalar by its value, in both directions'
$fg = Load $fxPers
$gh = @($fg.entries | Where-Object { $_.kind -eq 'hosts_file' })
if ($gh.Count -eq 0) { throw 'no hosts entry in fixture' }
$gh[0].host_effective = 0
$gh[0].host_count = 4
Save $fg (Join-Path $work 'facts-hosts-zero.json')
Run-Engine @{ Mode = 'baseline'; FactsFile = @(Join-Path $work 'facts-hosts-zero.json'); StoreDir = (Join-Path $work 'store-z'); OutFile = (Join-Path $work 'hosts-zero.json') }
$zd = Load (Join-Path $work 'hosts-zero.json')
Expect 'host_effective=0 does not fire PS-04 (a scalar is not a one-element list)' ((SubjectSet $zd 'PS-04').Count -eq 0)

$fg2 = Load $fxPers
$gh2 = @($fg2.entries | Where-Object { $_.kind -eq 'hosts_file' })
$gh2[0].host_effective = 3
$gh2[0].host_count = 9
Save $fg2 (Join-Path $work 'facts-hosts-three.json')
Run-Engine @{ Mode = 'baseline'; FactsFile = @(Join-Path $work 'facts-hosts-three.json'); StoreDir = (Join-Path $work 'store-t'); OutFile = (Join-Path $work 'hosts-three.json') }
$td = Load (Join-Path $work 'hosts-three.json')
Expect 'host_effective=3 does fire PS-04' ((SubjectSet $td 'PS-04').Count -eq 1)
Expect 'and its advice survived rendering' (@($td.findings | Where-Object { $_.rule_id -eq 'PS-04' -and $_.advice -ne '' }).Count -eq 1)

# --- [10] a planted residue is classified NEW, not merged ---------------------
Write-Output ''
Write-Output '[10] a newly planted residue opens as NEW without swallowing neighbours'
$fp = Load $fxPers
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
Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-planted.json'); StoreDir = $sp; OutFile = (Join-Path $work 'scan-planted.json') }
$pd = StateMap (Join-Path $work 'scan-planted.json')
Expect 'planted residue opens PS-01 as NEW' ($pd.map['PS-01|run_key / ZZSelfTestResidue'] -eq 'NEW')
Expect 'existing PS-01 rows stay PERSIST' ($pd.map['PS-01|service / ZzSvcGone'] -eq 'PERSIST')
Expect 'nothing disappeared from the baseline' ([int]$pd.doc.counts.RESOLVED -eq 0)
Expect 'subject count grew by exactly 1' ([int]$pd.doc.subjects_total -eq ($ents.Count + 1))

# --- [11] an unknown probe name must fail loudly ------------------------------
Write-Output ''
Write-Output '[11] an unrecognised probe name is an error, not silently empty facts'
$fu = Load $fxPers
$fu.probe = 'persistence prefs (renamed by hand)'
Save $fu (Join-Path $work 'facts-badprobe.json')
$threw = $false
try {
    Run-Engine @{ Mode = 'scan'; FactsFile = @(Join-Path $work 'facts-badprobe.json'); StoreDir = $sp; OutFile = (Join-Path $work 'bad.json') }
} catch { $threw = $true }
Expect 'unknown probe name throws instead of silently dropping facts' $threw

# --- [12] rule metadata must survive into the payload -------------------------
# A group title that silently arrives empty is invisible in the engine's own
# summary line and only shows up as a blank subtitle on every report card, so it
# is asserted here rather than eyeballed in a screenshot.
Write-Output ''
Write-Output '[12] every finding carries its group label and a renderable title'
$both = @($browserBase.findings) + @($persBase.findings)
$badGroup = @($both | Where-Object {
    [string]::IsNullOrWhiteSpace([string]$_.group_title) -or
    [string]$_.group_title -like '*@{*}' -or
    [string]::IsNullOrWhiteSpace([string]$_.group)
})
Expect ('group_title populated and sane on all ' + $both.Count + ' findings') ($badGroup.Count -eq 0)
Expect 'both rule groups are represented' `
    (@($both | ForEach-Object { $_.group } | Select-Object -Unique).Count -eq 2)
$badTitle = @($both | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.title) -or [string]::IsNullOrWhiteSpace([string]$_.why) })
Expect 'every finding has a title and a why' ($badTitle.Count -eq 0)
$badAdvice = @($both | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.advice) })
Expect ('every finding has actionable advice (' + $badAdvice.Count + ' empty)') ($badAdvice.Count -eq 0)
$badFp = @($both | Where-Object { [string]$_.fingerprint -notmatch '^[0-9A-F]{16}$' })
Expect 'every fingerprint is a 16 hex char digest' ($badFp.Count -eq 0)
$badPath = @($browserBase.findings | Where-Object { [string]$_.detail_path -eq '' })
Expect 'browser findings point at a document path' ($badPath.Count -eq 0)

# An advice branch that collapses to its fallback is invisible in counts, so the
# two fixture profiles that differ only in sync.preferences must get different
# BR-05 texts. Compared for inequality on purpose: no literal from rules.json is
# duplicated here, so rewording the advice cannot silently break the assertion.
$syncBranch = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-05' -and $_.subject -eq 'Edge / Profile 1' } | ForEach-Object { [string]$_.advice })
$plainBranch = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-05' -and $_.subject -eq 'Chrome / Default' } | ForEach-Object { [string]$_.advice })
Expect 'conditional advice really branches (sync on vs off give different text)' ($syncBranch[0] -ne $plainBranch[0])

# --- [13] live rules vs a predicate recomputed from the real capture ----------
# The expected hit set here is recomputed from the raw facts by independent
# filtering, not pasted from a snapshot. A machine that gains or loses autostart
# entries tomorrow therefore does not break this test, while a rule whose logic
# drifts from its stated predicate does.
Write-Output ''
Write-Output '[13] live persistence facts must agree with the same predicate recomputed from raw entries'
if (-not (Test-Path $realPers)) {
    Skip 'no out\facts-persistence.json on this box - run scan.bat first'
} else {
    $live = Load $realPers
    $lents = @($live.entries)
    Run-Engine @{ Mode = 'baseline'; FactsFile = @($fxBrowser, $realPers); StoreDir = (Join-Path $work 'store-live'); OutFile = (Join-Path $work 'live.json') }
    $ld = Load (Join-Path $work 'live.json')
    Expect ('subjects = fixture 5 + live persistence ' + $lents.Count) ([int]$ld.subjects_total -eq (5 + $lents.Count))

    $want01 = @($lents | Where-Object {
        $_.exe_exists -eq $false -and [string]$_.exe -ne '' -and
        @('run_key', 'startup_folder', 'scheduled_task', 'service', 'elam_driver', 'ifeo_debugger') -contains $_.kind
    } | ForEach-Object { PersSubject $_ })
    Expect ('PS-01 == independently computed residue set (' + $want01.Count + ')') (SetEq (SubjectSet $ld 'PS-01') $want01)

    $want02 = @($lents | Where-Object {
        $_.exe_exists -eq $true -and $_.in_windows -eq $false -and
        @('NotSigned', 'HashMismatch', 'NotTrusted') -contains [string]$_.sig_status
    } | ForEach-Object { PersSubject $_ })
    Expect ('PS-02 == independently computed unsigned set (' + $want02.Count + ')') (SetEq (SubjectSet $ld 'PS-02') $want02)

    $want07 = @($lents | Where-Object {
        $_.exe_exists -eq $true -and $_.in_writable -eq $true -and (-not ($MS -contains [string]$_.signer))
    } | ForEach-Object { PersSubject $_ })
    Expect ('PS-07 == independently computed writable-resident set (' + $want07.Count + ')') (SetEq (SubjectSet $ld 'PS-07') $want07)

    # The four hard surfaces are asserted as "fires iff its condition holds",
    # so a clean machine passing this is a real result, not an empty one.
    Expect ('PS-03 fires iff Early-Launch holds more than WdBoot (members=' + (@($live.elam_members) -join ',') + ')') `
        ((SubjectSet $ld 'PS-03').Count -eq @($live.elam_members | Where-Object { $_ -ne 'WdBoot' }).Count)
    $hostsEnt = @($lents | Where-Object { $_.kind -eq 'hosts_file' })
    $hEff = 0
    if ($hostsEnt.Count -gt 0) { $hEff = [int]$hostsEnt[0].host_effective }
    Expect ('PS-04 fires iff hosts has an effective override (host_effective=' + $hEff + ')') `
        ((SubjectSet $ld 'PS-04').Count -eq $(if ($hEff -ge 1) { 1 } else { 0 }))
    Expect 'PS-05 fires iff an IFEO entry exists' `
        ((SubjectSet $ld 'PS-05').Count -eq @($lents | Where-Object { $_.kind -eq 'ifeo_debugger' }).Count)
    Expect 'PS-06 fires iff a non-OS LSP provider exists' `
        ((SubjectSet $ld 'PS-06').Count -eq @($lents | Where-Object { $_.kind -eq 'winsock_lsp' -and $_.in_windows -eq $false }).Count)

    # --- [14] residue claims must be real, not a PATH-resolution artifact -----
    # The first version of PS-01 also fired on a scheduled task running
    # `rasdial <connection> <user> <password>`. A bare command name is not a missing
    # file: CreateProcess resolves it against the PATH. Any row the engine calls a
    # residue is therefore re-confirmed absent here, so the rule cannot quietly
    # decay back into reporting healthy Windows commands as leftovers.
    Write-Output '[14] every live residue claim is independently re-confirmed absent'
    $res01 = SubjectSet $ld 'PS-01'
    $unconfirmed = @()
    foreach ($x in $lents) {
        if (-not ($res01 -contains (PersSubject $x))) { continue }
        $p = [string]$x.exe
        if ($p -notmatch '[\\/]') { $unconfirmed += ((PersSubject $x) + ' bare name, should have resolved') }
        elseif (Test-Path -LiteralPath $p) { $unconfirmed += ((PersSubject $x) + ' file actually exists') }
    }
    Expect ('PS-01 rows (' + $res01.Count + ') all confirmed absent, none a bare name') ($unconfirmed.Count -eq 0)
    if ($res01.Count -eq 0) { Write-Output '     (no residue on this box: the set is legitimately empty)' }
    foreach ($u in $unconfirmed) { Write-Output ('     ! ' + $u) }
    $ras = @($lents | Where-Object { [string]$_.command -match '^rasdial\s' })
    if ($ras.Count -gt 0) {
        Expect 'the bare-command dial task resolves to an existing binary' ($ras[0].exe_exists -eq $true)
        Expect 'and lands inside the OS tree' ($ras[0].in_windows -eq $true)
    } else {
        Skip 'no bare-command task on this box to re-check'
    }
}

Write-Output ''
Write-Output ('SELFTEST: ' + $pass + ' PASS, ' + $fail + ' FAIL, ' + $skip + ' SKIP')
if ($fail -gt 0) { exit 1 }
exit 0
