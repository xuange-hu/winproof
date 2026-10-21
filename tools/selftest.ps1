$ErrorActionPreference = 'Stop'

# Contract test. The baseline diff is the product's whole claim ("what changed"),
# and the rule files are the product's whole judgement, so both are exercised
# against committed synthetic captures rather than hoped for.
#
# Sections [1]-[13] and [16] run on tests/fixtures/*.json and therefore give the
# same verdict on any machine, including one that has never been hijacked and one
# with no browser installed at all. Sections [14]-[15] re-run the same rules
# against the real capture on this box and skip cleanly when it is absent. (The
# numbering follows the order sections were added, so [16] is a fixture section
# that runs after the live ones; renaming it would break the references to
# [14]-[15] in the README.)
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
# Advice text, looked up rather than retyped: the rules carry CJK wording, so an
# assertion that compares two rows' advice must read it out of the findings and
# never hard-code a translation of it here.
function AdviceOf($doc, $rid, $subj) {
    return @(@($doc.findings | Where-Object { $_.rule_id -eq $rid -and [string]$_.subject -eq $subj } |
        ForEach-Object { [string]$_.advice }))[0]
}
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
    # BR-08 is deliberately pinned to three subjects, one per shape of the same
    # problem: Profile 1 is hijacked now and also holds grants, Edge / Default is
    # clean at the startup page but still holds a grant, Chrome / Profile 3 and
    # Edge / Profile 2 hold none at all. That split is what makes the rule's
    # conditional advice branch observable inside the fixture instead of only on a
    # machine that happens to be infected.
    'BR-08' = @('Chrome / Default', 'Edge / Default', 'Edge / Profile 1')
    # BR-09 has two independent triggers and the fixture gives one subject to each:
    # Edge / Profile 2 is a blocklisted engine with a literal search_url (what a
    # hijacker leaves behind), Chrome / Default is google.com but
    # enforced_by_policy=true (what a policy or an extension leaves behind). A
    # subject set that loses either one means a branch silently stopped firing.
    'BR-09' = @('Edge / Profile 2', 'Chrome / Default')
    # BR-10 is the coverage-honesty rule: it must fire on exactly the three
    # subjects where something genuinely could not be read, and must NOT fire on
    # Chrome / Default or Edge / Profile 2, whose engine was readable and clean.
    # If the engine ever falls back to the plain Preferences for the provider,
    # Chrome / Profile 3 would drop out of this set and the assertion fails.
    'BR-10' = @('Chrome / Profile 3', 'Edge / Default', 'Edge / Profile 1')
    # BR-11 reads a different surface entirely (machine-level .lnk targets, not
    # profile JSON), so its subject kind is browser_shortcut and it is scoped to
    # one row on purpose: the other two shortcut rows exist to prove the rule
    # does NOT fire on a shortcut that merely has no URL, nor on one that carries
    # a legitimate --app-url. A manifest that grows to three subjects here means
    # the blocklist match leaked into benign launchers.
    'BR-11' = @('browser_shortcut / Zz 2345 Chrome.lnk')
    # BR-12 shares BR-11's surface family but not its criterion, and the fixture
    # carries both consequences of that: the blocklisted launch command and a
    # benign Outlook app-url both fire, because on a real machine no registry
    # browser launch command carries a URL at all (33 of 33 measured), so the URL
    # itself is the signal and the reputation only decides the advice branch. The
    # two other launch rows - a StartMenuInternet value with --brand-quark and an
    # MSEdgeHTM value with --single-argument %1 - must stay silent, which is what
    # stops the rule from firing on every OEM browser. Two subjects also mean both
    # advice branches are exercised inside the fixture.
    'BR-12' = @('browser_launch_cmd / HKLM:Classes/2345HTM',
                'browser_launch_cmd / HKCU:Classes/TaskbarEdgeOffice')
    # BR-13 is the false-positive trap made explicit. On a real machine 13 of 211
    # UserChoice extensions point at a ProgID that does not resolve under Classes,
    # and they are AppX packages and Windows components - so the AppX-shaped row
    # must NOT fire while the two genuinely dangling ones must, one carrying a Hash
    # (written through the proper API) and one without (hand-imported), which is
    # again both advice branches. The .shtml row resolves to a live ProgID and must
    # stay silent.
    'BR-13' = @('browser_file_assoc / .htm', 'browser_file_assoc / .xhtml')
    # BR-14/BR-15 are the policy layer, and the fixture is where their known answer
    # lives: on a clean machine the whole policy surface is 3 rows and none of them
    # forces anything, so the live scan can only ever show BR-15 here. Two rows must
    # fire BR-14 (one HKLM, one HKCU, so both advice branches are exercised) and two
    # must fire BR-15 (a capability grant plus an empty user-hive key). Three rows
    # exist only to stay silent: MetricsReportingEnabled and CloudPrintProxyEnabled
    # are what a managed enterprise machine is full of, and an empty key under HKLM
    # is not a finding - only the HKCU one is. Drop those negatives and the rules
    # decay into "any policy counts", which lights up red on a corporate laptop.
    # Both list-shaped rows are matched by pol_name (the last segment of the key),
    # not by the value name - the value under RestoreOnStartupURLs is just '1'.
    'BR-14' = @('browser_policy / HKLM Edge RestoreOnStartupURLs\1',
                'browser_policy / HKCU Chrome ExtensionInstallForcelist\1')
    'BR-15' = @('browser_policy / HKLM Edge LocalNetworkAccessAllowedForUrls\1',
                'browser_policy / HKCU Chromium (key itself)')
}
$wantPers = [ordered]@{
    'PS-01' = @('run_key / ZzResidueGhost', 'service / ZzSvcGone', 'scheduled_task / \ZzTaskGone')
    'PS-02' = @('scheduled_task / \ZzHashDrift', 'startup_folder / ZzOld Helper.lnk')
    'PS-03' = @('elam_driver / ZzThirdPartyElam')
    'PS-04' = @('hosts_file / hosts')
    'PS-05' = @('ifeo_debugger / notepad.exe')
    'PS-06' = @('winsock_lsp / ZzNetFilter')
    'PS-07' = @('service / ZzWritableResident')
    'PS-08' = @('scheduled_task / \ZzDialPlain')
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
# 5 profiles + 3 machine-level shortcut rows + 4 registry launch commands +
# 4 browser document-type associations + 7 policy rows. Counting them here is what
# makes a row that silently stopped reaching the engine visible as a subject miss
# rather than as an unexplained clean result.
Expect 'fixture exposes 5 profiles, 3 shortcuts, 4 launch cmds, 4 file assocs, 7 policy rows' ([int]$browserBase.subjects_total -eq 23)
Expect 'only the blocklisted shortcut fires BR-11' (SetEq (SubjectSet $browserBase 'BR-11') @('browser_shortcut / Zz 2345 Chrome.lnk'))
Expect 'the AppX-shaped dangling ProgID does not fire BR-13' `
    (-not ((SubjectSet $browserBase 'BR-13') -contains 'browser_file_assoc / .html'))
# The three policy negatives, spelled out rather than left to the set equality:
# a benign enterprise policy that starts firing BR-14 means the list drifted, and
# an HKLM empty key that starts firing BR-15 means the hive guard fell off.
Expect 'benign enterprise policies stay silent (HKLM MetricsReporting, HKCU CloudPrint)' `
    (@(@('browser_policy / HKLM Chrome MetricsReportingEnabled', 'browser_policy / HKCU Edge CloudPrintProxyEnabled') | Where-Object { (SubjectSet $browserBase 'BR-14') -contains $_ -or (SubjectSet $browserBase 'BR-15') -contains $_ }).Count -eq 0)
Expect 'an empty policy key under HKLM is not a finding' `
    (-not ((SubjectSet $browserBase 'BR-15') -contains 'browser_policy / HKLM Brave (key itself)'))
Expect 'BR-15 picks the empty-key advice on HKCU and the grant advice on HKLM' `
    ((@($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-15' }).Count -eq 2) -and
     ((AdviceOf $browserBase 'BR-15' 'browser_policy / HKCU Chromium (key itself)') -ne
      (AdviceOf $browserBase 'BR-15' 'browser_policy / HKLM Edge LocalNetworkAccessAllowedForUrls\1')))
Expect 'BR-14 picks the no-elevation advice on HKCU and the elevated advice on HKLM' `
    ((AdviceOf $browserBase 'BR-14' 'browser_policy / HKCU Chrome ExtensionInstallForcelist\1') -ne
     (AdviceOf $browserBase 'BR-14' 'browser_policy / HKLM Edge RestoreOnStartupURLs\1'))

Write-Output '[2] live capture and fixture must not be confusable: all 15 browser rules exercised'
$brIds = @($browserBase.findings | ForEach-Object { $_.rule_id } | Select-Object -Unique)
Expect ('all 15 browser rules fire on the fixture (' + ($brIds -join ',') + ')') ($brIds.Count -eq 15)

Write-Output '[3] rescan the same facts: nothing may report as changed'
Run-Engine @{ Mode = 'scan'; FactsFile = @($fxBrowser); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-same.json') }
$r0 = StateMap (Join-Path $work 'scan-same.json')
Expect 'all 31 PERSIST' (@($r0.doc.findings | Where-Object { $_.state -eq 'PERSIST' }).Count -eq 31)
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
# BR-09 Edge / Profile 2 cites startup_urls_bad alongside the engine fields, so a
# hijacked startup page changes how much a bad default engine matters: with the
# page still dirty the two have one root cause, with it clean the engine is a
# separate decision the user has to undo in another settings page.
Expect 'BR-09 Edge/Profile 2 is CHANGED (it cites startup_urls_bad)' ($rB.map['BR-09|Edge / Profile 2'] -eq 'CHANGED')
Expect 'counts.CHANGED == 1' ([int]$rB.doc.counts.CHANGED -eq 1)
Expect 'neighbour Edge/Profile 1 unaffected' ($rB.map['BR-01|Edge / Profile 1'] -eq 'PERSIST')
Expect 'neighbour Chrome/Default unaffected' ($rB.map['BR-05|Chrome / Default'] -eq 'PERSIST')
Expect 'finding set is 31 - 1 resolved + 2 new' (@($rB.doc.findings).Count -eq 32)

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
Expect 'no finding lost' (@($rC.doc.findings).Count -eq 31)
Expect 'zero NEW on a metadata rewrite' ([int]$rC.doc.counts.NEW -eq 0)
# Exactly four rows move, and they are the four whose cited evidence moved:
# BR-01 and BR-05 show bytes/mtime, BR-06 shows mtime, and BR-10 shows both
# because "we could not read the engine" is itself a statement about this file
# version - a rewrite may have changed that. A rewrite after a crash is real
# information, not noise. Pinning the number is what stops the scoping from
# degrading back into "every rule on a touched file lights up".
Expect 'only the four mtime-citing rules are CHANGED' ([int]$rC.doc.counts.CHANGED -eq 4)
Expect 'BR-06 Edge P1 is CHANGED (its evidence cites mtime)' ($rC.map['BR-06|Edge / Profile 1'] -eq 'CHANGED')
Expect 'BR-10 Edge P1 is CHANGED (its evidence cites mtime too)' ($rC.map['BR-10|Edge / Profile 1'] -eq 'CHANGED')
Expect 'BR-08 Edge P1 stays PERSIST (the grants did not move)' ($rC.map['BR-08|Edge / Profile 1'] -eq 'PERSIST')
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
# BR-08 cites startup_urls_bad on purpose: an exception grant for a domain is only
# as serious as whether that domain is still being loaded at startup. So injecting
# a URL must move this profile's grant row to CHANGED rather than leave it frozen.
Expect 'BR-08 Edge/Default is CHANGED (it also cites startup_urls_bad)' ($rD.map['BR-08|Edge / Default'] -eq 'CHANGED')
Expect 'exactly the four cited-evidence rows move' ([int]$rD.doc.counts.NEW + [int]$rD.doc.counts.CHANGED -eq 4)

# --- [7] acknowledge ----------------------------------------------------------
Write-Output '[7] acknowledge demotes without deleting the rule'
Run-Engine @{ Mode = 'ack'; AckKey = 'BR-06|Chrome / Profile 3'; StoreDir = (Join-Path $work 'store') }
Run-Engine @{ Mode = 'scan'; FactsFile = @($fxBrowser); StoreDir = (Join-Path $work 'store'); OutFile = (Join-Path $work 'scan-ack.json') }
$rA = StateMap (Join-Path $work 'scan-ack.json')
Expect 'BR-06 Chrome/Profile 3 is KNOWN' ($rA.map['BR-06|Chrome / Profile 3'] -eq 'KNOWN')
Expect 'the other BR-06 stays PERSIST (ack is per-subject)' ($rA.map['BR-06|Edge / Profile 1'] -eq 'PERSIST')
Expect 'finding still present after ack (31 total)' (@($rA.doc.findings).Count -eq 31)
# low severity on this fixture is exactly the two BR-06 rows, so the count is the
# proof that KNOWN rows are excluded from the severity histogram rather than the
# list - the report must not still show "2 low" for something the user owns.
Expect 'low severity count drops to 1' ([int]$rA.doc.severity_counts.low -eq 1)

# --- [8] persistence fixture: coverage a clean machine cannot give -------------
# On an uninfected box PS-03/04/05/06/08 legitimately hit zero - no early-launch
# driver, no hosts override, no IFEO, no LSP, no plaintext-credential task - which
# means a real scan never exercises them and a broken predicate would go unnoticed
# until the day one of them matters. The fixture fires all eight on purpose.
Write-Output ''
Write-Output '[8] persistence fixture: all 8 rules exercised, including the five that are idle on a clean box'
$sp = Join-Path $work 'store-p'
Run-Engine @{ Mode = 'baseline'; FactsFile = @($fxPers); StoreDir = $sp; OutFile = (Join-Path $work 'p0.json') }
$persBase = Load (Join-Path $work 'p0.json')
Check-Manifest $persBase $wantPers
$pf = Load $fxPers
$ents = @($pf.entries)
Expect ('fixture exposes one row per surface (15 subjects, ' + $ents.Count + ' entries)') ([int]$persBase.subjects_total -eq $ents.Count)
$psIds = @($persBase.findings | ForEach-Object { $_.rule_id } | Select-Object -Unique)
Expect ('all 8 persistence rules fire (' + ($psIds -join ',') + ')') ($psIds.Count -eq 8)

# The Microsoft-signer exclusion has to be asserted against a row that would
# otherwise be reported, or it proves nothing. On a real box this is Defender's
# own binary under C:\ProgramData; here it is a clone of that shape.
$MS = @('Microsoft Windows', 'Microsoft Windows Publisher', 'Microsoft Corporation')
$msWr = @($ents | Where-Object {
    $_.exe_exists -eq $true -and $_.in_writable -eq $true -and ($MS -contains [string]$_.signer)
} | ForEach-Object { PersSubject $_ })
Expect ('a Microsoft-signed writable resident exists in the fixture to exclude (' + $msWr.Count + ')') ($msWr.Count -gt 0)
Expect 'and it does not leak into PS-07' (@( @(SubjectSet $persBase 'PS-07') | Where-Object { $msWr -contains $_ }).Count -eq 0)

# High severity must come only from the hard surfaces - the four that break the
# boot/startup integrity plus PS-08's on-disk credential - not from residue or
# signature noise - that ordering is the report's whole prioritisation.
$hi = @($persBase.findings | Where-Object { $_.severity -eq 'high' } | ForEach-Object { $_.rule_id } | Select-Object -Unique)
Expect ('high severity rows are only PS-03/04/05/06/08 (' + ($hi -join ',') + ')') (SetEq $hi @('PS-03', 'PS-04', 'PS-05', 'PS-06', 'PS-08'))

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

# BR-08 has the same two-text structure driven by a different fact, and its filter
# is the one place where an over-broad match would print a stranger's domain next
# to an accusation. The fixture plants clean origins alongside dirty ones, so both
# directions are pinned: the branch has to differ, and no clean origin may appear
# in the evidence of any BR-08 row.
$b08sync = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-08' -and $_.subject -eq 'Edge / Default' } | ForEach-Object { [string]$_.advice })
$b08live = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-08' -and $_.subject -eq 'Edge / Profile 1' } | ForEach-Object { [string]$_.advice })
Expect 'BR-08 advice branches (grant-only profile vs still-hijacked profile)' ($b08sync[0] -ne $b08live[0])
$clean = @('www.google.com', 'www.bilibili.com', '10086.91.com', 'wustacm.cn')
$leakedClean = @()
foreach ($f in @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-08' })) {
    foreach ($g in @($f.evidence.perm_grants_bad)) {
        foreach ($c in $clean) { if (([string]$g) -like ('*' + $c + '*')) { $leakedClean += (([string]$f.subject) + ' -> ' + ([string]$g)) } }
    }
}
Expect ('BR-08 evidence contains only blocklisted origins (' + $leakedClean.Count + ' leaks)') ($leakedClean.Count -eq 0)
foreach ($l in $leakedClean) { Write-Output ('     ! ' + $l) }

# --- [13] the search provider is scoped to the protected document -------------
# default_search_provider_data only ever lives in Secure Preferences. If the
# engine ever fell back to the plain copy, Chrome / Profile 3 would report a
# readable engine it cannot possibly have, and BR-10 would stop telling the
# reader that this profile was only half examined. Both directions are pinned:
# the two subjects with a readable engine must NOT carry a blind spot.
Write-Output ''
Write-Output '[13] provider scoping: an unreadable engine is a blind spot, not a clean result'
$b09 = @(SubjectSet $browserBase 'BR-09')
Expect ('BR-09 fires on the two planted shapes only (' + ($b09 -join ', ') + ')') (SetEq $b09 @('Chrome / Default', 'Edge / Profile 2'))
$b10 = @(SubjectSet $browserBase 'BR-10')
Expect ('BR-10 fires on the three unreadable subjects (' + ($b10 -join ', ') + ')') (SetEq $b10 @('Chrome / Profile 3', 'Edge / Default', 'Edge / Profile 1'))
$readable = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-10' -and @('Chrome / Default', 'Edge / Profile 2') -contains [string]$_.subject })
Expect ('a readable-and-clean engine produces no blind spot (' + $readable.Count + ' false rows)') ($readable.Count -eq 0)
$p3 = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-10' -and $_.subject -eq 'Chrome / Profile 3' })
Expect 'the plain-only profile reports search_read=false even though its Preferences parsed' `
    (@($p3 | Where-Object { (-not [bool]$_.evidence.search_read) -and @($_.evidence.blind_spots).Count -eq 2 }).Count -eq 1)
# The two BR-09 triggers are different problems with different fixes, so their
# advice must differ - and neither may collapse onto the fallback text. The
# fallback is read out of rules/browser.json rather than repeated here, so
# rewording the advice cannot silently break the assertion or force a CJK
# literal into a .ps1 file that must stay ASCII.
$b09kw = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-09' -and $_.subject -eq 'Edge / Profile 2' } | ForEach-Object { [string]$_.advice })
$b09po = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-09' -and $_.subject -eq 'Chrome / Default' } | ForEach-Object { [string]$_.advice })
Expect 'BR-09 advice branches (blocklisted engine vs policy-enforced engine)' ($b09kw[0] -ne $b09po[0])
$br09Rule = @(Load (Join-Path $root 'rules\browser.json')).rules | Where-Object { $_.id -eq 'BR-09' }
$b09Fallback = [string]@($br09Rule.advice)[-1].text
$b09fb = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-09' -and [string]$_.advice -eq $b09Fallback })
Expect ('BR-09 never falls through to its fallback advice (' + $b09fb.Count + ' fell through)') ($b09fb.Count -eq 0)
# BR-10 is severity=info and must never be counted as a threat: an info row is a
# statement about the scan, and the severity histogram is what the reader trusts.
$b10sev = @($browserBase.findings | Where-Object { $_.rule_id -eq 'BR-10' -and $_.severity -ne 'info' })
Expect 'BR-10 rows are all info severity' ($b10sev.Count -eq 0)

# --- [14] live rules vs a predicate recomputed from the real capture ----------
# The expected hit set here is recomputed from the raw facts by independent
# filtering, not pasted from a snapshot. A machine that gains or loses autostart
# entries tomorrow therefore does not break this test, while a rule whose logic
# drifts from its stated predicate does.
Write-Output ''
Write-Output '[14] live persistence facts must agree with the same predicate recomputed from raw entries'
if (-not (Test-Path $realPers)) {
    Skip 'no out\facts-persistence.json on this box - run scan.bat first'
} else {
    $live = Load $realPers
    $lents = @($live.entries)
    Run-Engine @{ Mode = 'baseline'; FactsFile = @($fxBrowser, $realPers); StoreDir = (Join-Path $work 'store-live'); OutFile = (Join-Path $work 'live.json') }
    $ld = Load (Join-Path $work 'live.json')
    Expect ('subjects = fixture 23 + live persistence ' + $lents.Count) ([int]$ld.subjects_total -eq (23 + $lents.Count))

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

    # --- [15] residue claims must be real, not a PATH-resolution artifact -----
    # The first version of PS-01 also fired on a scheduled task running
    # `rasdial <connection> <user> <password>`. A bare command name is not a missing
    # file: CreateProcess resolves it against the PATH. Any row the engine calls a
    # residue is therefore re-confirmed absent here, so the rule cannot quietly
    # decay back into reporting healthy Windows commands as leftovers.
    Write-Output '[15] every live residue claim is independently re-confirmed absent'
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

# --- [16] the English overlay is wording, never a verdict --------------------
# The report is bilingual, and the design claim is that a translation cannot
# change what fires. That is only true if three things hold: the overlay is
# attached to every row, its advice list is indexed by the same branch the
# Chinese text came from, and nothing in the fingerprint reads it. A typo fixed
# in an English sentence must not turn 30 PERSIST rows into CHANGED - that would
# make the whole baseline diff lie about a documentation edit.
Write-Output ''
Write-Output '[16] the i18n.en overlay is attached, branch-aligned, and outside the fingerprint'
$noEn = @($both | Where-Object {
    (-not $_.i18n) -or (-not $_.i18n.en) -or
    [string]::IsNullOrWhiteSpace([string]$_.i18n.en.title) -or
    [string]::IsNullOrWhiteSpace([string]$_.i18n.en.why) -or
    [string]::IsNullOrWhiteSpace([string]$_.i18n.en.group_title)
})
Expect ('every finding carries an English title, why and group title (' + $noEn.Count + ' missing)') ($noEn.Count -eq 0)

# Asserted as a mapping, not a text comparison, because this file must stay ASCII
# and cannot quote either wording: for each rule, one Chinese branch must always
# yield the same English branch, and two different Chinese branches must never
# collapse onto one English string. Either failure is an overlay whose entries
# are out of order with the advice list they translate.
$branchBad = @()
foreach ($g in ($both | Group-Object rule_id)) {
    $fwd = @{}
    $rev = @{}
    foreach ($f in $g.Group) {
        $z = [string]$f.advice
        $e = [string]$f.i18n.en.advice
        if ($z -eq '' -or $e -eq '') { continue }
        if ($fwd.ContainsKey($z)) {
            if ($fwd[$z] -ne $e) { $branchBad += ($g.Name + ' one branch two translations') }
        } else { $fwd[$z] = $e }
        if ($rev.ContainsKey($e)) {
            if ($rev[$e] -ne $z) { $branchBad += ($g.Name + ' two branches one translation') }
        } else { $rev[$e] = $z }
    }
}
Expect ('English advice follows the same branch index as the Chinese (' + ($branchBad -join '; ') + ')') ($branchBad.Count -eq 0)
# A mapping test is vacuous on a rule whose fixtures only ever take one branch,
# so the coverage behind it is printed rather than assumed.
$multi = @(foreach ($g in ($both | Group-Object rule_id)) {
        $u = @($g.Group | ForEach-Object { [string]$_.advice } | Where-Object { $_ -ne '' } | Sort-Object -Unique)
        if ($u.Count -gt 1) { $g.Name }
    })
Write-Output ('     > rules whose fixtures take 2+ distinct advice branches: ' + ($multi -join ', '))
Expect 'the branch mapping is actually exercised (at least two rules take different branches)' ($multi.Count -ge 2)

# Load-time contract, run against a scratch copy of the engine and the rule files
# so the real rules/ directory is never touched.
function New-ScratchRoot([string]$name) {
    $dir = Join-Path $work $name
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'rules') | Out-Null
    Copy-Item $engine (Join-Path $dir 'engine.ps1') -Force
    Copy-Item (Join-Path $root 'rules\*.json') (Join-Path $dir 'rules') -Force
    return $dir
}
function Run-Scratch([string]$dir) {
    $res = @(& (Join-Path $dir 'engine.ps1') -Mode scan -FactsFile @($fxBrowser, $fxPers) `
        -StoreDir (Join-Path $dir 'store') -OutFile (Join-Path $dir 'f.json') 2>&1)
    return Load (Join-Path $dir 'f.json')
}

# Fingerprint invariance: change only the English wording, re-run, compare.
$dirA = New-ScratchRoot 'i16-pristine'
$dirB = New-ScratchRoot 'i16-retranslated'
foreach ($n in @(Get-ChildItem (Join-Path $dirB 'rules') -Filter *.json)) {
    $rj = Load $n.FullName
    $rj.i18n.en.group_title = ([string]$rj.i18n.en.group_title) + ' (revised)'
    foreach ($r in @($rj.rules)) {
        foreach ($slot in @('title', 'why', 'verified_evidence')) {
            $r.i18n.en.$slot = ([string]$r.i18n.en.$slot) + ' (revised)'
        }
        $r.i18n.en.advice = @(@($r.i18n.en.advice) | ForEach-Object { ([string]$_) + ' (revised)' })
    }
    Save $rj $n.FullName
}
$fpA = @(Run-Scratch $dirA)
$fpB = @(Run-Scratch $dirB)
$docA = $fpA[0]
$docB = $fpB[0]
$sigA = @($docA.findings | ForEach-Object { [string]$_.key + '=' + [string]$_.fingerprint } | Sort-Object)
$sigB = @($docB.findings | ForEach-Object { [string]$_.key + '=' + [string]$_.fingerprint } | Sort-Object)
Expect ('a retranslation produces the same findings (' + $docA.findings.Count + ' vs ' + $docB.findings.Count + ')') ($docA.findings.Count -eq $docB.findings.Count)
Expect ('and byte-identical fingerprints - wording is not evidence') (SetEq $sigA $sigB)
$changed = @()
foreach ($f in $docB.findings) {
    if ([string]$f.i18n.en.title -notmatch '\(revised\)') { $changed += [string]$f.rule_id }
}
Expect ('the perturbed copy really was perturbed (' + $changed.Count + ' rows left un-perturbed)') ($changed.Count -eq 0)

$dirC = New-ScratchRoot 'i16-no-overlay'
$cf = Join-Path $dirC 'rules\browser.json'
$cj = Load $cf
foreach ($r in @($cj.rules)) { if ([string]$r.id -eq 'BR-03') { $r.PSObject.Properties.Remove('i18n') } }
Save $cj $cf
$msgC = ''
try { Run-Scratch $dirC | Out-Null } catch { $msgC = [string]$_.Exception.Message }
Expect ('a rule with no i18n.en aborts the run rather than mixing languages (' + $msgC + ')') ($msgC -match 'no i18n.en wording')

$dirD = New-ScratchRoot 'i16-short-advice'
$df = Join-Path $dirD 'rules\browser.json'
$dj = Load $df
foreach ($r in @($dj.rules)) {
    if ([string]$r.id -eq 'BR-01') { $r.i18n.en.advice = @(@($r.i18n.en.advice) | Select-Object -Skip 1) }
}
Save $dj $df
$msgD = ''
try { Run-Scratch $dirD | Out-Null } catch { $msgD = [string]$_.Exception.Message }
Expect ('an overlay with fewer advice branches than the rule aborts the run (' + $msgD + ')') ($msgD -match 'i18n.en.advice has')

$dirE = New-ScratchRoot 'i16-no-group'
$ef = Join-Path $dirE 'rules\persistence.json'
$ej = Load $ef
$ej.i18n.en.PSObject.Properties.Remove('group_title')
Save $ej $ef
$msgE = ''
try { Run-Scratch $dirE | Out-Null } catch { $msgE = [string]$_.Exception.Message }
Expect ('a rule file with no English group title aborts the run (' + $msgE + ')') ($msgE -match 'no i18n.en.group_title')

Write-Output ''
Write-Output ('SELFTEST: ' + $pass + ' PASS, ' + $fail + ' FAIL, ' + $skip + ' SKIP')
if ($fail -gt 0) { exit 1 }
exit 0
