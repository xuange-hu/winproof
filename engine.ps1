param(
    [ValidateSet('scan', 'baseline', 'ack')]
    [string]$Mode = 'scan',
    [string]$AckKey = '',
    # Facts and store are injectable so the state machine can be exercised on
    # fixtures without ever touching a real baseline.
    [string[]]$FactsFile = @(),
    [string]$StoreDir = '',
    [string]$OutFile = ''
)
$ErrorActionPreference = 'Stop'

# WinProof evaluation engine.
#
# Layering, and why it is split this way:
#   probes   read-only fact capture, no judgement
#   rules    data (JSON), no code, no eval
#   engine   one small declarative predicate interpreter + baseline diff
#   report   static self-contained HTML, no server
# A rule file can come from a pull request or from an LLM without ever becoming
# executable input: conditions are an AST over a fixed operator set, so the
# injection surface of "add a rule" is zero and every rule stays statically
# checkable.

$root = $PSScriptRoot
$outDir = Join-Path $root 'out'
if ($StoreDir -eq '') { $StoreDir = Join-Path $root 'store' }
if ($OutFile -eq '') { $OutFile = Join-Path $outDir 'findings.json' }
$baselinePath = Join-Path $StoreDir 'baseline.json'
$knownPath = Join-Path $StoreDir 'known.json'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $StoreDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null

function Read-Json([string]$path) {
    $txt = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    return $txt | ConvertFrom-Json
}

function Write-Json($obj, [string]$path, [int]$depth = 8) {
    $json = $obj | ConvertTo-Json -Depth $depth
    [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding $false))
}

function As-Array($v) {
    if ($null -eq $v) { return @() }
    if ($v -is [System.Array]) { return @($v) }
    return @($v)
}

function Hash16([string]$s) {
    $alg = [Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes($s)
    $full = $alg.ComputeHash($bytes)
    $hex = [BitConverter]::ToString($full).Replace('-', '')
    return $hex.Substring(0, 16)
}

# --- predicate interpreter ---------------------------------------------------
# Supported facts are plain scalars and string arrays taken from a subject.
# Fields are read through helpers because a clause can arrive either as a
# PSCustomObject (from JSON) or as a hashtable (from an internal recursion),
# and property probing on a hashtable silently reports the wrong names.

function Has-Field($obj, [string]$name) {
    if ($null -eq $obj) { return $false }
    if ($obj -is [System.Collections.IDictionary]) { return $obj.Contains($name) }
    return ($obj.PSObject.Properties.Name -contains $name)
}

function Get-Field($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) {
        if ($obj.Contains($name)) { return $obj[$name] }
        return $null
    }
    if ($obj.PSObject.Properties.Name -contains $name) { return $obj.$name }
    return $null
}

function Test-Clause($clause, $subject) {
    if ($null -eq $clause) { return $false }

    if (Has-Field $clause 'all') {
        foreach ($c in As-Array (Get-Field $clause 'all')) {
            if (-not (Test-Clause $c $subject)) { return $false }
        }
        return $true
    }
    if (Has-Field $clause 'any') {
        foreach ($c in As-Array (Get-Field $clause 'any')) {
            if (Test-Clause $c $subject) { return $true }
        }
        return $false
    }

    $fact = [string](Get-Field $clause 'fact')
    $op = [string](Get-Field $clause 'op')
    if ([string]::IsNullOrEmpty($fact)) { return $false }
    if (-not $subject.Contains($fact)) { return $false }
    $v = $subject[$fact]
    $want = Get-Field $clause 'value'

    switch ($op) {
        'eq' {
            if ($v -is [System.Array]) {
                return (@(As-Array $v | ForEach-Object { [string]$_ }) -contains [string]$want)
            }
            if ($v -is [bool]) {
                if ($want -is [bool]) { return ($v -eq $want) }
                $ws = [string]$want
                return ($v -eq ($ws -eq 'True'))
            }
            return (([string]$v) -eq ([string]$want))
        }
        'ne' { return (-not (Test-Clause @{ fact = $fact; op = 'eq'; value = $want } $subject)) }
        'nonEmpty' {
            if ($v -is [System.Array]) { return (@(As-Array $v).Count -gt 0) }
            if ($v -is [bool]) { return $v }
            if ($null -eq $v) { return $false }
            return (-not [string]::IsNullOrWhiteSpace([string]$v))
        }
        'isEmpty' { return (-not (Test-Clause @{ fact = $fact; op = 'nonEmpty' } $subject)) }
        'hasAny' {
            $list = As-Array $want
            foreach ($item in As-Array $v) {
                $s = [string]$item
                foreach ($w in $list) { if ($s -like $w) { return $true } }
            }
            return $false
        }
        'countGte' {
            # "at least N": an array is measured by length, a scalar by its own
            # numeric value. Without this split a count fact such as
            # host_effective=0 would read as a one-element list and report true.
            if ($v -is [System.Array]) { return (@(As-Array $v).Count -ge [int]$want) }
            if ($v -is [bool]) { return $([int]$v -ge [int]$want) }
            $n = 0
            if (-not [int]::TryParse([string]$v, [ref]$n)) { return $false }
            return ($n -ge [int]$want)
        }
        'in' {
            $list = As-Array $want | ForEach-Object { [string]$_ }
            foreach ($item in As-Array $v) { if ($list -contains [string]$item) { return $true } }
            return $false
        }
        'notIn' {
            $list = As-Array $want | ForEach-Object { [string]$_ }
            foreach ($item in As-Array $v) { if ($list -contains [string]$item) { return $false } }
            return $true
        }
        default { throw ("unsupported operator: " + $op) }
    }
}

# --- fact normalisation ------------------------------------------------------
# One subject per browser profile, merging the two documents it is spread over.
# Secure Preferences holds the hijacked value; Preferences holds sync state and
# exit state. Neither file alone answers "will editing this file stick".

function Get-BadUrls($urls, $blocklist) {
    $bad = @()
    foreach ($u in As-Array $urls) {
        $s = [string]$u
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        foreach ($b in $blocklist) {
            if ($s.ToLower().Contains([string]$b.ToLower())) { $bad += $s; break }
        }
    }
    return @($bad | Select-Object -Unique)
}

# Content setting rows arrive as "setting|origin|written". Matching has to look at
# the origin field only: a blocklist token may legally appear in a setting name,
# and the port/pattern suffix carries no reputation.
function Get-BadGrants($grants, $blocklist) {
    $bad = @()
    foreach ($g in As-Array $grants) {
        $parts = ([string]$g) -split '\|'
        if ($parts.Count -lt 2) { continue }
        $origin = [string]$parts[1]
        if ([string]::IsNullOrWhiteSpace($origin)) { continue }
        foreach ($b in $blocklist) {
            if ($origin.ToLower().Contains([string]$b.ToLower())) { $bad += ([string]$g); break }
        }
    }
    return @($bad | Select-Object -Unique)
}

function New-BrowserSubjects($facts, $blocklist) {
    $byProfile = @{}
    foreach ($f in As-Array $facts.files) {
        $key = [string]$f.brand + '/' + [string]$f.profile
        if (-not $byProfile.ContainsKey($key)) { $byProfile[$key] = @() }
        $byProfile[$key] += $f
    }

    $subjects = @()
    foreach ($key in ($byProfile.Keys | Sort-Object)) {
        $docs = $byProfile[$key]
        $secure = $docs | Where-Object { [string]$_.doc -eq 'Secure Preferences' } | Select-Object -First 1
        $plain = $docs | Where-Object { [string]$_.doc -eq 'Preferences' } | Select-Object -First 1
        $anchor = $secure
        if ($null -eq $anchor) { $anchor = $plain }
        if ($null -eq $anchor) { continue }

        $s = @{}
        $s['brand'] = [string]$anchor.brand
        $s['profile'] = [string]$anchor.profile
        $s['subject'] = [string]$anchor.brand + ' / ' + [string]$anchor.profile
        $s['doc_role'] = 'secure'
        if ($null -eq $secure) { $s['doc_role'] = 'plain_only' }

        # Startup values come from the anchor: Secure Preferences when it exists,
        # otherwise the plain Preferences. Reading them only from the secure copy
        # silently dropped a profile that has no Secure Preferences at all - a
        # hijacked session.startup_urls in a plain-only document reported nothing.
        $urls = As-Array $anchor.startup_urls
        $mode = $anchor.startup_mode
        $bytes = [int]$anchor.bytes
        $mtime = [string]$anchor.mtime
        $path = [string]$anchor.path
        $backups = As-Array $anchor.backups

        # Seals and signatures stay scoped to the secure document on purpose:
        # protection.macs and the *_edge_enclave key family only exist there, so a
        # plain-only profile cannot invent sealed-copy findings.
        $seals = @()
        $orphans = @()
        $macs = @()
        if ($null -ne $secure) {
            $seals = As-Array $secure.seal_keys
            $orphans = As-Array $secure.orphan_sigs
            $macs = As-Array $secure.macs_session
        }

        $s['startup_urls'] = $urls
        $s['startup_urls_bad'] = Get-BadUrls $urls $blocklist
        $s['startup_mode'] = $mode
        $s['seal_keys'] = $seals
        $s['seal_enclave'] = @($seals | Where-Object { $_ -match 'enclave' })
        $s['seal_lightweight'] = @($seals | Where-Object { $_ -match 'lightweight' })
        $s['orphan_sigs'] = $orphans
        $s['macs_session'] = $macs
        $s['bytes'] = $bytes
        $s['mtime'] = $mtime
        $s['path'] = $path
        $s['backups'] = $backups
        $s['has_repair_backup'] = (@($backups).Count -gt 0)

        # cross-document facts: sync and exit state live in the other file
        $syncOn = $false
        $exitType = ''
        $grants = @()
        $gTotal = 0
        foreach ($d in $docs) {
            if ($d.sync_prefs) { $syncOn = $true }
            if ([string]$d.exit_type -eq 'Crashed') { $exitType = 'Crashed' }
            if ([string]::IsNullOrEmpty($exitType)) { $exitType = [string]$d.exit_type }
            foreach ($b in As-Array $d.backups) {
                if (-not ($backups | Where-Object { $_.name -eq $b.name })) { $backups += $b }
            }
            # Content setting exceptions are stored in the plain Preferences, the
            # file that has no signed copy and no hijacked startup value. Merging
            # them into the same subject is what lets one card say "the config is
            # clean and the browser still remembers loading that origin".
            foreach ($g in As-Array $d.perm_grants) {
                if (-not ($grants -contains [string]$g)) { $grants += [string]$g }
            }
            $gTotal += [int]$d.perm_keys_total
        }
        $s['sync_preferences_enabled'] = $syncOn
        $s['exit_type'] = $exitType
        $s['backups'] = $backups
        $s['perm_total_keys'] = $gTotal
        $s['perm_grants_bad'] = Get-BadGrants $grants $blocklist
        $s['perm_bad_settings'] = @($s['perm_grants_bad'] | ForEach-Object { ([string]$_ -split '\|')[0] } | Select-Object -Unique)

        # Default search provider. `default_search_provider_data` is one of
        # Chromium's protected preferences and only ever lands in Secure
        # Preferences, so - like the seal and signature families above - it is
        # scoped to that document. Falling back to the plain copy would let a
        # profile that has no Secure Preferences claim a readable engine it could
        # not actually have.
        if ($null -eq $secure) {
            $s['search_read'] = $false
            $s['search_keyword'] = ''
            $s['search_name'] = ''
            $s['search_url'] = ''
            $s['search_policy'] = $false
            $s['search_bad'] = @()
        } else {
            $s['search_read'] = [bool]$secure.search_read
            $s['search_keyword'] = [string]$secure.search_keyword
            $s['search_name'] = [string]$secure.search_name
            $s['search_url'] = [string]$secure.search_url
            $s['search_policy'] = [bool]$secure.search_policy
            $s['search_bad'] = Get-BadUrls @(
                $s['search_keyword'], $s['search_name'], $s['search_url'],
                [string]$secure.search_from) $blocklist
        }

        # What this tool could not see on this subject. A scan that reports
        # "nothing found" and one that "could not look" are different statements,
        # and only the second makes a clean result mean something. Codes, not
        # sentences: the .ps1 layer must stay ASCII (PowerShell 5.1 decodes a
        # BOM-less script with the active code page, so a Chinese literal here
        # would survive on this machine and break on another one), and the
        # rendering table in the template owns the wording.
        $blind = @()
        if ($s['doc_role'] -eq 'plain_only') { $blind += 'no_secure_prefs' }
        if (-not $s['search_read']) { $blind += 'engine_unreadable' }
        if ($null -ne $secure -and -not [bool]$secure.parse_ok) { $blind += 'prefs_unparseable' }
        $s['blind_spots'] = @($blind)

        # recurrence: a repair backup that already contained a bad URL, and the
        # live file still containing one, with the live file newer than the backup
        $regrew = $false
        if ($s['startup_urls_bad'].Count -gt 0 -and @($backups).Count -gt 0) {
            $live = [datetime]::MinValue
            if ($mtime -ne '') { $live = [datetime]::Parse($mtime) }
            foreach ($b in $backups) {
                $bt = [datetime]::Parse([string]$b.mtime)
                $bBad = Get-BadUrls (As-Array $b.urls) $blocklist
                if ($bBad.Count -gt 0 -and $live -gt $bt) { $regrew = $true }
            }
        }
        $s['regrew_after_repair'] = $regrew

        # the mirror case: repaired and it stayed repaired
        $held = $false
        if ($s['startup_urls_bad'].Count -eq 0 -and @($backups).Count -gt 0) {
            foreach ($b in $backups) {
                $bBad = Get-BadUrls (As-Array $b.urls) $blocklist
                if ($bBad.Count -gt 0) { $held = $true }
            }
        }
        $s['repair_held'] = $held

        $subjects += $s
    }
    return $subjects
}

# Persistence entries arrive already flat: one row per autostart surface, each
# row a complete subject. The work here is only shape conversion, because the
# predicate interpreter reads subjects as hashtables.
function New-PersistenceSubjects($facts) {
    $subjects = @()
    foreach ($e in As-Array $facts.entries) {
        if ($null -eq $e) { continue }
        $s = @{}
        foreach ($p in $e.PSObject.Properties) { $s[$p.Name] = $p.Value }
        $s['subject'] = [string]$e.kind + ' / ' + [string]$e.name
        # Findings point the reader at the cheapest place to look. For browsers
        # that is the prefs file; for autostart it is the registry key or task path.
        if (-not $s.ContainsKey('path') -or [string]::IsNullOrEmpty([string]$s['path'])) {
            $s['path'] = [string]$e.location
        }
        $subjects += $s
    }
    return $subjects
}

# --- load rules --------------------------------------------------------------

$ruleFiles = @(Get-ChildItem (Join-Path $root 'rules\*.json') -ErrorAction SilentlyContinue)
if ($ruleFiles.Count -eq 0) { throw 'no rule files under rules/' }

$allRules = @()
$blocklist = @()
$groups = @{}
foreach ($rf in $ruleFiles) {
    $doc = Read-Json $rf.FullName
    $blocklist += As-Array $doc.domain_blocklist
    $groups[[string]$doc.group] = [string]$doc.group_title
    foreach ($r in As-Array $doc.rules) {
        # Parentheses matter: in argument mode a bare `[string]$doc.group` is not
        # an expression - PowerShell takes `[string]` as a literal token and the
        # value becomes the string "[string]@{...}.group", which then misses every
        # later hashtable lookup. This silently blanked the group title in reports.
        Add-Member -InputObject $r -MemberType NoteProperty -Name '_group' -Value ([string]$doc.group) -Force
        $allRules += $r
    }
}
$blocklist = @($blocklist | Where-Object { $_ -ne '' } | Select-Object -Unique)

# --- gather subjects from every probe that has run ---------------------------
# The facts directory is globbed rather than hardcoded to one file: a scan that
# ran two probes must evaluate both, and "which probes have run" is decided by
# what is on disk, not by a list someone has to remember to update.

$subjects = @()
if ($FactsFile.Count -eq 0) {
    $FactsFile = @( @(Get-ChildItem (Join-Path $outDir 'facts-*.json') -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object { $_.FullName }) )
}
$probeLog = @()
foreach ($fp in $FactsFile) {
    if (-not (Test-Path $fp)) { continue }
    $fb = Read-Json $fp
    $pname = [string]$fb.probe
    switch ($pname) {
        'browser_prefs' { $subjects += New-BrowserSubjects $fb $blocklist }
        'persistence' { $subjects += New-PersistenceSubjects $fb }
        default { throw ('unknown probe: ' + $pname + ' (' + $fp + ')') }
    }
    $probeLog += $pname
}

# --- evaluate ----------------------------------------------------------------

$findings = @()
foreach ($s in $subjects) {
    foreach ($r in $allRules) {
        if (-not (Test-Clause $r.when $s)) { continue }

        $advice = ''
        foreach ($a in As-Array $r.advice) {
            if (Has-Field $a 'if') {
                if (Test-Clause (Get-Field $a 'if') $s) { $advice = [string](Get-Field $a 'text'); break }
            }
        }
        if ($advice -eq '') {
            foreach ($a in As-Array $r.advice) {
                if (Has-Field $a 'if_any') { $advice = [string](Get-Field $a 'text'); break }
            }
        }

        # Evidence is serialised to compact JSON rather than stringified, so an
        # array of objects (repair backups, seal key families) still contributes
        # to the fingerprint. PSCustomObject.ToString() yields an empty string,
        # which would silently freeze the fingerprint while real facts change.
        $ev = [ordered]@{}
        foreach ($name in As-Array $r.show) {
            if ($s.Contains($name)) { $ev[$name] = $s[$name] }
        }
        $pairs = @()
        foreach ($kv in $ev.GetEnumerator()) {
            $pairs += ([string]$kv.Key + '=' + ($kv.Value | ConvertTo-Json -Depth 6 -Compress))
        }
        $evText = $pairs -join '~'
        $key = [string]$r.id + '|' + [string]$s['subject']

        $findings += [pscustomobject]@{
            rule_id     = [string]$r.id
            title       = [string]$r.title
            severity    = [string]$r.severity
            group       = [string]$r._group
            group_title = [string]$groups[[string]$r._group]
            subject     = [string]$s['subject']
            key         = $key
            fingerprint = (Hash16 ($key + '|' + $evText))
            evidence    = [pscustomobject]$ev
            advice      = $advice
            why         = [string]$r.why
            verified_on = [string]$r.verified_on
            verified_evidence = [string]$r.verified_evidence
            detail_path = [string]$s['path']
        }
    }
}

# --- baseline diff -----------------------------------------------------------

$baseline = $null
$baselineAt = ''
if (Test-Path $baselinePath) {
    $baseline = Read-Json $baselinePath
    $baselineAt = [string]$baseline.captured_at
}

$known = @()
if (Test-Path $knownPath) {
    $k = Read-Json $knownPath
    $known = As-Array $k.keys
}
if ($Mode -eq 'ack') {
    if ($AckKey -eq '') { throw 'ack mode needs -AckKey <finding key>' }
    $known += $AckKey
    $known = @($known | Select-Object -Unique)
    Write-Json @{ updated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); keys = $known } $knownPath
    Write-Output ('acknowledged: ' + $AckKey)
    exit 0
}

$baseMap = @{}
if ($null -ne $baseline) {
    foreach ($b in As-Array $baseline.findings) { $baseMap[[string]$b.key] = $b }
}

$enriched = @()
foreach ($f in $findings) {
    $state = 'NEW'
    if ($baselineAt -eq '') {
        $state = 'UNBASELINED'
    } elseif ($baseMap.ContainsKey($f.key)) {
        if ([string]$baseMap[$f.key].fingerprint -eq $f.fingerprint) { $state = 'PERSIST' }
        else { $state = 'CHANGED' }
    }
    if ($state -ne 'UNBASELINED' -and ($known -contains $f.key)) { $state = 'KNOWN' }
    Add-Member -InputObject $f -MemberType NoteProperty -Name 'state' -Value $state -Force
    $enriched += $f
}

$resolved = @()
if ($null -ne $baseline) {
    $nowKeys = @($findings | ForEach-Object { $_.key })
    foreach ($b in As-Array $baseline.findings) {
        if (-not ($nowKeys -contains [string]$b.key)) {
            $resolved += [pscustomobject]@{
                key      = [string]$b.key
                rule_id  = [string]$b.rule_id
                title    = [string]$b.title
                subject  = [string]$b.subject
                severity = [string]$b.severity
                since    = [string]$baselineAt
            }
        }
    }
}

$order = @{ high = 0; medium = 1; low = 2; info = 3; good = 4 }
$sorted = @($enriched | Sort-Object @{ Expression = { if ($order.ContainsKey($_.severity)) { $order[$_.severity] } else { 9 } } }, @{ Expression = { $_.rule_id } })

$counts = [ordered]@{}
foreach ($st in @('NEW', 'CHANGED', 'PERSIST', 'KNOWN', 'UNBASELINED')) {
    $counts[$st] = @($sorted | Where-Object { $_.state -eq $st }).Count
}
$counts['RESOLVED'] = @($resolved).Count

$severityCounts = [ordered]@{}
foreach ($sv in @('high', 'medium', 'low', 'info', 'good')) {
    $severityCounts[$sv] = @($sorted | Where-Object { $_.severity -eq $sv -and $_.state -ne 'KNOWN' }).Count
}

$payload = [ordered]@{
    schema          = 'winproof/1'
    scanned_at      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    computer        = $env:COMPUTERNAME
    user            = $env:USERNAME
    os_version      = [Environment]::OSVersion.Version.ToString()
    ps_version      = $PSVersionTable.PSVersion.ToString()
    baseline_at     = $baselineAt
    probes_run      = @($probeLog | Select-Object -Unique)
    rules_total     = $allRules.Count
    subjects_total  = $subjects.Count
    domain_blocklist = @($blocklist)
    counts          = $counts
    severity_counts = $severityCounts
    findings        = @($sorted)
    resolved        = @($resolved)
}

if ($Mode -eq 'baseline') {
    $bp = [ordered]@{
        captured_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        computer    = $env:COMPUTERNAME
        findings    = @($findings | ForEach-Object {
            [pscustomobject]@{ key = $_.key; rule_id = $_.rule_id; title = $_.title; subject = $_.subject; severity = $_.severity; fingerprint = $_.fingerprint }
        })
    }
    Write-Json $bp $baselinePath 8
    Write-Output ('baseline written: ' + @($findings).Count + ' findings -> ' + $baselinePath)
}

Write-Json ([pscustomobject]$payload) $OutFile 10

$high = @($sorted | Where-Object { $_.severity -eq 'high' -and $_.state -ne 'KNOWN' }).Count
Write-Output ('engine: subjects=' + $subjects.Count + ' rules=' + $allRules.Count + ' findings=' + $sorted.Count + ' high=' + $high + ' resolved=' + @($resolved).Count + ' baseline=' + $(if ($baselineAt -eq '') { 'none' } else { $baselineAt }))
