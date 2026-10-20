param(
    [string]$OutFile = ''
)
$ErrorActionPreference = 'Continue'

# Browser preference probe. Read only: never writes to a browser profile.
# It records facts (values, key inventories, signatures, timeline) and judges
# nothing - the engine applies rules so one rule change needs no re-scan.

$roots = @(
    @{ Brand = 'Edge'; Root = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
    @{ Brand = 'Chrome'; Root = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') }
)

# Sealed-copy key families observed on this machine. Edge keeps a second, signed
# copy of the same value here, so a plaintext-only edit can be reverted by the
# browser itself. The two spellings differ per profile (enclave vs lightweight).
$SEAL_RE = '_(edge_enclave|edge_lightweight)(_verify)?$'
$HIST_RE = '^(startup_urls|restore_on_startup|homepage)(_encrypted_hash)?$'

function Get-FileFacts($path, $brand, $profile, $doc) {
    $itm = Get-Item $path -Force
    $raw = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)

    $f = [ordered]@{
        brand          = $brand
        profile        = $profile
        doc            = $doc
        path           = $path
        bytes          = [int]$itm.Length
        mtime          = $itm.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        ctime          = $itm.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        parse_ok       = $true
        startup_mode   = $null
        startup_urls   = @()
        session_keys   = @()
        seal_keys      = @()
        macs_session   = @()
        orphan_sigs    = @()
        sync_prefs     = $false
        sync_keys      = @()
        backups        = @()
        exit_type      = ''
        search_read    = $false
        search_keyword = ''
        search_name    = ''
        search_url     = ''
        search_from    = ''
        search_policy  = $false
        homepage       = ''
        perm_grants    = @()
        perm_keys_total = 0
        perm_settings  = 0
    }

    $j = $null
    try { $j = $raw | ConvertFrom-Json } catch { $f.parse_ok = $false }
    if (-not $j) {
        $f.parse_ok = $false
        return [pscustomobject]$f
    }

    # --- session block -------------------------------------------------------
    if ($j.session) {
        $f.session_keys = @($j.session.PSObject.Properties.Name | Sort-Object)
        $f.startup_urls = @($j.session.startup_urls)
        if ($null -ne $j.session.restore_on_startup) {
            $f.startup_mode = [int]$j.session.restore_on_startup
        }
        $f.seal_keys = @($f.session_keys | Where-Object { $_ -match $SEAL_RE })
    }

    # --- signatures: proof of what the browser itself considered signed -------
    if ($j.protection -and $j.protection.macs -and $j.protection.macs.session) {
        $f.macs_session = @($j.protection.macs.session.PSObject.Properties.Name | Sort-Object)
        # A signature for a value that is no longer in session means the value
        # was once present and removed. This is residue, not an active hijack.
        $plain = @('startup_urls', 'restore_on_startup')
        $present = @($f.session_keys | Where-Object { $plain -contains $_ })
        $f.orphan_sigs = @($f.macs_session |
            Where-Object { ($plain -contains $_) -and (-not ($present -contains $_)) })
    }

    # --- sync: decides whether a local file edit can be reverted by the cloud --
    if ($j.sync) {
        $f.sync_keys = @($j.sync.PSObject.Properties.Name | Sort-Object)
        $f.sync_prefs = [bool]($f.sync_keys -contains 'preferences')
    }

    # --- repair timeline: backups left by earlier fixes -----------------------
    # Reading the backup's own startup_urls turns "it came back" from a guess
    # based on timestamps into a closed loop: the backup proves the value was
    # there before the repair, the live file proves it is there again after it.
    foreach ($b in @(Get-ChildItem ($path + '.bak_*') -Force -ErrorAction SilentlyContinue)) {
        $bUrls = @()
        try {
            $bRaw = [IO.File]::ReadAllText($b.FullName, [Text.Encoding]::UTF8)
            foreach ($x in [regex]::Matches($bRaw, '"startup_urls"\s*:\s*\[[^\]]*\]')) {
                foreach ($y in [regex]::Matches($x.Value, 'https?://[^"\s]+')) { $bUrls += $y.Value }
            }
        } catch { }
        $f.backups += [pscustomobject]@{
            name  = $b.Name
            bytes = [int]$b.Length
            mtime = $b.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            urls  = @($bUrls | Select-Object -Unique)
        }
    }

    # --- last exit state: 'Normal' means the browser rewrote this file itself --
    if ($j.profile) {
        if ($j.profile.exit_type) { $f.exit_type = [string]$j.profile.exit_type }
    }

    # --- default search provider ----------------------------------------------
    # Chromium stores the *selected* engine under
    # default_search_provider_data.template_url_data in Secure Preferences. For a
    # prepopulated engine every URL is a `{google:baseURL}` placeholder, so the
    # only stable identifier is `keyword` (a bare domain) plus `short_name`; a
    # hijacked engine is not prepopulated and therefore carries a literal
    # `search_url`. Both are read because they cover different cases.
    #
    # Edge replaces this node with a SHA hash plus an `_encrypted_hash`, so on
    # Edge the selected engine cannot be recovered from the prefs at all. That is
    # recorded as search_read=false rather than as a clean result: an unreadable
    # surface is a blind spot, not evidence of absence.
    $td = $null
    if ($j.default_search_provider_data) {
        $td = $j.default_search_provider_data.template_url_data
    }
    if ($td -and -not ($td -is [string])) {
        $f.search_read = $true
        $names = @($td.PSObject.Properties.Name)
        foreach ($pair in @(@('keyword', 'search_keyword'), @('short_name', 'search_name'),
                            @('search_url', 'search_url'), @('template_url', 'search_url'),
                            @('originating_url', 'search_from'))) {
            if (-not ($names -contains $pair[0])) { continue }
            $v = [string]$td.($pair[0])
            if ($v -ne '' -and [string]$f[$pair[1]] -eq '') { $f[$pair[1]] = $v }
        }
        if ($names -contains 'enforced_by_policy') { $f.search_policy = [bool]$td.enforced_by_policy }
    }

    if ($j.homepage) { $f.homepage = [string]$j.homepage }

    # --- content setting exceptions ------------------------------------------
    # This table is the browser's own record of which origins it actually loaded
    # and what it decided to allow them, so it answers a question the startup
    # value cannot: a hijacked URL in session.startup_urls only proves the
    # configuration, a grant here proves the page was reached. Keys are
    # "<scheme>://<host>:<port>,*", one entry per setting type.
    #
    # Everything is captured, no filtering by reputation: the probe does not know
    # the blocklist and must not decide what is suspicious. Each row is
    # "setting|origin|last_written_local" because Chrome/Edge store the write
    # time as WebKit microseconds (100 ns ticks since 1601-01-01 UTC) and a
    # timeline is only readable once converted.
    $cs = $null
    if ($j.profile -and $j.profile.content_settings -and $j.profile.content_settings.exceptions) {
        $cs = $j.profile.content_settings.exceptions
    }
    if ($null -ne $cs) {
        $epUtc = [datetime]::SpecifyKind([datetime]'1601-01-01 00:00:00', [datetimekind]::Utc)
        foreach ($sname in @($cs.PSObject.Properties.Name | Sort-Object)) {
            $node = $cs.$sname
            if ($null -eq $node) { continue }
            $keys = @($node.PSObject.Properties.Name)
            if ($keys.Count -eq 0) { continue }
            $f.perm_settings += 1
            foreach ($k in $keys) {
                if ($null -eq $k) { continue }
                $ks = [string]$k
                if ($ks -eq '') { continue }
                $f.perm_keys_total += 1
                $written = ''
                $lm = ''
                try { $lm = [string]$node.$ks.last_modified } catch { $lm = '' }
                if ($lm -match '^\d{8,}$') {
                    try {
                        $written = $epUtc.AddSeconds(([double]$lm / 1000000.0)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
                    } catch { $written = '' }
                }
                $f.perm_grants += ($sname + '|' + $ks + '|' + $written)
            }
        }
        $f.perm_grants = @($f.perm_grants | Sort-Object)
    }

    return [pscustomobject]$f
}

$all = @()
$missing = @()

foreach ($r in $roots) {
    if (-not (Test-Path $r.Root)) { $missing += $r.Root; continue }
    foreach ($prof in @(Get-ChildItem $r.Root -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($doc in @('Secure Preferences', 'Preferences')) {
            $fp = Join-Path $prof.FullName $doc
            if (-not (Test-Path $fp)) { continue }
            $all += Get-FileFacts $fp $r.Brand $prof.Name $doc
        }
    }
}

# --- browser shortcut launch arguments ----------------------------------------
# A hijacker that survives profile cleaning usually does NOT live in the profile:
# it rewrites the .lnk so the shortcut launches the browser with a start URL
# appended after the exe path. Every time the user opens the browser from that
# icon the page loads again and the profile value is re-created, which is exactly
# the "I cleaned it and it came back" loop. This is a machine-level surface, not
# per profile, and no profile cleaner inspects it. Read only: CreateShortcut does
# not write, and WScript.Shell is a standard Windows component.
$shortcutRoots = @(
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'),
    (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
)
# Only browser executables are collected. The reputation decision is left to the
# engine: the probe records the launch URL verbatim and never matches a blocklist,
# because it must not decide what is suspicious. PWA/app hosts (msedge_proxy.exe,
# chrome.exe --app-id=) are included deliberately - an app shortcut pointed at a
# blacklisted origin is still a hijack, and a benign one simply will not match.
$BROWSER_RX = '(?i)(chrome|msedge|firefox|brave|opera|vivaldi|edge|360se|360chrome|qqbrowser|sogouexplorer|2345explorer|2345chrome|maxthon|ucbrowser|liebao)([a-z0-9_\-]*)\.exe$'
$shortcuts = @()
$wsh = $null
try { $wsh = New-Object -ComObject WScript.Shell } catch { $wsh = $null }
if ($null -ne $wsh) {
    foreach ($sr in $shortcutRoots) {
        if (-not (Test-Path $sr)) { continue }
        foreach ($lnk in @(Get-ChildItem -Path $sr -Filter *.lnk -Recurse -ErrorAction SilentlyContinue)) {
            $sc = $null
            try { $sc = $wsh.CreateShortcut($lnk.FullName) } catch { continue }
            $tp = [string]$sc.TargetPath
            $ar = [string]$sc.Arguments
            if ($tp -notmatch $BROWSER_RX) { continue }
            $urls = @()
            foreach ($m in [regex]::Matches($ar, 'https?://[^\s"' + [char]39 + '<>]+')) { $urls += $m.Value }
            $urls = @($urls | Select-Object -Unique)
            $shortcuts += [pscustomobject]@{
                name       = $lnk.Name
                path       = $lnk.FullName
                target_exe = [IO.Path]::GetFileName($tp)
                args       = $ar
                urls       = $urls
            }
        }
    }
}

$payload = [ordered]@{
    probe           = 'browser_prefs'
    captured_at     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    computer        = $env:COMPUTERNAME
    user            = $env:USERNAME
    files           = $all
    shortcuts       = $shortcuts
    missing_roots   = @($missing)
}

$json = $payload | ConvertTo-Json -Depth 8
if ($OutFile -eq '') {
    $OutFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'out\facts-browser.json'
}
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding $false))
$gAll = 0
$gRead = 0
foreach ($x in $all) { $gAll += [int]$x.perm_keys_total; if ($x.search_read) { $gRead += 1 } }
Write-Output ('browser_prefs: files=' + $all.Count + ' shortcuts=' + $shortcuts.Count + ' missing_roots=' + $missing.Count +
    ' perm_grants=' + $gAll + ' search_read=' + $gRead + ' -> ' + $OutFile)
