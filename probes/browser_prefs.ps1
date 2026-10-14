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
        search_urls    = @()
        homepage       = ''
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

    # --- search engine + homepage (same hijack family, facts only) ------------
    $m = [regex]::Matches($raw, '"(search_url|template_url)"\s*:\s*"([^"]{0,160})"')
    foreach ($x in $m) { $f.search_urls += [pscustomobject]@{ field = $x.Groups[1].Value; value = $x.Groups[2].Value } }
    $f.search_urls = @($f.search_urls | Select-Object -First 12)

    if ($j.homepage) { $f.homepage = [string]$j.homepage }

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

$payload = [ordered]@{
    probe           = 'browser_prefs'
    captured_at     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    computer        = $env:COMPUTERNAME
    user            = $env:USERNAME
    files           = $all
    missing_roots   = @($missing)
}

$json = $payload | ConvertTo-Json -Depth 8
if ($OutFile -eq '') {
    $OutFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'out\facts-browser.json'
}
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding $false))
Write-Output ('browser_prefs: files=' + $all.Count + ' missing_roots=' + $missing.Count + ' -> ' + $OutFile)
