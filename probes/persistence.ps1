param(
    [string]$OutFile = ''
)
$ErrorActionPreference = 'Continue'

# Persistence probe. Read only: enumerates the autostart surfaces a program can
# use to survive a reboot, and for each one records who signed the target binary.
#
# Why signing data instead of a vendor keyword list: a keyword list only ever
# catches the vendors somebody already wrote down. "this auto-starting binary is
# not signed by the OS vendor" catches whatever is on your machine instead.

$signCache = @{}

function Test-Target([string]$p, [switch]$Leaf) {
    # Registry values routinely hold command strings with embedded quotes or
    # characters that are illegal in a path, and Test-Path then throws an
    # ArgumentException rather than returning false - seen on a GitHub-hosted
    # runner, where it printed a red error mid-probe. A missing target must
    # degrade to "not found", never to noise on stderr.
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    try {
        if ($Leaf) { return [bool](Test-Path -LiteralPath $p -PathType Leaf -ErrorAction Stop) }
        return [bool](Test-Path -LiteralPath $p -ErrorAction Stop)
    } catch { return $false }
}

function Get-SignInfo([string]$exe) {
    if ([string]::IsNullOrWhiteSpace($exe)) { return $null }
    if ($signCache.ContainsKey($exe)) { return $signCache[$exe] }
    $r = [ordered]@{ exists = $false; signer = ''; status = ''; subject = '' }
    try {
        if (Test-Target $exe) {
            $r['exists'] = $true
            $sig = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction SilentlyContinue
            $r['status'] = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $r['subject'] = [string]$sig.SignerCertificate.Subject
                # Subject is like CN=Microsoft Windows,O=Microsoft Corporation,...
                # A CN containing a comma is quoted by the cert encoder
                # (CN="Zhuhai Kingsoft Office Software Co., Ltd."), so a plain
                # up-to-next-comma match would return a truncated value with a
                # stray quote in it.
                $m = [regex]::Match($r['subject'], 'CN=("([^"]*)"|([^,]*))')
                if ($m.Success) {
                    $q = [string]$m.Groups[2].Value
                    $r['signer'] = $(if ($q -ne '') { $q } else { [string]$m.Groups[3].Value })
                }
            }
        }
    } catch { }
    $o = [pscustomobject]$r
    $signCache[$exe] = $o
    return $o
}

$WRAPPERS = @('rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'svchost.exe', 'msiexec.exe', 'schtasks.exe')

function Get-ExeFromCommand([string]$cmd) {
    # Returns exe path, whether the line starts with a known loader, and the
    # loader's first argument (that argument is where the real payload hides).
    $res = [ordered]@{ exe = ''; wrapper = $false; payload = ''; raw = $cmd }
    if ([string]::IsNullOrWhiteSpace($cmd)) { return [pscustomobject]$res }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    $exe = ''
    if ($c.StartsWith('"')) {
        $i = $c.IndexOf('"', 1)
        if ($i -gt 1) { $exe = $c.Substring(1, $i - 1); $rest = $c.Substring($i + 1).Trim() }
        else { $exe = $c.Trim('"'); $rest = '' }
    } else {
        # An unquoted command line cannot be split at the first space: registry
        # values routinely hold "C:\Program Files\...\x.exe" as one path. Join
        # tokens back until the prefix is a real file, or until it ends in an
        # executable extension - the second test is what keeps a genuinely
        # missing target attributed to its full path instead of "C:\Program".
        $tokens = $c -split '\s+'
        $exe = $tokens[0]
        $used = 1
        if ($tokens.Count -gt 1) {
            if (Test-Target $c) { $exe = $c; $used = $tokens.Count }
            else {
                for ($i = 1; $i -lt $tokens.Count; $i++) {
                    $cand = ($tokens[0..$i] -join ' ')
                    if ((Test-Target $cand) -or ($cand -match '\.(exe|dll|com|bat|cmd|ps1)$')) {
                        $exe = $cand
                        $used = $i + 1
                        break
                    }
                }
            }
        }
        $rest = ''
        if ($used -lt $tokens.Count) { $rest = ($tokens[$used..($tokens.Count - 1)] -join ' ') }
    }
    $res['exe'] = $exe
    $base = [IO.Path]::GetFileName($exe).ToLower()
    if ($WRAPPERS -contains $base) {
        $res['wrapper'] = $true
        $p = ($rest -split '[, ]', 2)[0].Trim('"')
        if ($p -ne '') {
            $res['payload'] = [Environment]::ExpandEnvironmentVariables($p)
        }
    }
    return [pscustomobject]$res
}

function Resolve-BareCommand([string]$name) {
    # CreateProcess resolves a bare command name against the system PATH, so
    # A bare command name such as `rasdial <conn> <user> <password>` in a task
    # action really points at
    # C:\Windows\System32\rasdial.exe. Treating the bare token as a relative path
    # reports it as a missing file, which made the residue rule fire on a
    # perfectly healthy Windows command.
    if ($name -match '[\\/]') { return '' }
    $dirs = @($env:SystemRoot, (Join-Path $env:SystemRoot 'System32'))
    $dirs += (@($env:Path -split ';') | Where-Object { $_ -ne '' })
    foreach ($d in $dirs) {
        foreach ($ext in @('.exe', '.com', '.cmd', '.bat')) {
            $cand = Join-Path $d ($name + $ext)
            if (Test-Target $cand) { return $cand }
        }
        $cand = Join-Path $d $name
        if (Test-Target $cand -Leaf) { return $cand }
    }
    return ''
}

function Get-CmdSecret([string]$cmd) {
    # Some autostart command lines carry a credential as a literal argument:
    # `rasdial <connection> <user> <password>`, `net user <name> <password>`, or a
    # `--password=value` flag. The value is readable by anyone who can read the task
    # definition or registry key, so it is a finding - but the report must never
    # reproduce the secret. This returns the matched pattern name and a copy of the
    # command with the credential replaced by ***. The raw command stays in the
    # facts file, which is local-only by design; only the masked form is citable.
    $r = [ordered]@{ kind = ''; masked = '' }
    if ([string]::IsNullOrWhiteSpace($cmd)) { return [pscustomobject]$r }
    $s = $cmd.Trim()

    if ($s -match '(?i)\brasdial\b') {
        $toks = @($s -split '\s+')
        $ri = -1
        for ($i = 0; $i -lt $toks.Count; $i++) {
            if ($toks[$i] -match '(?i)rasdial(\.exe)?$') { $ri = $i; break }
        }
        # connection + user + password means at least three tokens after the exe
        if ($ri -ge 0 -and ($toks.Count - $ri) -ge 4) {
            $toks[$toks.Count - 2] = '***'
            $toks[$toks.Count - 1] = '***'
            $r['kind'] = 'rasdial-positional'
            $r['masked'] = ($toks -join ' ')
            return [pscustomobject]$r
        }
    }

    if ($s -match '(?i)^(.*\bnet\s+user\s+\S+)(\s+)(?![%\$\{])\S+$') {
        $r['kind'] = 'net-user-positional'
        $r['masked'] = ($matches[1] + $matches[2] + '***')
        return [pscustomobject]$r
    }

    $re = '(?i)((?:pass(?:word|wd)?|pwd|secret|token|cred(?:ential)?|api[_-]?key)\s*[=:]\s*)("?)(?![%\$\{])[^"\s]+\2'
    if ($s -match $re) {
        $r['kind'] = 'secret-flag'
        $r['masked'] = [regex]::Replace($s, $re, '$1$2***$2')
        return [pscustomobject]$r
    }

    return [pscustomobject]$r
}

function New-Entry($kind, $name, $loc, $cmd) {
    $p = Get-ExeFromCommand $cmd
    # Driver ImagePath values are often relative to the Windows directory
    # (\SystemRoot\system32\drivers\WdBoot.sys, or bare System32\...). Without
    # expanding them every driver looks like a missing file, which would make
    # the residue rule fire on Defender itself.
    $exe = $p.exe
    if ($exe -match '^\\+\??\\?SystemRoot\\(.+)$') { $exe = Join-Path $env:SystemRoot $matches[1] }
    elseif ($exe -match '^(System32|SysWOW64|WinSxS)\\') { $exe = Join-Path $env:SystemRoot $exe }
    else {
        $resolved = Resolve-BareCommand $exe
        if ($resolved -ne '') { $exe = $resolved }
    }

    $sign = Get-SignInfo $exe
    $psign = $null
    if ($p.wrapper -and $p.payload -ne '') { $psign = Get-SignInfo $p.payload }
    $e = [ordered]@{
        kind       = $kind
        name       = $name
        location   = $loc
        command    = $cmd
        exe        = $exe
        is_wrapper = [bool]$p.wrapper
        payload    = $p.payload
        exe_exists = $false
        signer     = ''
        sig_status = ''
        payload_signer = ''
        payload_exists = $false
        in_windows = $false
        in_writable = $false
        exe_mtime  = ''
        exe_bytes  = 0
        cmd_secret_kind = ''
        cmd_masked = ''
    }
    $sec = Get-CmdSecret $cmd
    $e['cmd_secret_kind'] = [string]$sec.kind
    $e['cmd_masked'] = [string]$sec.masked
    if ($sign) {
        $e['exe_exists'] = [bool]$sign.exists
        $e['signer'] = [string]$sign.signer
        $e['sig_status'] = [string]$sign.status
    }
    if ($psign) {
        $e['payload_exists'] = [bool]$psign.exists
        $e['payload_signer'] = [string]$psign.signer
    }
    if ($exe -ne '') {
        $low = $exe.ToLower()
        $win = $env:SystemRoot.ToLower()
        $e['in_windows'] = $low.StartsWith($win)
        # A runnable target under ProgramData, AppData or a profile is writable
        # by far less privileged software than a program-files install, which is
        # why malware and installer leftovers both like these locations.
        $writable = @(
            $env:ProgramData.ToLower(),
            $env:APPDATA.ToLower(),
            $env:LOCALAPPDATA.ToLower(),
            $env:USERPROFILE.ToLower(),
            $env:TEMP.ToLower()
        )
        foreach ($w in $writable) {
            if ($w -and $low.StartsWith($w)) { $e['in_writable'] = $true; break }
        }
        try {
            if (Test-Target $exe) {
                $fi = Get-Item -LiteralPath $exe -Force
                $e['exe_mtime'] = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                $e['exe_bytes'] = [int]$fi.Length
            }
        } catch { }
    }
    return [pscustomobject]$e
}

$entries = @()

# --- 1) Run / RunOnce keys ---------------------------------------------------
$runKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($rk in $runKeys) {
    if (-not (Test-Path $rk)) { continue }
    $ip = Get-ItemProperty $rk -ErrorAction SilentlyContinue
    if (-not $ip) { continue }
    foreach ($n in @($ip.PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS' })) {
        $entries += New-Entry 'run_key' $n $rk ([string]$ip.$n)
    }
}

# --- 2) Startup folders ------------------------------------------------------
$startupDirs = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
)
foreach ($d in $startupDirs) {
    foreach ($f in @(Get-ChildItem $d -Force -ErrorAction SilentlyContinue)) {
        if ($f.PSIsContainer) { continue }
        # desktop.ini is a folder-settings file that every Windows folder
        # carries. Treating it as an autostart entry would mislabel a system
        # file on every machine, so it never becomes an entry at all.
        if ($f.Name -eq 'desktop.ini') { continue }
        $target = ''
        if ($f.Extension -eq '.lnk') {
            try {
                $sh = New-Object -ComObject WScript.Shell
                $target = [string]$sh.CreateShortcut($f.FullName).TargetPath
            } catch { }
        }
        if ($target -ne '') {
            $entries += New-Entry 'startup_folder' $f.Name $d $target
        } else {
            $e = New-Entry 'startup_folder' $f.Name $d ''
            Add-Member -InputObject $e -MemberType NoteProperty -Name 'command' -Value ('<no shortcut target: ' + $f.Extension + '>') -Force
            $entries += $e
        }
    }
}

# --- 3) Scheduled tasks outside the Microsoft namespace ----------------------
foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    $path = [string]$t.TaskPath
    if ($path -like '\Microsoft\*') { continue }
    foreach ($a in $t.Actions) {
        if (-not $a.Execute) { continue }
        $cmd = [string]$a.Execute
        if ($a.Arguments) { $cmd = $cmd + ' ' + [string]$a.Arguments }
        $e = New-Entry 'scheduled_task' ([string]$path + [string]$t.TaskName) 'Task Scheduler' $cmd
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'task_state' -Value ([string]$t.State) -Force
        $entries += $e
    }
}

# --- 4) Auto-start services whose binary lives outside Windows ---------------
foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
    if ([string]$s.StartMode -ne 'Auto') { continue }
    $pn = [string]$s.PathName
    if ($pn -eq '') { continue }
    if ($pn.ToLower().StartsWith($env:SystemRoot.ToLower())) { continue }
    if ($pn -match '^\s*"?([A-Za-z]:\\[^"]*svchost\.exe)' -or $pn -match 'svchost\.exe') { continue }
    $e = New-Entry 'service' ([string]$s.Name) 'SCM' $pn
    Add-Member -InputObject $e -MemberType NoteProperty -Name 'svc_state' -Value ([string]$s.State) -Force
    Add-Member -InputObject $e -MemberType NoteProperty -Name 'svc_account' -Value ([string]$s.StartName) -Force
    $entries += $e
}

# --- 5) ELAM / Early-Launch drivers -----------------------------------------
# Measured on this machine: this set must contain exactly one member, WdBoot.
# An Early-Launch driver loads before most security software and can whitelist
# malicious binaries, so an unexpected member here matters far more than a
# harmless-looking autostart entry.
$svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$elam = @()
foreach ($k in @(Get-ChildItem $svcRoot -ErrorAction SilentlyContinue)) {
    $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
    if ($p.Group -eq 'Early-Launch') {
        $elam += [pscustomobject]@{ name = [string]$k.PSChildName; start = [string]$p.Start; image = [string]$p.ImagePath }
        $e = New-Entry 'elam_driver' ([string]$k.PSChildName) 'HKLM\SYSTEM\CurrentControlSet\Services' ([string]$p.ImagePath)
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'drv_start' -Value ([string]$p.Start) -Force
        $entries += $e
    }
}

# --- 6) hosts file -----------------------------------------------------------
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostLines = @()
if (Test-Path $hostsPath) {
    foreach ($l in @(Get-Content $hostsPath -ErrorAction SilentlyContinue)) {
        $s = [string]$l
        if ($s.Trim() -eq '' -or $s.Trim().StartsWith('#')) { continue }
        $hostLines += $s.Trim()
    }
    $h = Get-Item $hostsPath
    # localhost mappings are the one default every Windows hosts file ships
    # with. Counting them as overrides would flag a clean machine as hijacked.
    $effective = @($hostLines | Where-Object { $_ -notmatch '^(127\.0\.0\.1|::1)\s+localhost$' })
    $entries += [pscustomobject]@{
        kind = 'hosts_file'; name = 'hosts'; location = $hostsPath
        command = (($effective | Select-Object -First 8) -join ' ;; ')
        exe = ''; is_wrapper = $false; payload = ''; exe_exists = $true
        signer = ''; sig_status = ''; payload_signer = ''; payload_exists = $false
        in_windows = $true; in_writable = $false; exe_mtime = ''; exe_bytes = 0
        cmd_secret_kind = ''; cmd_masked = ''
        host_count = @($hostLines).Count
        host_effective = @($effective).Count
        host_mtime = $h.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
}

# --- 7) IFEO Debugger hooks --------------------------------------------------
# A Debugger value under Image File Execution Options replaces the process that
# starts when any program runs, including security tools. Rare, but it is the
# single most damaging autostart surface on the list.
$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($k in @(Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue)) {
    $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
    if ($p.Debugger) {
        $e = New-Entry 'ifeo_debugger' ([string]$k.PSChildName) $ifeoRoot ([string]$p.Debugger)
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'global_flag' -Value ([string]$p.GlobalFlag) -Force
        $entries += $e
    }
}

# --- 8) Winsock LSP providers ------------------------------------------------
$lspRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\NameSpace_Catalog5\Catalog_Entries64'
foreach ($k in @(Get-ChildItem $lspRoot -ErrorAction SilentlyContinue)) {
    $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
    $dll = [string]$p.LibraryPath
    if ($dll -eq '') { continue }
    $dll = [Environment]::ExpandEnvironmentVariables($dll)
    $e = New-Entry 'winsock_lsp' ([string]$k.PSChildName) $lspRoot $dll
    $entries += $e
}

$payload = [ordered]@{
    probe        = 'persistence'
    captured_at  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    computer     = $env:COMPUTERNAME
    user         = $env:USERNAME
    elam_members = @($elam | ForEach-Object { $_.name })
    entries      = $entries
}

if ($OutFile -eq '') {
    $OutFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'out\facts-persistence.json'
}
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
[IO.File]::WriteAllText($OutFile, ($payload | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
Write-Output ('persistence: entries=' + @($entries).Count + ' elam=[' + (@($elam | ForEach-Object { $_.name }) -join ',') + '] hosts=' + @($hostLines).Count + ' -> ' + $OutFile)
