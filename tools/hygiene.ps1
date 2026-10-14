$ErrorActionPreference = 'Stop'
# Shipped-file hygiene, two failure modes that both bite silently on Windows.
#
# 1) Batch files need CRLF. cmd mis-parses LF-only scripts, and the failure mode
#    is a half-executed script rather than a clean error.
# 2) PowerShell 5.1 reads a BOM-less file as the ANSI codepage. Any non-ASCII
#    byte in a .ps1 is therefore either mojibake in a comment or, if the decoded
#    garbage happens to contain a quote or backtick, a parser error that only
#    appears on machines with a different active codepage. So: ASCII only, or
#    UTF-8 with a BOM - never UTF-8 without one.

$cr = [string][char]13
$lf = [string][char]10
$root = Split-Path $PSScriptRoot -Parent
$problems = 0

foreach ($b in @(Get-ChildItem (Join-Path $root '*.bat'))) {
    $t = [IO.File]::ReadAllText($b.FullName)
    $t = $t.Replace($cr + $lf, $lf).Replace($lf, $cr + $lf)
    [IO.File]::WriteAllText($b.FullName, $t, (New-Object Text.UTF8Encoding $false))
    $n = ([regex]::Matches($t, [regex]::Escape($cr + $lf))).Count
    Write-Output ('bat   | ' + $b.Name + ' CRLF=' + $n + ' bytes=' + (Get-Item $b.FullName).Length)
}

$ps1 = @(Get-ChildItem (Join-Path $root '*.ps1') -Recurse |
    Where-Object { $_.FullName -notmatch '\\out\\' })
foreach ($f in $ps1) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $body = $bytes
    if ($hasBom) { $body = $bytes[3..($bytes.Length - 1)] }
    $nonAscii = @($body | Where-Object { $_ -gt 0x7F }).Count
    if ($nonAscii -gt 0 -and -not $hasBom) {
        Write-Output ('PS1   | FAIL ' + $f.Name + ' has ' + $nonAscii + ' non-ASCII bytes and no BOM')
        $problems++
    } elseif ($nonAscii -gt 0) {
        Write-Output ('PS1   | ok   ' + $f.Name + ' (UTF-8 BOM, ' + $nonAscii + ' non-ASCII bytes)')
    } else {
        Write-Output ('PS1   | ok   ' + $f.Name + ' (pure ASCII)')
    }
}

Write-Output ('hygiene: ' + $(if ($problems -eq 0) { 'OK' } else { $problems + ' problem(s)' }))
if ($problems -gt 0) { exit 1 }
exit 0
