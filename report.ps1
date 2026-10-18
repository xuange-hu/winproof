param(
    # Injectable so the same renderer can build the committed demo from
    # tests/fixtures, not only from this machine's capture.
    [string]$FindingsFile = '',
    [string]$OutFile = '',
    # The demo is rendered from synthetic facts, so it has to say so. The wording
    # lives in the template and this only flips an attribute - a .ps1 must stay
    # ASCII, so no user-facing sentence can be written here.
    [switch]$Demo
)
$ErrorActionPreference = 'Stop'

# Build the report: one self-contained HTML file with the findings inlined.
# No server, no external assets, no second run needed to view it - the file is
# the artefact, so it can be mailed or posted and still render in five years.

$root = $PSScriptRoot
$src = $FindingsFile
if (-not $src) { $src = Join-Path $root 'out\findings.json' }
$tpl = Join-Path $root 'render\template.html'
$dst = $OutFile
if (-not $dst) { $dst = Join-Path $root 'out\report.html' }

if (-not (Test-Path $src)) { throw 'run the engine first: scan.bat' }
if (-not (Test-Path $tpl)) { throw 'missing render\template.html' }

$json = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)

# A report that gets screenshotted should not carry the owner's paths.
$privacy = @(
    @($env:USERPROFILE, '~'),
    @($env:LOCALAPPDATA, '~\AppData\Local'),
    @($env:USERNAME, '<user>')
)
foreach ($p in $privacy) {
    if ($p[0]) { $json = $json.Replace($p[0], $p[1]) }
}
# An empty oldValue makes .Replace() insert between every character, which would
# corrupt the whole payload - so the hostname pass is guarded like the two above.
if ($env:COMPUTERNAME) {
    $json = $json.Replace($env:COMPUTERNAME, '<host>')
    $json = $json.Replace('"computer": "' + $env:COMPUTERNAME + '"', '"computer": "<host>"')
}

# Inline JSON must not be able to close its own script element.
$json = $json.Replace('</script>', '<\/script>')

$html = [IO.File]::ReadAllText($tpl, [Text.Encoding]::UTF8)
$html = $html.Replace('__WP_DATA__', $json)
if ($Demo) {
    $html = $html.Replace('<html lang="zh-CN">', '<html lang="zh-CN" data-demo="1">')
}

New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
[IO.File]::WriteAllText($dst, $html, (New-Object Text.UTF8Encoding $false))
Write-Output ('report: ' + $dst + ' (' + [int]((Get-Item $dst).Length / 1024) + ' KB, self-contained)')
