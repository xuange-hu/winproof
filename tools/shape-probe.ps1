$ErrorActionPreference = 'Continue'
# Grounding probe - run this BEFORE writing or changing a shipped rule.
#
# It dumps the real structure of the browser preference files on this machine:
# which keys exist, where the sealed copies live, what the protection.macs
# section actually contains. Every predicate in rules/*.json was written against
# output from this script rather than against a description of the format, which
# is why the shipped parser reads `restore_on_startup` from Secure Preferences
# and `startup_setting` from Preferences instead of guessing one of them.
#
# Read only. Nothing here writes.

$roots = @(
    @{ brand = 'Edge';   root = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
    @{ brand = 'Chrome'; root = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') }
)

foreach ($r in $roots) {
    $brand = $r.brand
    $root = $r.root
    if (-not (Test-Path $root)) { Write-Output ('MISSING| ' + $brand + ' ' + $root); continue }
    foreach ($prof in @(Get-ChildItem $root -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($fn in @('Secure Preferences', 'Preferences')) {
            $fp = Join-Path $prof.FullName $fn
            if (-not (Test-Path $fp)) { continue }
            $itm = Get-Item $fp -Force
            Write-Output ('')
            Write-Output ('=== ' + $brand + ' / ' + $prof.Name + ' / ' + $fn + ' ===')
            Write-Output ('  len=' + $itm.Length + ' mtime=' + $itm.LastWriteTime + ' ctime=' + $itm.CreationTime)

            # Backups left by earlier repairs are timeline evidence: they are what
            # lets a later scan distinguish "never infected" from "infected, fixed,
            # and fixed again".
            foreach ($b in @(Get-ChildItem ($fp + '.bak_*') -Force -ErrorAction SilentlyContinue)) {
                Write-Output ('  BACKUP| ' + $b.Name + ' len=' + $b.Length + ' at=' + $b.LastWriteTime)
            }

            $raw = [IO.File]::ReadAllText($fp, [Text.Encoding]::UTF8)

            $j = $null
            try { $j = $raw | ConvertFrom-Json } catch { Write-Output ('  JSONFAIL| ' + $_.Exception.Message) }

            if ($j) {
                if ($j.session) {
                    Write-Output ('  session.keys= ' + (($j.session.PSObject.Properties.Name) -join ','))
                    Write-Output ('  session.restore_on_startup= ' + ($j.session.restore_on_startup | Out-String).Trim())
                    Write-Output ('  session.startup_urls= ' + (($j.session.startup_urls) -join ' ; '))
                } else { Write-Output '  session.keys= <absent>' }

                if ($j.protection -and $j.protection.macs) {
                    Write-Output ('  macs.sections= ' + (($j.protection.macs.PSObject.Properties.Name) -join ','))
                    if ($j.protection.macs.session) {
                        Write-Output ('  macs.session.keys= ' + (($j.protection.macs.session.PSObject.Properties.Name) -join ','))
                    } else { Write-Output '  macs.session.keys= <absent>' }
                } else { Write-Output '  macs.sections= <absent>' }

                if ($j.sync) {
                    Write-Output ('  sync.keys= ' + (($j.sync.PSObject.Properties.Name) -join ','))
                    # sync.preferences is the field that decides whether editing the
                    # file by hand survives: the cloud may write the value back.
                    Write-Output ('  sync.preferences= ' + ($j.sync.preferences | Out-String).Trim())
                }
                $enc = @($j.PSObject.Properties.Name | Where-Object { $_ -match 'enclave' })
                if ($enc.Count) { Write-Output ('  TOPLEVEL-ENCLAVE| ' + ($enc -join ',')) }
            }

            # Raw scan for the sealed-copy key family anywhere in the document.
            $m = [regex]::Matches($raw, '"[A-Za-z0-9_]*(enclave|lightweight)[A-Za-z0-9_]*"')
            $names = @($m | ForEach-Object { $_.Value } | Sort-Object -Unique)
            Write-Output ('  ENCLAVE-KEYS| count=' + $m.Count + ' unique=' + ($names -join ' '))

            $u = [regex]::Matches($raw, '"startup_urls"\s*:\s*\[[^\]]*\]')
            foreach ($x in $u) { Write-Output ('  URLS| ' + $x.Value) }

            $w = [regex]::Matches($raw, '"restore_on_startup"\s*:\s*\d+')
            foreach ($x in $w) { Write-Output ('  MODE| ' + $x.Value) }
        }
    }
}
