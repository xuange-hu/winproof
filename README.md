# WinProof · Windows persistence forensics, with a baseline

[![scan and tests](https://github.com/xuange-hu/winproof/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/winproof/actions/workflows/ci.yml)
[![demo report](https://img.shields.io/badge/demo-live%20report-35d39a)](https://xuange-hu.github.io/winproof/demo/)
[![release](https://img.shields.io/github/v/release/xuange-hu/winproof)](https://github.com/xuange-hu/winproof/releases)
![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![powershell](https://img.shields.io/badge/powershell-5.1%20only-informational)
![deps](https://img.shields.io/badge/dependencies-0-green)
![language](https://img.shields.io/badge/report-%E4%B8%AD%E6%96%87%20%7C%20English-informational)
![license](https://img.shields.io/badge/license-MIT-blue)

**简体中文版：[README.zh-CN.md](README.zh-CN.md)** — same rules, same numbers, same 25 defect write-ups.

> Not another cleaner. It answers the three questions a cleaner cannot answer:
> **what changed · when it changed · whether the fix you just applied will be reverted.**

**No Windows machine handy? Look at the output first → [live demo report](https://xuange-hu.github.io/winproof/demo/)**
— rendered from the synthetic captures committed in this repo, and the page says in its own banner that
it is a demo and not your machine.

Zero dependencies: only the PowerShell 5.1 that ships with Windows. No .NET SDK, no Node, no network,
nothing uploaded anywhere. Double-click `scan.bat` and you get one self-contained HTML report.

---

## Why this exists: two fixes, two different outcomes

My Edge startup page was hijacked to `2345.pbgia.com`. I removed it twice — on 10-10 and on 10-16.
Both times it came back, **for different reasons**, and both reasons are observable in the files.
That is the entire premise of this project.

| | Edge / Profile 1 | Chrome / Default |
|---|---|---|
| Repair backup | `bak_20261010-221049` · 71,212 B · still contains the malicious URL | `bak_20261010-152128` · 30,814 B · still contains the malicious URL |
| First fix (10-10, deleted the plaintext key only) | **recurred** | **stayed clean** |
| Difference | 4 `*_edge_enclave` sealed keys + `_verify` | no sealed copy at all |
| Second fix (10-16 14:18, deleted the plaintext key **and** the whole sealed key family) | **recurred again**: at 15:55:30 a background Edge process started, at 15:55:40 `restore_on_startup=4` plus the malicious URL were written back (148,932 B) | n/a |
| Was that value still anywhere on disk when it recurred | No — `session` in the plaintext `Preferences` was empty and the sealed keys had been deleted | — |
| So where did it come from | `sync.preferences` = present ⇒ **the cloud pushed the configuration back** | — |
| Conclusion | **A file-level fix on a profile like this survives until the next browser start.** It has to be done through `edge://settings/onStartup`, so the cloud copy changes too | **Repair held** (BR-07) |

One action, three structurally different objects, three different results: *not reverted*,
*reverted by a local sealed copy*, *reverted by the cloud*. And at the file level, all three of them
look exactly like "deleted".

> No tool on the market reports this, because every one of them is a one-shot scan-then-delete.
> WinProof makes the **baseline** a first-class object: `baseline.bat` freezes the current state, and
> every later `scan.bat` classifies each conclusion as `new / changed / persisting / known / resolved`.
> The timeline above was not typed by hand. It comes from the timestamps inside the `.bak_` filenames
> that my own repair left behind, the `mtime` of the two documents, and the `startup_urls` values found
> **inside those backup files**. The traces a fix leaves are themselves the evidence.

> The baseline **never updates itself**. Otherwise whatever writes into your machine only has to wait
> for you to re-capture a baseline, and it launders itself.

---

## 30-second start

Do not want to clone: download `winproof-1.0.0.zip` from
[Releases](https://github.com/xuange-hu/winproof/releases/tag/v1.0.0) (183 KB, unzip and double-click).
CI re-verifies on every push that the three `.bat` files inside that archive are CRLF — an LF-only batch
file is executed half-way by cmd and then reports a syntax error that has nothing to do with your machine.

```
scan.bat                          # read-only capture + evaluation + out\report.html, then opens it
baseline.bat                      # freeze the current state as the reference point
ack.bat "BR-06|Edge / Profile 1"  # "this one is mine, stop reporting it" — downgrades one finding, never deletes a rule
```

That `ack` command contains quotes, a pipe and a space, which is the one step in the whole workflow that
fails silently when typed by hand. So every card in the report carries the finished command on a
**click-to-copy button**: it turns into `Copied ✓`, or, if the clipboard is unavailable over `file://`,
it says `Copy failed, select it manually` — a button that lies about having copied something is worse
than no button at all.

This is a real run on a real machine, redacted. To click the filters, expand the evidence and read the
collapsed "why this rule exists" notes, use the [live demo](https://xuange-hu.github.io/winproof/demo/) —
it is rendered from the committed fixtures, so it also demonstrates states like "fixed, then came back",
which a clean machine can never produce:

![report](docs/report.png)

The same page in Chinese — one scan serves both wordings, the language is picked when the file is opened,
and the toggle is in the header (see [Architecture](#architecture-five-layers-no-overlapping-responsibilities)):

![report in Chinese](docs/report-zh.png)

---

## Detection inventory: 17 rules, each restatable as one concrete observation

This is not "a long list so it looks thorough". What follows each rule is **what it looks like on your
machine**. Every rule in `rules/*.json` must fill `verified_evidence` with hit counts and object names
produced by an actual run — a rule without measured evidence does not reach main.

**Browser startup page and search engine — 10 rules**

| Rule | Severity | The condition, in one line | Why it is a separate rule |
|---|---|---|---|
| BR-01 | high | `session.restore_on_startup=4` **and** `startup_urls` matches the domain blocklist | It does not touch hosts, does not install a service, does not appear in Task Manager: it writes two keys in a JSON file |
| BR-02 | high | A sealed `*_edge_enclave` / `*_edge_lightweight` key family exists | **The real reason manual cleaning fails.** You delete the plaintext, and the other copy is treated as authoritative and restores it |
| BR-03 | info | Startup mode is 4 (open specific pages) but the URL is not blocklisted | Harmless on its own; read next to BR-01 it means *someone has been changing this place* |
| BR-04 | medium | `protection.macs` still holds a signature while the plaintext key is gone | An attacker never has to forge a signature — delete the value, leave the signature, and the browser still treats the block as authoritative |
| BR-05 | high | Current value is blocklisted, the repair backup was blocklisted too, **and** the live file is newer | A one-shot scanner cannot answer "I cleaned this last week, why is it still here". This rule puts the two timestamps side by side |
| BR-06 | low | `profile.exit_type != Normal` (probed with a non-blocking exclusive lock, never by process name) | Resident background processes make "process name ⇒ in use" permanently wrong; failing to open the file exclusively is the actual evidence |
| BR-07 | good | The repair backup contains a malicious value and the current plaintext is clean | The only signal that proves a remediation *worked*. Every other tool only ever says "deleted" |
| BR-08 | medium | A blocklisted origin still holds rows in `content_settings.exceptions` | Permissions, cookies and `media_engagement` are traces that the page **was actually loaded** — they survive after the startup URL is deleted |
| BR-09 | medium | The default search engine's `keyword`/URL is blocklisted, **or** `enforced_by_policy=true` | The startup page decides what you see when you open the browser; the search engine decides what your searches return, and that only shows up when you actually search. The policy half separates "you installed the wrong thing" from "something decided for you" — the remediations are not the same |
| BR-10 | info | This object has surfaces this tool **cannot read** (engine stored as a hash, no `Secure Preferences`, JSON parse failure) | A scanner that only reports problems has an uninformative "nothing found": it cannot distinguish *this machine is clean* from *this machine contains things I do not cover*. This rule turns the coverage boundary into a conclusion that is itself baseline-tracked |

**Boot-time persistence: Run keys, services, drivers, network layer — 7 rules**

| Rule | Severity | The condition, in one line | Why it is a separate rule |
|---|---|---|---|
| PS-01 | medium | A Run key / service / scheduled task points at a file that no longer exists | Uninstall residue is far more common than malware, and it destroys the usefulness of "I have 40 startup entries" as a metric |
| PS-02 | medium | A binary that runs at every boot has no valid Authenticode signature | Uses signer attribution, not a vendor keyword list — keywords can only ever catch the vendors someone already typed into the list |
| PS-03 | high | The `Group=Early-Launch` list contains anything other than `WdBoot` | A threat measured on this machine: a 360 downloader once installed `360elam64.sys`, BOOT_START, one boot stage earlier than ordinary drivers |
| PS-04 | high | `hosts` contains a mapping other than `localhost` | Needs no privilege, leaves no resident process, stays in effect forever, and most cleaners do not even look at it |
| PS-05 | high | A `Debugger` value exists under IFEO | The highest-impact single-point persistence: applies only to a named process, looks normal in any process list, and needs administration rights to write |
| PS-06 | high | The Winsock LSP provider is not a system DLL | This registry position has very few entries and very little churn, so one non-system provider is a hard signal |
| PS-07 | low | A resident binary lives in a user-writable directory (excluding exactly three Microsoft signer names) | The Microsoft exclusion is mandatory, otherwise Defender's own `MpCmdRun` / `MsMpEng` get reported as suspicious |

The blocklist is currently 9 tokens (`2345` `pbgia` `hao.360` `mydown` `so.com` `360safe` `duba`
`haosf` `win23`). In `rules/browser.json` it is data, not code: a new machine or a new domain never
touches the engine. It matches by **substring**, so if you set `so.com` as your own homepage you will be
reported — the correct response is `ack.bat`, marking it as known, not dulling the rule.

---

## What it actually reports on this machine

```
engine: subjects=65 rules=17 findings=27 high=4 resolved=1
counts: NEW=8 CHANGED=5 PERSIST=14 KNOWN=0 RESOLVED=1
```
(Re-scanned on 10-18. The baseline was captured on 10-15, so every state above is a judgement **about
five days ago**, not about yesterday.)

| Severity | Rule | Hits | Objects |
|---|---|---|---|
| high | BR-01 startup page hijacked | 1 | Edge / Profile 1 — state `changed`, i.e. the cloud write-back above |
| high | BR-02 sealed copy exists, plaintext deletion will be reverted | 2 | Edge / Default, Edge / Profile 1 |
| high | BR-05 it came back after being cleaned | 1 | Edge / Profile 1 |
| medium | BR-04 orphan signature (this place was tampered with and cleaned up) | 4 | Edge ×3, Chrome ×1 — the Edge / Profile row is **new** in this scan |
| medium | BR-08 blacklisted domain still holds content-setting exceptions | 3 | Edge / Profile 1, Edge / Default, Chrome / Default |
| medium | PS-01 startup entry points at a missing file | 1 | service / AndrowsSvr |
| medium | PS-02 boot-time binary without a valid signature | 2 | Authenticator, OpenClaw Gateway |
| low | BR-06 browser did not exit normally | 2 | Edge / Profile 1, Chrome / Default — both state `changed` |
| low | PS-07 resident binary in a user-writable directory | 5 | Rd_Service, 3 WPS tasks, OpenClaw |
| info | BR-03 startup mode set to "open specific pages" | 1 | Edge / Profile 1 |
| info | BR-10 surfaces this tool cannot read | 4 | the 4 Edge profiles: the default engine is stored as a hash |
| good | BR-07 the previous repair survived re-check | 1 | Chrome / Default |

**The most interesting part of this re-scan is that the `resolved` column went from 2 rows to 1.**
On 10-16, `BR-06 / Chrome / Default` had been reported as *resolved* (that profile had exited cleanly
once). Today it is back, state `changed`, `exit_type=Crashed`. So: **a "resolved" verdict is not an end
state — it is a conclusion that can be overturned again**, which is precisely why the baseline exists.
The other row, `PS-02 / run_key / Lively`, is still resolved, because I deleted that startup entry myself
and deleted means deleted. A tool that only lists current problems cannot tell those two situations apart.

**BR-09 has 0 hits while BR-10 has 4, and those two sentences must be read together.**
Chrome / Default keeps `default_search_provider_data.template_url_data` as a plaintext object
(keyword=google.com, `enforced_by_policy=false`), so "the Chrome search engine on this machine was not
swapped" is a conclusion that was **looked at**. The same position in Edge's 4 profiles is a 40-character
hex digest plus an `_encrypted_hash`: the engine cannot be recovered, so those 4 BR-10 rows mean
"here, I did not look". Report only "0 BR-09 hits" and both situations look identical.

**PS-03 / PS-04 / PS-05 / PS-06 have 0 hits, and that is the correct state, not a miss.**
The Early-Launch group contains only `WdBoot`, hosts contains only `127.0.0.1 localhost`, there is no
`Debugger` under IFEO, and all 5 Winsock LSP entries are Microsoft-signed system DLLs. Each rule's
`verified_evidence` records the measured local distribution, so "0 hits" is something you can re-check —
not a "probably this rule never fires" guess.

---

## Architecture: five layers, no overlapping responsibilities

```
probes/     read-only fact capture, judges nothing
rules/      pure JSON data. no code, no eval
engine.ps1  declarative predicate interpreter + baseline diff
report.ps1  emits one self-contained static HTML. no server
tests/      committed synthetic captures: the executable definition of every criterion
```

**Rules are data, not code — that is the core decision of this project.**

A rule looks like this:

```json
{
  "id": "PS-07",
  "title": "A resident binary lives in a user-writable directory",
  "severity": "low",
  "when": { "all": [
    { "fact": "exe_exists",  "op": "eq",     "value": true },
    { "fact": "in_writable", "op": "eq",     "value": true },
    { "fact": "signer",      "op": "notIn",  "value": ["Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"] }
  ]},
  "show": ["kind", "exe", "signer", "sig_status", "exe_mtime", "exe_bytes"]
}
```

Conditions are a **bounded AST**. The operator set is fixed at
`eq / ne / nonEmpty / isEmpty / hasAny / countGte / in / notIn`, and an unknown operator `throw`s.
Consequences:

- A rule merged from a pull request, or generated for you by an LLM, **can never become executable
  input** — the injection surface is zero.
- Rules can be statically checked, diffed and machine-validated, instead of "read the code to find out
  whether it calls `Invoke-Expression`".
- Adding a criterion does not touch the engine.

`when` decides whether a rule fires; `show` decides which fields enter the **evidence fingerprint**.
The fingerprint is computed only from the fields `show` lists, so a file being rewritten while the cited
evidence is untouched keeps the conclusion at `PERSIST` rather than flipping it to `CHANGED` — otherwise
one browser start would light up every rule on that profile and "what changed?" would be noise again.

**Two wordings, one evaluation.** The report is bilingual, and where the language is chosen is a design
decision, not a detail. Each rule file carries its own English wording under `i18n.en`; the engine attaches
it to every finding in the same pass it computes the fingerprint; the renderer picks the language when the
page is opened (`navigator.language`, overridable with `?lang=en` / `?lang=zh` and by a toggle in the
header). Consequences:

- The overlay may only hold `title / advice[] / why / verified_evidence`. It has no access to `when`, `show`
  or `severity`, so **a translation cannot change what fires**. `selftest [16]` proves it rather than
  asserting it: it re-runs the engine against a scratch copy whose English wording has been perturbed and
  requires the fingerprints to come out byte-identical.
- `findings.json`, `store\baseline.json` and every fingerprint stay locale-free. One scan serves both
  languages, and fixing a typo in a sentence never turns 30 `PERSIST` rows into `CHANGED`.
- Advice is selected by branch index, and the English half follows the *same* index — the conditional
  remediation is derived from the facts once, not re-derived per language.
- The overlay is validated at load time. A rule with no `i18n.en`, or with fewer translated branches than the
  rule has branches, aborts the run: a report that quietly mixes two languages is worse than one that fails
  to build.
- If the script never runs at all, the page still renders as a complete Chinese report — the fallback is a
  language, not a blank screen.

---

## Twenty-five defects, and how each one became code

These are not reflections. Each corresponds to logic that is still alive in the repository.
(The Chinese README carries the long form of each; nothing below is a different claim.)

**1. `Secure Preferences` and `Preferences` have to be read together.**
The hijacked value lives in `Secure Preferences` under `session.startup_urls`, while `sync.preferences` —
the thing that decides whether a hand edit gets pushed back by the cloud — lives in the `sync` block of
*the other* file. Either file alone yields the wrong remediation advice. The engine merges both documents
per profile and derives `sync_preferences_enabled` before the rules ever run.

**2. The plaintext key is spelled differently in the two files.**
`Secure Preferences` uses `restore_on_startup`; a plain-only `Preferences` uses `startup_setting`.
Checking one of them silently misses the other.

**3. A sealed copy has to be deleted as a family.**
Edge stores `session.startup_urls_edge_enclave` / `_verify` alongside the plaintext (on another machine
the same family is spelled `_edge_lightweight`). Delete only the plaintext and Edge restores it from the
sealed copy the next time it writes the file — that is exactly the "recurred" cell in the table above.
So the rule matches the whole key family: `_(edge_enclave|edge_lightweight)(_verify)?$`.

**4. `protection.macs` is two levels deep: section → key → signature.**
And those signatures are **deterministic**: `Default` and `Profile 2` hold byte-identical signatures for
the same non-existent value. Which means an attacker needs to forge nothing — delete the value, leave the
signature, and you get what `BR-04` reports as an orphan signature. It is not a current threat, it is
history: it proves this position was modified and cleaned up.

**5. Use signer attribution, not a vendor keyword blocklist.**
A keyword list can only catch the vendors someone already wrote into it. "This binary runs at every boot
and has no valid signature" catches **what is actually on your machine**.

**6. `Microsoft Windows Hardware Compatibility Publisher` is not Microsoft software.**
It is the WHQL third-party signing channel. I treated it as a Microsoft signature at first, which let a
batch of third-party drivers through. `PS-07`'s exclusion list is therefore three exact names, not
`startswith("Microsoft")`.

**7. `PS-07` must exclude Microsoft signatures or Defender reports itself.**
The real binaries behind `WinDefend` and `MDCoreSvc` live under `C:\ProgramData\Microsoft\Windows
Defender\`. The self-test asserts this **positively**: first confirm that objects matching
"Microsoft-signed + resident in a writable directory" exist on this machine (2 of them), then assert that
not one of them leaked into `PS-07`. Without the first half, that assertion can pass vacuously forever.

**8. A bare command name is not a missing file.**
`\自动拨号` has the command line `rasdial <connection> <user> <password>`. The first version reported
"the target file no longer exists" — a false positive. `CreateProcess` resolves bare names through
`PATH`, so this one points at `C:\Windows\System32\rasdial.exe`, alive and well. After adding
`Resolve-BareCommand`, `PS-01` went from 2 hits to the truthful 1.
(Side effect: that command line stores the broadband password in plaintext. Once the resolution defect was
fixed it stopped appearing in the report, and `verify.js` now extracts those tokens from the fact files and
asserts they are absent from the HTML.)

**9. `\SystemRoot\...` relative `ImagePath` values must be expanded.**
Without expansion, `WdBoot` looks like a missing file and the residue rule fires on Defender.

**10. An unquoted path containing spaces must not be split at the first space.**
For a registry value like `"C:\Program Files\...\x.exe"`, re-join tokens one by one and `Test-Path` each
candidate, then fall back on the extension. The second check guarantees that a genuinely missing file is
attributed to its full path instead of to `C:\Program`.

**11. `countGte` on a scalar takes the numeric value, not the "array length".**
`host_effective = 0` was being treated as one element, so **every machine got a hosts-hijack finding**.
This is pinned by section [7] of the self-test, asserted in both directions.

**12. PowerShell 5.1's serialisation traps.**
An empty array becomes `{}` and a single-element array becomes an object → the renderer normalises every
list field through `norm()`. `PSCustomObject.ToString()` returns an empty string → evidence must be
`ConvertTo-Json -Compress` before it enters a fingerprint, otherwise object-shaped evidence (backup lists,
sealed key families) contributes nothing and the baseline diff is permanently blind to it.

**13. `-Value [string]$x` is not an expression in argument mode.**
`[string]` was parsed as a literal token, so the value became the string `"[string]@{...}.group"` and every
later hash lookup missed → each card's group name was silently empty in the report. It must be written
`-Value ([string]$x)`. Found via a screenshot; `selftest [12]` now asserts directly that `group_title` is
non-empty and contains no `@{`.

**14. A clean machine cannot test the four most dangerous rules.**
`PS-03` (ELAM), `PS-04` (hosts), `PS-05` (IFEO) and `PS-06` (LSP) have 0 hits on this machine — correct,
but it also means the live-machine self-test would never execute them: an inverted predicate would only be
discovered on the day it mattered. `tests/fixtures/facts-persistence.json` therefore contains one record in
each of those four states, and section [8] asserts all 7 persistence rules fire **and** that the hit set
equals the manifest exactly. The same applies to `BR-01`/`BR-05`'s two remediation branches (sync on/off),
`PS-01`'s three branches, and `BR-08`'s "startup page already clean vs still hijacked" pair. `BR-08` gets
one more guard: the fixture mixes ordinary origins (google / bilibili / a bare IP) into every profile and
asserts none of them may appear in the evidence — the blocklist is substring matching, so that assertion is
its safety rail (`so.com` matches `www.so.com`, and tomorrow it could match someone else's suffix).

**15. The anchor document was chosen and then ignored: plain-only profiles were silently skipped.**
`New-BrowserSubjects` computed `$anchor = Secure Preferences ?? Preferences` and then read fields only when
`$null -ne $secure`. Result: a profile without `Secure Preferences` could contain a hijacked
`session.startup_urls` in plaintext and `BR-01` would not fire. **This false negative was only exposed when
writing the fixture** — the plain-only record `Chrome / Profile 3` exists for exactly this test point.
Fixed by reading from the anchored document while keeping sealed keys and orphan signatures scoped to the
secure document (they only ever exist there), so a plain-only profile cannot conjure "a sealed copy
exists". The `doc_role=secure` preconditions on `BR-01`/`BR-03` were dropped and `doc_role` was added to
the evidence — the reader needs to know which document a value was read from, because that is what decides
whether a hand edit survives.

**16. A rule can cite a field the renderer never translated.**
`PS-03/05/06` list `name` in `show`, but the template's label table had no entry for it. On this machine
those three rules hit nothing, so the live report would **never show** that blank cell — until some machine
actually trips an ELAM rule. `verify.js` now walks every `show` field of every rule in `rules/*.json` and
asserts a label exists, independent of whether the rule fires.

**17. `Get-Content -Raw` decodes using the ANSI code page in 5.1.**
The CI step "create baseline → immediately re-scan → assert `counts.NEW == 0`" originally read
`Get-Content out\findings.json -Raw | ConvertFrom-Json`. It failed instantly on a local run:
`findings.json` is BOM-less UTF-8, 5.1 decoded it as ANSI, and once the Chinese titles became mojibake bytes
even the JSON structure no longer parsed ("expected : or }") — although the file itself is perfectly valid.
Replaced with `[IO.File]::ReadAllText()`. The engine has always used `ReadAllText`, so this trap lives only
in **peripheral scripts** — which is also why every CI step has to be run locally in the same order first,
instead of trusting that it looks right.

**18. `run: & report.ps1` is not a PowerShell quote, it is a YAML anchor.**
After the first push, CI went red with **not a single step in the log**: three lines of
`run: & xxx.ps1` used `&`, YAML's anchor indicator, so the whole file failed to parse, zero jobs started,
and the run title showed the filename. Fix: quote the scalar (`run: '& report.ps1'`). Two lessons: any
command starting with `&` must be quoted whole, and to decide whether a workflow ran you look at the job
list, not the conclusion — a run with zero jobs still gives you a red cross.

**19. `& engine.ps1` resolves locally and fails in Actions.**
A `shell: powershell` step's working directory is the repo root, but a bare filename is not resolved
against CWD: it has to be `& .\engine.ps1`. This surfaced on the second red run — i.e. only after fix #18
made that step reachable — so "get the workflow to run at all" is itself a form of testing. The assertion
was also made self-evidencing: when `NEW != 0`, print every `rule_id | subject` row before throwing,
otherwise the log says only "rescan reported 3 NEW rows" and nobody knows which three.

**20. `Test-Path -LiteralPath` throws on illegal characters, it does not return `$false`.**
`persistence.ps1`, green locally for days, crashed on the runner on its first go: one registry value's
command line contained a newline/control character and `Test-Path -LiteralPath` raised
`ArgumentException: Illegal characters in path`, taking the whole probe with it. Fix: a `Test-Target`
wrapper — `try { Test-Path -LiteralPath $p -ErrorAction Stop } catch { $false }`. Deeper: **the probe
iterates over strings other software wrote into the registry**, so "this is not a path at all" has to be a
normal outcome, never an exception. The intuition "Test-Path returns false" does not hold for
`-LiteralPath` + illegal characters.

**21. The last hop for a scheduled task cannot avoid elevation.**
`\自动拨号` stores the broadband account and password as plaintext `rasdial` arguments. After moving the
value into a CurrentUser DPAPI blob, replacing the task's Action with a wrapper failed on all three paths —
`Set-ScheduledTask`, `Register-ScheduledTask`, `schtasks /change` — every one `0x80070005`, even though the
task's Author is the current user. Cause: a passwordless S4U principal needs `SeTcbPrivilege`; even
changing `LogonType` from S4U to Interactive, which looks like a *reduction* in privilege, is refused
un-elevated. So the deliverable can only be a self-elevating double-click script. Plus one risk I cannot
falsify locally: whether DPAPI CurrentUser can unseal the master key inside an S4U context **can only be
tested from an elevated position** (creating a probe task of that kind already needs administration), so
the wrapper turns that uncertainty into an observable exit code: cannot unseal → `7`, and the script
responds to `7` by rolling back to the original plaintext form. Keeping a known risk is better than
shipping a machine that no longer dials.

**22. My "I re-checked it" evidence window was too short.**
At 14:18 on 10-16 I finished the file-level fix (deleted the plaintext key plus the entire
`*_edge_enclave` family, comparing every other top-level value byte-for-byte before writing), then started
and shut down the browser once to re-check — clean, `BR-07 good`. At 15:55:30 Edge's background process
(Startup boost) came up on its own, and **at 15:55:40 the malicious value was back**, with `session` empty
in the plaintext `Preferences` and no local copy of that value left on disk. So the source of the
recurrence was the cloud configuration under `sync.preferences`, not local residue — and my re-check only
covered "the next time *I* open the browser", not "the time it opens itself". Verifying that a remediation
holds requires a window that spans **whatever actually rewrites the file**, not whichever trigger is easiest
to think of. This is why `BR-05` exists: it does not require me to be smarter, only to run `scan.bat` again
tomorrow.

**23. The group title said "search engine" while the fact behind it was a dead field.**
`probes/browser_prefs.ps1` used to scan the raw text with a regex for `"search_url"|"template_url"`, but the
selected engine lives inside the `default_search_provider_data.template_url_data` object, which that regex
cannot reach — so the field was **always an empty array on this machine** while the report title claimed
search-engine coverage. This class of defect is the hardest to see: no error, no crash, no false positive,
just a permanently clean false negative. It is now read structurally, and the probe prints
`search_read=` in its own output line — a counter that is always 0 proves nothing, a counter that moves is
what self-evidences in a CI log. Fixing it came with `BR-10`: make "could not look" itself a conclusion,
because for a scanner that only reports problems, "nothing found" and "this machine is genuinely clean"
render identically.

**24. Chinese inside a `.ps1` does not just mojibake — it eats the parser.**
`hygiene.ps1` catches Chinese in **comments** (without a BOM it decodes through the active code page). The
layer I hit was worse: the engine's `blind_spots` **string literals** were Chinese, and PowerShell 5.1
answered "an unexpected token in expression or statement" — reported on the `if` **on the next line**. The
error location sits several lines past the offending characters, so navigating back from the message is
guesswork. Fix: the engine emits ASCII codes only (`engine_unreadable` and friends) and all wording lives in
the renderer's `BLIND` map. That turned out to be better layering anyway: criterion language belongs to the
engine, human sentences belong to the template — so shipping an English report later means swapping one
table, not touching any logic.

**25. A "is this translated?" gate that matched every English sentence.**
Shipping two languages needs a machine gate, and the obvious one is
`if (/[\u4e00-\u9fff…]/.test(englishHalf)) fail()`. Mine started its first range with a character that
*looks* like a space and **is** U+0020, so the class ran from U+0020 to U+303F and matched every Latin
letter, digit and punctuation mark on the page. The general form of the trap: a character class whose
endpoint is a Han character can silently swallow the whole ASCII table, and nothing in the source shows it.
It failed 128 correct rows — and, the part that matters, it would have **passed** a page nobody had
translated, because what it asserted was "contains no character from a huge block", not "reads as English".
Fixed in the order that made it provable: write the class with `\u3000`-style escapes so the source cannot
lie about itself, then stop asserting on the source at all. `tools/i18n-probe.html` loads the report at
`?lang=en` and `?lang=zh`, walks every text node and keeps only the ones that own a box on screen, so the
measurement is the prose a reader sees — not the bytes of a file that always contains both languages. And
the gate now keeps Chinese inside English on purpose: PS-01's evidence names the task 自动拨号, PS-07's
names the signer 济南快安网络科技. Those are values a reader has to be able to look for on their own
machine, so translating them would destroy the evidence. What gets asserted instead is a ratio (a
copy-pasted paragraph is 100 % Chinese, a quoted proper noun is under 1 %) plus "the English half may not be
a copy of the Chinese half".

---

## Known-answer tests: 90 PASS / 0 FAIL

The criteria are defined before the scanning logic. Run `powershell -File tools\selftest.ps1`:

```
[1]  browser fixture: the hit set must equal the manifest, row by row
[2]  all 10 browser rules get triggered
[3]  re-scan of the same facts: no CHANGED allowed
[4]  fixture B: fixed, then came back → NEW, and the retired conclusion becomes RESOLVED
[5]  fixture C: the file written again → CHANGED, not NEW
[6]  fixture D: only the rules citing that field light up
[7]  acknowledge downgrades, it never deletes a rule
[8]  persistence fixture: all 7 rules fire, including the 4 idle on a clean machine
[9]  countGte's scalar semantics, asserted in both directions
[10] plant a fake residue → must be NEW, and must not swallow its neighbours
[11] an unknown probe name must throw, facts may never be dropped silently
[12] group title / card title / advice / fingerprint must all be populated
[13] the search engine may only be judged on the protected document, and unreadable must be said out loud
[14] live persistence facts vs predicates re-derived by independent logic
[15] every row called "residue" is independently re-checked as genuinely missing
[16] the English overlay is attached, branch-aligned, and outside the fingerprint
```

**[1]–[13] and [16] run against the two committed synthetic captures in `tests/fixtures/`, so they produce
the same verdict on any Windows** — including a machine that was never hijacked, a machine with no browser
installed, and the throwaway runner in CI. [14][15] run against the real captures under `out\` and print
`SKIP` rather than failing when those files are absent (currently 0 SKIP). (The numbering follows the order
sections were added, which is why a fixture section sits at the end: renumbering [14][15] would break every
reference to them above.)

The fixture is not a snapshot. The manifests `$wantBrowser` / `$wantPers` map each rule to the set of objects
the capture *should* hit, and `Check-Manifest` asserts both directions: nothing may be missing, and no
conclusion may exist outside the manifest (`no finding outside the manifest`). So adding a rule to `rules/`
that unexpectedly lights up another object turns the test red.

[13] pins the semantic boundary of the `BR-09`/`BR-10` pair: the default search engine is a Chromium
**protected preference**, so it can only live in `Secure Preferences`. The two plain-only records in the
fixture therefore must **not** be reported as "engine swapped" even though they literally contain `2345.com`
— that would be an invented accusation. The assertion runs the other way as well: a readable and clean engine
must produce **no** blind-spot row, otherwise `BR-10` degrades into background noise and its entire value —
distinguishing "checked" from "cannot check" — is gone. This section also asserts that none of `BR-09`'s
three remediation branches falls through to the default one, reading the branch text out of the rule file at
runtime rather than copying it into the test: if the wording changes, the assertion changes with it, instead
of quietly becoming a sentence that is always true.

[14] is the other half of what matters: **the expected set is not a copied snapshot, it is re-derived from the
raw facts by independent logic.** So this machine gaining or losing a startup entry tomorrow does not turn the
test red — but a rule implementation drifting away from the criterion it claims does.

[15] exists specifically to stop defect #8 from ever coming back: any row `PS-01` calls residue is
`Test-Path`-ed again inside the test, and a bare command name is judged a defect on sight.

[16] is the gate that keeps the second language honest, and it is the only section that copies the engine
into a scratch directory to run it. Three things are asserted. That every finding arrives with an English
title, `why` and group title. That the translated advice list is indexed by the *same* branch the Chinese
text came from — checked as a mapping (one Chinese branch must always give one English branch, two Chinese
branches may never collapse onto one English string) because a `.ps1` may not contain the Chinese literals
the comparison is about. And, on a scratch copy whose English wording has been deliberately perturbed, that
the engine still emits **byte-identical fingerprints** — which is the proof that a translation can never
disturb a baseline. It closes with three negative runs: a rule with no overlay, an overlay with one advice
branch missing, and a rule file with no English group title must each abort the run rather than render a
half-translated report.

### CI

`.github/workflows/ci.yml` runs the whole chain on `windows-latest`, in the real order:
two probes → `engine -Mode baseline` → `engine -Mode scan` → `report.ps1` → `selftest.ps1` →
`hygiene.ps1` → `node tools/verify.js`.

`verify.js` carries the bilingual checks that need no browser at all: it evaluates the renderer's locale
tables out of `render/template.html`, and fails on a row that is not a `[zh, en]` pair, on an English half
that is still Chinese, on a translated sentence that dropped a `%1` placeholder, and on any of the 17 rules
whose overlay is short. It also checks the *published* demo for the same property, because a visitor who
clicks "English" on a stale artefact gets Chinese anyway — and a stale demo is invisible to every other gate
in here, since its counts can be perfectly correct while its wording is a build behind.

One of those steps is a contract assertion rather than "no error was raised": **create a baseline, re-scan
immediately, and `counts.NEW` must be 0.** If that ever turns red, fingerprint computation has picked up
jitter unrelated to the facts (a timestamp leaking into the evidence, say) — and that is precisely the thing
that decides whether this tool can still tell you what changed.

Two more steps guard the artefacts rather than the working tree: the committed demo is regenerated from the
fixtures and `demo/build.json` compared (a rule change with a stale demo goes red), and the release archive
is rebuilt with `git archive`, unzipped, and checked for CRLF in all three `.bat` files — because the file a
visitor double-clicks is the zip, not your repository.

> This workflow **has actually run three times on GitHub**: red, red, green. Neither red was environment
> flake — both were real defects unreachable from my machine: a YAML anchor indicator that failed the whole
> file (zero jobs started), and an unresolvable relative `& engine.ps1`. See #18 and #19. The first green run
> is number 3, and both failures stay in the history, because for this project a one-shot green CI would be
> the suspicious signal.

There is also `tools/layout-probe.html`: it loads the report into iframes from 360 to 1280px and measures
`scrollWidth`, driven through headless Edge —

```
msedge --headless=new --allow-file-access-from-files --virtual-time-budget=20000 \
       --dump-dom "file:///.../tools/layout-probe.html?lang=en"
```

Re-measured today for **both** wordings: **all 7 widths have 0 horizontal overflow in English and in
Chinese**, which matters because persistence findings are routinely 120-character Windows paths and because
the two languages have different metrics — an English card title is longer, a Chinese evidence label is
wider per glyph. The reason to measure this at all: reports like this get ruined in the middle of "looks
fine on my screen".

`tools/i18n-probe.html` is the same idea applied to wording instead of geometry. Grepping a rendered report
for Chinese proves nothing, because the file *always* contains both languages — the inactive one sits in
hidden spans, and the rule text appears twice inside the data block. So the probe loads the report at
`?lang=en` and `?lang=zh`, keeps only the text nodes that own a box on screen, and reports what a reader
actually sees. On this machine the English render contains exactly three Chinese runs: the language toggle's
own label, one signer company name, and one task path. That is the expected answer, and it is the only
answer that distinguishes "translated" from "the checker cannot tell".

### How the live demo was made

`tools/make-demo.ps1` performs on `tests/fixtures/` exactly what the contract test performs: build a baseline
from the fixtures as they are, then re-inject the malicious startup URL into "the profile that had been
repaired" and re-scan. One page therefore shows `NEW 2`, `CHANGED 1`, `PERSIST 30`, `RESOLVED 1` —
**which is what a baseline diff is actually for**, and what a clean machine can never produce.

It never touches the probes, so it reads nobody's browser or registry, and it gives identical results on any
Windows. The demo page's top banner ("this is a demo, not your machine") is worded in the template and turned
on by a `data-demo` attribute that `report.ps1 -Demo` sets — because a `.ps1` may not contain Chinese
literals (see #24).

---

## Probe coverage

**`browser_prefs.ps1`** — `Preferences` + `Secure Preferences` for every Edge / Chrome profile: startup URLs,
startup mode, sealed key families, `protection.macs` and orphan signatures, `sync.preferences`,
`profile.exit_type`, and the **complete** `profile.content_settings.exceptions` ledger
(`setting|origin|last written`, 1700+ rows in one scan on this machine; WebKit microsecond timestamps are
converted to local time inside the probe, because "when did this machine actually load that page" has to be
readable), `default_search_provider_data.template_url_data` (`keyword` / `short_name` / URL /
`enforced_by_policy`, plus a `search_read` boolean — "cannot read it" is one fact, "read it and it is clean"
is another), and **the contents of past repair backups** (whether a backup contained a malicious value at the
time is the timeline evidence a recurrence verdict is built from).

The probe layer still judges nothing: it hands over both "what I read here" and "what I could not read here"
as facts, and the engine aggregates the latter into `blind_spots` codes
(`no_secure_prefs` / `engine_unreadable` / `prefs_unparseable`).

**`persistence.ps1`** — 8 boot-time surfaces: Run / RunOnce (5 views, WOW6432Node included), the Startup
Folder, scheduled tasks outside `\Microsoft\`, services set to Auto-start that are not in a Windows
directory, ELAM drivers by `Group=Early-Launch`, hosts, IFEO Debugger, Winsock LSP. Each row carries the
target binary's Authenticode signer, status, modification time, size, and `in_windows` / `in_writable`
attribution.

Read-only. It writes no registry key, stops no service, modifies no file, opens no socket. Every suggestion in
the report is something you have to execute yourself — because "the correct remediation" depends on whether a
sealed copy and a sync switch exist, and that judgement does not necessarily transfer to your machine.

---

## Limitations, stated up front

- **Windows only**, relying on `Get-AuthenticodeSignature` / `Get-ScheduledTask` as shipped by PowerShell 5.1.
- The browser rules cover the startup-page and default-search-engine family of hijacks, and `BR-08` adds the
  permissions-and-visits ledger a malicious origin leaves behind. Still **not covered**: extension policy,
  tampering inside other preference sections (new tab page, per-Omnibox engine settings), and scheduled tasks
  that relaunch the browser.
- **The default search engine cannot be read on Edge.** Edge stores
  `default_search_provider_data` as a 40-hex digest plus `_encrypted_hash`; only Chrome, or a user-added
  engine, is a plaintext object. So on this machine `BR-09` has 0 hits while `BR-10` lights up on 4 Edge
  profiles — that is not a miss, it is the capability boundary of this criterion, and it is now a
  baseline-tracked conclusion instead of a confession in a README.
  We did try the `Web Data` SQLite table: every Edge profile on this box contains baidu / sogou / so.com / 360
  `{searchTerms}` templates, because that table is the **available** engine list, not the **selected** one —
  using it as a criterion would report every Chinese-language Edge as hijacked. That path was rejected by
  numbers, not by intuition.
- `BR-08`'s evidence is the `content_settings` ledger, and **it shrinks by itself as the browser writes**:
  measured at 19:05 profile 1 had 1355 rows, Edge rewrote the file itself at 19:24:58, and by 19:27 only 1251
  rows were left; in the same window the hit `trackers_data|https://cdn.weather.hao.360.cn:443,*` went from
  present at 12:38 to absent at 19:27. So it is evidence that "the page was visited and this is what was
  decided then", not a permanent record — and `RESOLVED` does not mean "the user revoked the permission".
- **The report cannot prove that a remediation is durable** — a conclusion measured today, not a disclaimer.
  A profile with `sync.preferences` on will have a file-level fix pushed back by the cloud during the next
  browser start cycle, and the tool can only say so **on the next scan**, as `changed`. That is an intrinsic
  limit of this class of tool; it is written here instead of being buried in "cleanup complete".
- `PS-05` (IFEO) and `PS-06` (LSP) are implemented against the measured registry structure but have no local
  sample. The fixture `tests/fixtures/facts-persistence.json` contains a record that fires each of them, so
  **the predicate logic is executed**; but the "what it looks like in the wild" layer still rests on public
  cases rather than local observation for those two, while ELAM does have local history (`360elam64.sys`).
  Version 1 does not invent success stories for them.
- The baseline is **per machine**: switch machines, or install a batch of software on purpose, and you will
  see many `CHANGED` rows. That is normal.
- `domain_blocklist` matches substrings, so setting `so.com` as your own homepage gets reported. Use
  `ack.bat` to mark it known — do not dull the rule.

---

## Contributing a rule

Add it to `rules/*.json`; the engine is not involved. Fill in `verified_on` and `verified_evidence` with
**the hit count and object names produced on your own machine**. A criterion without measured evidence does
not reach main — every gram of credibility this project has comes from "each rule can be restated as one
concrete observation".

Before writing a predicate, run `powershell -File tools\shape-probe.ps1` (read-only). It dumps the **real
structure** of this machine's browser preference files: which keys exist, where sealed copies hang, what is
actually inside `protection.macs`. Every predicate in main was written against that output rather than against
a format document — which is why the engine reads `restore_on_startup` in `Secure Preferences` and
`startup_setting` in `Preferences` instead of guessing a key name. Defect #23 is the counter-example: a read
path that was never validated against real output can return empty forever without an error.

```bash
powershell -File tools\selftest.ps1     # 90 PASS or it did not pass (the fixture part must be identical on any Windows)
node tools\verify.js                    # structure + label coverage + redaction
powershell -File tools\hygiene.ps1      # .bat must be CRLF; .ps1 must be pure ASCII or carry a BOM
```

If a new rule cannot fire on this machine (`PS-03`–`PS-06` hitting 0 on a clean box is a normal state), add a
record to `tests/fixtures/` that does fire it and write the expected object into the `tools\selftest.ps1`
manifest — otherwise that rule is never executed.

When you introduce a new fact field, every key in `show` needs a label entry in `render/template.html`
(`verify.js` walks all rules and asserts this regardless of local hits), and a new blind-spot code needs an
entry in the `BLIND` map. The engine emits codes, the template owns the sentences — defect #24 explains why
the direction has to be that way.

A new rule also needs `"i18n": { "en": { … } }` with `title`, one `advice` string **per branch**, `why` and
`verified_evidence`, and the rule file needs `i18n.en.group_title`. This is enforced at rule-load time, not
at render time: the engine aborts on a missing or short overlay, because a report that mixes two languages is
harder to disprove than one that fails to build. The overlay is wording only — it cannot see `when`, `show` or
`severity`, so a translation can never change a verdict, and `selftest [16]` is the test that holds that line.
Quote Chinese inside the English text freely when it *is* the evidence (a signer name, a task path); what the
gate rejects is a field that was never translated.

`hygiene.ps1` blocks two classes of failure that Windows does not report as errors: an LF-only `.bat` is
executed half-way by cmd, and a BOM-less `.ps1` is decoded by PowerShell 5.1 through the active code page, so
Chinese in a comment becomes mojibake bytes — and if one of those bytes parses as a quote or a backtick, you
have produced a syntax error that only exists on someone else's machine. (Chinese in a **string literal** is
worse: not mojibake, outright parse failure — see #24.)

The full workflow is in [CONTRIBUTING.md](CONTRIBUTING.md), changes are recorded in [CHANGELOG.md](CHANGELOG.md),
and the security boundary — what counts as a vulnerability here — is in [SECURITY.md](SECURITY.md).

## License

MIT
