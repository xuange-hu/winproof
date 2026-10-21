# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the versions are the tags, and the dates
are the dates the commits landed — this file was written after `v1.0.0` and describes work already in
the tree rather than pretending the history was planned.

## [Unreleased](https://github.com/xuange-hu/winproof/compare/v1.5.0...HEAD)

Nothing pending.

## [1.5.0] — 2026-10-21

Two rules about the one layer the browser's settings page cannot reach, plus a capability the whole report
had been missing: **when a registry key was written**. 23 rules, 96 assertions, three CI gates
(`selftest.ps1`, `verify.js`, `hygiene.ps1`), two headless probes, one double-click entry point.

### Added

- **BR-14 — a browser policy forces a setting.** The probe now walks `SOFTWARE\Policies` for Edge, Chrome,
  Chromium and Brave under HKCU and HKLM, with HKLM read in both the 64-bit and the `WOW6432Node` view, and
  hands over every value verbatim. The trigger is a list of 28 policy *names* that force a startup page,
  homepage, new tab, search engine, extension list, proxy, DoH or managed bookmarks — kept in the rule file
  as data, so a contributed policy name never becomes executable input. The hive is a separate fact on
  purpose: HKCU means something running as you wrote it, HKLM means something that could elevate, and the
  two get different remediation.
- **BR-15 — a policy pre-grants a permission, or an empty policy key sits in the user hive.** A second list
  of 14 names catches the quieter class: policies that delete a confirmation the browser would otherwise
  show. One real row on the author's machine — `LocalNetworkAccessAllowedForUrls` under HKLM Edge — means a
  named origin may reach devices on the local network with no prompt, ever. An empty policy key (0 values,
  0 subkeys) under HKCU is reported too: it changes nothing, and it is still evidence that something
  created the location and wrote nothing into it.
- **Registry write times, via P/Invoke.** The registry provider exposes no last-write time at all, so the
  probe calls `advapi32!RegQueryInfoKey` for it. Every policy row now carries the second it was written in,
  which is what lets two rows sharing a second be read as one install action. The probe also emits
  `policy_mtime` so a reader can tell whether a given capture had timestamps available.

### Changed

- Rule count 21 → 23, browser group 13 → 15, fixture policy rows 0 → 7, selftest assertions 92 → 96,
  fixture subjects 16 → 23, live baseline findings 29 → 32 on the author's machine.
- Predicates match `pol_name`, derived by the engine from the last segment of the key path. Matching the
  registry *value* name is wrong for every list-shaped policy: `RestoreOnStartupURLs`,
  `ExtensionInstallForcelist`, `LocalNetworkAccessAllowedForUrls` and `URLBlocklist` carry their name in the
  key and only an index in the value, so a value-name match misses exactly the strongest entries. The engine
  smoke test caught this — a real HKLM grant sat in the list without firing.
- `BR-14` is the first rule whose known answer is entirely inside the fixture, because a clean machine cannot
  produce a positive case for it. The fixture therefore carries three rows that must stay silent
  (`MetricsReportingEnabled`, `CloudPrintProxyEnabled`, and an empty key under HKLM); without those negatives,
  widening the list to "any policy counts" keeps every other assertion green while turning a managed
  corporate laptop red.
- Two candidate rules were measured and **dropped** instead of shipped: a scheduled-task browser relauncher
  (0 of 206 tasks on this machine carry any browser command line) and a forced-extension/DNS-over-HTTPS check
  with no local sample at all. Both are recorded here as refusals, because the project's evidence rule cuts
  both ways.

### Fixed

- `RegQueryInfoKey` declared with 13 parameters returns `rc = 0` and leaves the FILETIME at 0, so every key
  looks never-written and nothing errors. The signature has exactly 12; the call was validated against the
  managed `ValueCount`/`SubKeyCount` on 8 real keys before the parameter list was identified as the culprit,
  and `Get-KeyWriteTime` now returns an empty string rather than a fabricated zero date.

## [1.4.0] — 2026-10-20

Two new rules, both about the layer that **writes** the other layers. 21 rules, 92 assertions, three CI
gates (`selftest.ps1`, `verify.js`, `hygiene.ps1`), two headless probes, one double-click entry point.

### Added

- **BR-12 — a registry browser launch command contains a URL.** The probe now reads every
  `SOFTWARE\Clients\StartMenuInternet\<app>\shell\open\command` in both hives, plus the ProgIDs that
  `http`/`https` and the browser document types actually resolve to — resolved through `UserChoice` with
  the user hive before the machine hive, because that is the order the shell itself uses. This is the
  layer that decides what "open a browser on this machine" executes at all, so it re-applies a hijack to
  every profile and every shell-initiated open.
- **BR-13 — a browser file type is still claimed by a program that is gone.** `.htm`/`.html`/`.shtml`/
  `.xhtml`/`.mhtml` `UserChoice` entries are captured with their ProgID, whether that ProgID resolves
  anywhere under `Classes`, and whether the choice carries a `Hash` (a Hash means some program wrote it
  through the supported API rather than having a key dropped in by hand). Reported as residue, not as an
  active hijack — a handler that no longer resolves cannot re-hijack anything, but the machine is holding
  a dead claim on every saved web page, and the row is timeline evidence of what was installed and removed.
- **Two machine-level subject kinds**, `browser_launch_cmd` and `browser_file_assoc`, so a report's subject
  count is now profiles + shortcuts + launch commands + file-type associations.
- **BR-13 caught something real the day it was written.** On the author's machine `.htm` and `.html` both
  point at a ProgID called `ZEROBURL` that exists in neither `Classes` hive, each with a valid
  `UserChoice` Hash: a program took over those two file types properly and was later removed. It is in the
  live-scan table in the README, and it is why `verified_evidence` is mandatory — BR-12 shipped with 0 hits
  and would otherwise have been an unverifiable claim.

### Changed

- 19 rules → 21; the browser group is now 13 rules. Known-answer assertions 91 → 92, fixture subjects
  8 → 16 (baseline findings 23 → 27).
- **The asymmetry between BR-11 and BR-12 is documented, not incidental.** `BR-11` fires only on a
  blocklist hit, because a `.lnk` that opens a URL is a normal Windows construct — that is what a PWA
  launcher is. `BR-12` fires on *any* literal URL: a sweep of both `Classes` hives found 33 browser-named
  open commands and not one carries a URL, so presence is the anomaly and reputation only picks which
  advice you get.
- **`BR-13`'s capture was scoped by measurement, not by taste.** Its naive predicate ("the handler no
  longer resolves") fires 13 times on a clean machine, because AppX package identifiers never resolve
  under `Classes`. Those are classified as `appx` and excluded; the exclusion count is recorded in the
  rule's evidence rather than left as an unexplained gap.
- **Exe-existence judgement was deliberately not implemented.** Slicing an executable path out of a
  command line is unreliable for unquoted paths containing spaces, and a wrong slice would report "the
  program is missing" about a browser that is installed. The resulting gap — a handler that resolves but
  points at a deleted binary (`HKCU\SOFTWARE\Classes\secure-browser`, which turns out to be an
  `AvastBrowser.exe` that is no longer there) — is named in Limitations instead of being papered over.
- The fixture gained 8 rows (4 launch commands, 4 associations) with the negatives chosen from the real
  near-misses: an OEM `--brand-quark` flag, a `--single-argument %1` placeholder, an AppX-shaped dangling
  identifier, and a live handler. One BR-12 row must fire **without** the blocklist, which is what keeps
  the BR-11/BR-12 difference from silently collapsing back into each other.
- `probes/browser_prefs.ps1` emits `launch_cmds` and `file_assocs` arrays; `engine.ps1` reads them;
  `render/template.html` gained `[zh, en]` label pairs plus value maps for `cmd_source`, `cmd_value`,
  `cmd_urls`, `cmd_bad`, `assoc_progid`, `assoc_kind`, `assoc_hash`.
- The README's live-scan block is re-measured on 2026-10-20 (`subjects=82 rules=21 findings=29`).
- `CONTRIBUTING.md` states the negative-row requirement for a rule whose naive predicate fires on a clean
  machine, and points at the AppX case as the worked example.

## [1.3.0] — 2026-10-20

One new rule, and the first one that reads a surface outside the browser profile directories.
19 rules, 91 assertions, three CI gates (`selftest.ps1`, `verify.js`, `hygiene.ps1`), two headless
probes, one double-click entry point.

### Added

- **BR-11 — a browser shortcut carries a forced startup URL.** The probe now walks Desktop, both Start
  Menu trees and the pinned-Taskbar folder through `WScript.Shell`, keeps only shortcuts whose target
  resolves to a browser binary, and reports the URL tokens found in the arguments. A hijack that edits
  the `.lnk` instead of the prefs file opens the page on every launch from that icon while touching no
  profile key at all — and it quietly re-applies itself over a BR-01 repair done from the settings UI.
  The judgement reuses the existing `domain_blocklist`, so the rule adds a **surface**, not a new
  opinion; the probe stays reputation-blind and the blocklist match happens in the engine.
- **A machine-level subject kind.** `New-BrowserSubjects` now emits `browser_shortcut / <name>` subjects
  alongside the per-profile ones, which is why a report's subject count is profiles *plus* shortcuts.
  The renderer passes an unknown subject prefix through unchanged, so no template code was needed.
- **The fixture carries a negative for it.** `tests/fixtures/facts-browser.json` gained three shortcut
  rows: one `chrome.exe` with `http://www.2345.com/?cid=win23` appended, one bare `msedge.exe` with only
  `--profile-directory`, and one `msedge_proxy.exe` PWA launcher whose `--app-url` is legitimate.
  `selftest [1]` asserts the hit set is exactly the first row — a manifest check alone would keep passing
  if the predicate had degraded to "any shortcut with any URL", and this rule has 0 hits on the author's
  machine, so the fixture is the only place its logic is actually executed.

### Changed

- 18 rules → 19; the browser group is now 11 rules. Known-answer assertions 90 → 91, and the fixture
  subject count 5 → 8 (baseline findings 22 → 23).
- `probes/browser_prefs.ps1` emits a `shortcuts` array in its payload; `engine.ps1` reads it;
  `render/template.html` gained `[zh, en]` label pairs for `path`, `lnk_target_exe`, `lnk_args`,
  `lnk_urls`, `lnk_url_bad` — `verify.js` fails a `show` key with no label, fired or not.
- The README's live-scan table is re-measured on 2026-10-20 (`subjects=69 rules=19 findings=27`), which
  also documents how a rule retires: `PS-08` no longer fires because the author's dial task had its
  plaintext arguments removed, but it cannot be reported as `RESOLVED` — it postdates the 2026-10-15
  baseline, so there is no baseline record to retire. "This stopped being a problem" and "this was never
  measured" are different statements, and the report must be able to say which one it is making.
- `CONTRIBUTING.md` now states the negative-row requirement, and what to do when a rule introduces a new
  subject kind rather than a new evidence field.

## [1.2.0] — 2026-10-18

One new rule, and its whole difficulty is that it reports a finding *about* a secret without ever
carrying the secret. 18 rules, 90 assertions, three CI gates (`selftest.ps1`, `verify.js`,
`hygiene.ps1`), two headless probes, one double-click entry point.

### Added

- **PS-08 — a credential stored in plaintext on a command line.** A startup entry whose command carries a
  secret as an argument (`rasdial <conn> <user> <pass>`, `net user <name> <pass>`, or a
  `--password=` / `token=` / `api_key=` style flag) is high severity. Neither antivirus nor a startup
  manager reads the *arguments* of a command that is itself legitimately signed, so this is a class the
  usual tools never look at. It fired on the author's machine on the first run: scheduled task `\自动拨号`
  whose action is `rasdial 宽带连接 <account> <password>`, resolved to `System32\rasdial.exe` with a valid
  Microsoft signature — which is exactly why the existing broken-link and unsigned-binary rules correctly
  stayed silent about it.
- **The rule reports the exposure without ever carrying the secret.** The probe computes a masked copy
  (`cmd_masked`, e.g. `rasdial 宽带连接 *** ***`) alongside a `cmd_secret_kind` classifier, and PS-08's
  `show` lists only the masked field. `tools/verify.js` keeps its dedicated gate — it derives the real
  dial tokens from the local facts and asserts they appear 0 times in the shipped report — and now also
  fails if any finding cites the raw `command` or if a PS-08 dial row is surfaced unmasked. Because the
  fingerprint is built from the masked value, rotating the password leaves the row `PERSIST` rather than
  flipping it to `CHANGED`, which is the correct reading: the exposure is the shape, not the value.
- 17 rules → 18. The persistence group is now 8 rules; `tools/selftest.ps1 [8]` exercises all eight
  against the fixture (including the five that stay idle on a clean box) and asserts high severity comes
  only from PS-03/04/05/06/08. Assertion count is unchanged at 90 — the new rule reuses the coverage
  assertions rather than adding net-new ones.

## [1.1.0] — 2026-10-18

The report is now bilingual without the evaluation becoming locale-aware. 90 assertions behind the
three CI gates (`selftest.ps1`, `verify.js`, `hygiene.ps1`), plus two headless probes
(`layout-probe.html`, `i18n-probe.html`) that measure geometry and wording rather than gate a merge,
and one double-click entry point.

### Added

- **The report is bilingual.** Each rule file carries its own English wording under `i18n.en`
  (`title`, one `advice` per branch, `why`, `verified_evidence`) plus a document-level
  `i18n.en.group_title`; the engine attaches it to every finding in the same pass that computes the
  fingerprint, and the renderer chooses the language when the page opens — `navigator.language`,
  overridable with `?lang=en` / `?lang=zh`, with a toggle in the header. Where the script never runs,
  the page is still a complete Chinese report.
- **The overlay is wording only, and that is enforced in three places.** It cannot reach `when`, `show`
  or `severity`; a missing or short overlay aborts the run at rule-load time; and
  `tools/selftest.ps1 [16]` re-runs the engine against a scratch copy whose English wording was
  deliberately perturbed and requires byte-identical fingerprints. `findings.json`, `store\baseline.json`
  and every fingerprint stay locale-free, so a translation edit can never turn `PERSIST` rows into
  `CHANGED`. 81 assertions → 90.
- **`tools/i18n-probe.html`** measures the wording the way `layout-probe.html` measures the geometry:
  it loads the report at both locales, keeps only text nodes that occupy a box on screen, and reports
  the distinct Chinese runs that survive an English render. Grepping the file cannot answer this
  question, because the file always contains both languages.
- **`tools/verify.js`** now evaluates the renderer's locale tables out of the template and fails on a
  row that is not a `[zh, en]` pair, on an English half that is still Chinese, on a translated sentence
  that dropped a `%1` placeholder, on a rule whose overlay is short, and on a committed demo whose rows
  carry no English wording. Chinese inside English is allowed on purpose where it is the evidence
  (a signer company name, a task path) and is asserted as a ratio instead.
- **`docs/report-zh.png`**, and `docs/report.png` re-shot: the README now shows the same run in both
  languages. The layout claim was re-measured for both wordings — 7 widths, 0 horizontal overflow each.

### Changed

- `tools/layout-probe.html` forwards its own `?lang=` to the iframe and records the locale in each
  result row, so a dump says which wording it measured.
- `render/template.html`: evidence keys render under a `raw` class instead of `zh`, the byte-delta and
  signature-status strings go through the locale tables rather than carrying full-width parentheses
  into both languages, and the footer counters use `data-f` attributes because two language copies
  cannot share an `id`.
- `README.md` / `README.zh-CN.md` / `CONTRIBUTING.md` document the overlay requirement, the new
  assertion count and the second screenshot.

## [1.0.0] — 2026-10-18

First tagged release. 17 rules, 81 known-answer assertions, three gates (`selftest.ps1`,
`verify.js`, `hygiene.ps1`), one double-click entry point.

### Added

- **`BR-09` — default search engine hijack, or an engine forced by policy.** Reads
  `default_search_provider_data.template_url_data` from the protected document. The policy half of
  the condition matters: a hijacked engine you can change in Settings and one you cannot are
  different incidents with different remediations.
- **`BR-10` — blind spots as a finding.** Per object, which surfaces this tool could not read:
  no `Secure Preferences`, an engine stored as a hash, an unparseable document. Before this, "0 hits"
  meant "clean" and "never looked" produced the same page. On the author's machine `BR-09` reports 0
  and `BR-10` reports 4, and the difference between those two numbers is the point.
- **`BR-08` — blocklisted origins still holding content-setting grants.** The browser's own ledger of
  origins it loaded, with each write time decoded from WebKit microseconds. A startup URL proves a
  configuration; a grant proves the page was reached.
- **`tools/make-demo.ps1` + a published demo report**, rendered from the committed fixtures so the
  states a clean machine cannot produce (`NEW`, `CHANGED`, a retired conclusion) are visible to
  anyone, on any OS. CI rebuilds it and compares `demo/build.json`, so the page cannot drift from
  the rules.
- **`SECURITY.md`, `CONTRIBUTING.md`, issue forms** for false positives and rule proposals.
- **`tools/shape-probe.ps1` in the README.** The grounding probe every predicate was written against
  has been in the tree since the start; it was simply never mentioned.

### Fixed

- **The search-engine claim in the README had no implementation behind it.** The probe scanned raw
  text with a regex for `"search_url"|"template_url"`, which never matches the real key, so the fact
  was permanently empty: a silent false negative that could not fail any test, because the field it
  would have failed on was the one that never had a value. Now a structured read, and the probe
  prints `search_read=` so a counter that is stuck at zero is visible in the log.
- **A plain-only profile could not be reported at all.** `New-BrowserSubjects` chose an anchor
  document (`Secure Preferences` ?? `Preferences`) and then read fields only when the secure copy
  existed. `BR-01`/`BR-03` also required `doc_role=secure`. Found while writing the fixture whose
  only purpose was to hit that point.
- **The home-path redaction check in `verify.js` was passing vacuously** — it searched the raw path
  while `ConvertTo-Json` had escaped every backslash, so a real leak scored zero occurrences.
- **`Test-Path -LiteralPath` throws on illegal characters** instead of returning `$false`, which took
  down the persistence probe on the CI runner (a registry command line contained a control
  character) while passing locally. Wrapped in `Test-Target`: a string that is not a valid path is a
  normal result when the string came from somebody else's registry.
- **`PS-01` reported `rasdial` as a missing file.** A bare command name resolves through `PATH`;
  `Resolve-BareCommand` cut the residue findings from 2 to the 1 real one. The same command line
  carries a plaintext dial-up password, which is why the redaction test extracts those tokens from
  the facts file and asserts none reach the HTML.
- **`countGte` on a scalar took the number, not the element count**, so `host_effective = 0` read as
  one entry and every machine was reported as having a hijacked hosts file.
- **`-Value [string]$x` in argument mode is not an expression**, so group titles silently rendered as
  the literal string `"[string]@{...}.group"`. Caught from a screenshot; now asserted directly.

### Changed

- Blind-spot text moved out of `engine.ps1` into the template's code table. A CJK string literal in a
  BOM-less `.ps1` breaks PowerShell 5.1 parsing, and the parser reports the failure several lines
  past the cause. The engine emits ASCII codes; the renderer owns the sentences.
- Baseline is never auto-updated, by design — otherwise whatever wrote to your machine gets laundered
  the next time you re-capture.

## 0.1.0 — 2026-10-15 (untagged: the first commit predates the first tag)

Initial tree: read-only probes, JSON rules over a bounded operator AST, evidence-scoped fingerprints,
baseline diff with `NEW / CHANGED / PERSIST / KNOWN / UNBASELINED / RESOLVED`, and a self-contained
static HTML report.

### Changed

- The contract suite moved from the author's laptop to `tests/fixtures/`. It originally asserted
  against a live capture, which meant it could only pass on one machine — the one that had actually
  been hijacked. Sections [1]–[13] now run on committed synthetic captures and give the same verdict
  on a machine that has never seen an infection, or has no browser installed.

## Notes on what is *not* here

- No PS7 support claim: `pwsh` was never available to test against, and a tool that says "and also
  PowerShell 7" without having run it is lying about one of its two runtimes.
- No rule for a malware family, and no cleaning action. The report tells a human what to do because
  whether a remediation sticks depends on sealed copies and sync flags that vary per machine.
- `PS-05` (IFEO) and `PS-06` (Winsock LSP) have no real-world sample from this machine. Their
  predicates are executed by fixture, so the logic is tested; the description of what a hit looks
  like in the wild comes from public cases, and the README says so instead of inventing a success
  story.

[1.5.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.5.0
[1.4.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.4.0
[1.3.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.3.0
[1.2.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.2.0
[1.1.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.1.0
[1.0.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.0.0
