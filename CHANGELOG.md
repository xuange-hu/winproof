# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the versions are the tags, and the dates
are the dates the commits landed — this file was written after `v1.0.0` and describes work already in
the tree rather than pretending the history was planned.

## [Unreleased](https://github.com/xuange-hu/winproof/compare/v1.3.0...HEAD)

Nothing pending.

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

[1.3.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.3.0
[1.2.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.2.0
[1.1.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.1.0
[1.0.0]: https://github.com/xuange-hu/winproof/releases/tag/v1.0.0
