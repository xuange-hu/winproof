# Contributing

Start with the README's
[detection inventory](README.md#detection-inventory-23-rules-each-restatable-as-one-concrete-observation)
— every shipped rule there carries the hit count and
subject names it produced on the author's machine. That convention is the whole contribution model:
**a judgement you have not measured does not enter the tree.**

## The one rule that matters

`rules/*.json` is data. If your change needs an engine modification, it is a different kind of
change and worth opening an issue first — the bounded operator set is a security property, not an
accident, and new operators expand the surface that lets a contributed rule do something surprising.

## Adding a rule

1. **Look before you write.** Run `powershell -File tools\shape-probe.ps1` (read-only). It dumps the
   real structure of the browser preference files on your machine. Every predicate in the tree was
   written against that output rather than against a description of the format — which is why the
   parser reads `restore_on_startup` from `Secure Preferences` and `startup_setting` from
   `Preferences` instead of guessing one name. Part of looking is finding **which level of the
   hierarchy carries the thing you match on**: the policy rules first matched registry *value* names,
   which is silent-wrong for every list-shaped policy, because `RestoreOnStartupURLs` and
   `ExtensionInstallForcelist` put their name in the **key** and leave `1`, `2`, `3` as the values.
2. Add the rule to `rules/browser.json` or `rules/persistence.json`, filling `verified_on` and
   `verified_evidence` with **your** measured hit count and subject names.
3. If it does not fire on your machine, add a fixture row in `tests/fixtures/` that *does* fire and
   list the expected subjects in the `$wantBrowser` / `$wantPers` manifest in `tools/selftest.ps1`.
   A rule with no executing test is a rule whose predicate can be inverted and nobody finds out
   until it matters. When the rule reads a surface the fixture did not carry before, give it a
   **neighbour that must stay clean**, not just a positive row: `BR-11` ships three shortcut rows, one
   hijacked and two benign (one with no URL, one with a legitimate `--app-url`), because a manifest
   check alone would still pass if the predicate had been weakened to "any shortcut carrying any URL".
   If your predicate **fires on a clean machine**, the negative row is not enough on its own — scope the
   capture instead, and put the excluded class in the fixture so the scoping itself is tested. `BR-13`
   is that case: "the handler no longer resolves" fired 13 times on the author's healthy box, because
   AppX package identifiers never resolve under `Classes`. The probe now labels those rows `appx` and
   the rule ignores them, and the fixture carries one AppX-shaped dangling identifier that must stay
   silent — without it, a future edit that drops the classifier turns those 13 false positives back on
   and every manifest assertion still passes.

   A rule whose trigger is a **list of names** has the mirror-image problem, and `BR-14` is that case:
   on a clean machine it cannot fire at all (the whole policy surface here is 3 rows, none forcing), so
   its positive rows can only come from the fixture — and then the negatives are what make the list
   honest. The fixture therefore plants `MetricsReportingEnabled` and `CloudPrintProxyEnabled` beside the
   rows that must fire, and asserts they stay silent. Widen that name list to "any policy counts" and
   every other assertion in the suite still passes while a managed corporate laptop lights up red forty
   times; the negative rows are what turn that edit into a failing test instead of a release.
4. If your rule cites a new evidence field, add its `[zh, en]` label pair to the table in
   `render/template.html` (and to `BLIND` if it is a blind-spot code). `tools/verify.js` walks every
   `show` key in every rule file and fails on an untranslated one, regardless of whether it fired.
   If your rule introduces a new **subject kind** rather than a new field, the engine's `subject`
   string is `"<kind> / <name>"`; `KIND` in the template translates known prefixes and passes anything
   else through, so a new kind is readable without a code change — but check the rendered card, because
   a machine-level subject has no profile to name itself after.
5. **Write the English wording**, or the run aborts. A rule needs an `i18n.en` block with `title`, one
   `advice` string *per branch* of your `advice` list, `why` and `verified_evidence`; the rule file needs
   `i18n.en.group_title`. The engine validates this while loading rules, not while rendering, so a short
   overlay is a build failure rather than a half-translated report:

   ```json
   "i18n": { "en": {
     "title": "A resident binary lives in a user-writable directory",
     "advice": ["What to do, branch 1 …", "What to do, the fallback branch …"],
     "why": "Why this criterion deserves to exist.",
     "verified_evidence": "Hits on my machine: service/Foo (C:\\ProgramData\\…), 2 scheduled tasks."
   }}
   ```

   The overlay may only contain wording: it has no access to `when`, `show` or `severity`, so a
   translation cannot change what fires — `selftest [16]` re-runs the engine on a copy whose English was
   perturbed and requires byte-identical fingerprints. Quote Chinese inside the English text when the
   Chinese *is* the evidence (a signer company name, a task path); the gate rejects a field that was
   never translated, judged by CJK ratio, not by presence.
6. Rebuild the demo: `powershell -File tools\make-demo.ps1`. CI compares `demo/build.json` against a
   fresh build and goes red when the committed page no longer matches the rule set — and `verify.js`
   checks that the committed demo carries the English wording too, because its counts can stay correct
   while its text is a build behind.

```bash
powershell -File tools\selftest.ps1     # must end in "0 FAIL", and 0 SKIP on a machine with out\
node tools\verify.js                    # structure + label coverage + redaction + the published demo
powershell -File tools\hygiene.ps1      # .bat CRLF, .ps1 encoding
```

## Two Windows traps that will bite you

- **A `.ps1` must be pure ASCII, or UTF-8 with BOM.** Windows PowerShell 5.1 decodes a BOM-less file
  using the active codepage, so Chinese in a comment becomes garbage bytes and — if one of those
  bytes parses as a quote or backtick — a syntax error that only appears on someone else's machine.
  Chinese in a *string literal* is worse: parsing fails outright, and the error is reported several
  lines past the cause. This has happened here; the rule is that engine output carries ASCII codes
  (`engine_unreadable`) and the wording lives in the template's lookup table.
- **A `.bat` must be CRLF.** `cmd.exe` mis-parses LF-only batch files in ways that surface as
  unrelated syntax errors. `.gitattributes` pins this at checkout, so do not fight it.

## What gets rejected

- A rule with no `verified_evidence`.
- A vendor keyword blocklist as a judgement ("anything signed by FooInc is suspicious"). Attribution
  by signature works on what is actually on the machine; keyword lists only catch what somebody
  already wrote into a list.
- Anything that writes to, deletes from, or "repairs" the system. The advice column tells a human
  what to do, because whether a fix will stick depends on sealed copies and sync flags that this
  tool cannot know about on your machine.
- A "clean" scan result that cannot say what it could not see. If a surface is unreadable, it should
  become a `BR-10`-style blind-spot finding, not a silent zero.

## Pull requests

Squash-free: small commits with a sentence each about *why*, since the git log is the design record
for a project this size. CI must be green on `windows-latest` before review — a workflow that has
never run is not a test.
