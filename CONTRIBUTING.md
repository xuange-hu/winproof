# Contributing

Start with the README's
[detection inventory](README.md#detection-inventory-17-rules-each-restatable-as-one-concrete-observation)
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
   `Preferences` instead of guessing one name.
2. Add the rule to `rules/browser.json` or `rules/persistence.json`, filling `verified_on` and
   `verified_evidence` with **your** measured hit count and subject names.
3. If it does not fire on your machine, add a fixture row in `tests/fixtures/` that *does* fire and
   list the expected subjects in the `$wantBrowser` / `$wantPers` manifest in `tools/selftest.ps1`.
   A rule with no executing test is a rule whose predicate can be inverted and nobody finds out
   until it matters.
4. If your rule cites a new evidence field, add its Chinese label to the table in
   `render/template.html` (and to `BLIND` if it is a blind-spot code). `tools/verify.js` walks every
   `show` key in every rule file and fails on an untranslated one, regardless of whether it fired.
5. Rebuild the demo: `powershell -File tools\make-demo.ps1`. CI compares `demo/build.json` against a
   fresh build and goes red when the committed page no longer matches the rule set.

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
