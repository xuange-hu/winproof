const fs = require('fs');
const path = require('path');

// Verification harness for the generated report: proves the data block parses,
// every finding carries the fields the UI needs, every citable evidence field has
// a Chinese label, and no owner identity or credential leaked through redaction.
// Node is only used for this check; nothing in the shipped tool depends on it.

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'out', 'report.html'), 'utf8');

let bad = 0;
function fail(msg) { console.log('FAIL: ' + msg); bad++; }

const m = html.match(/<script id="wp-data" type="application\/json">([\s\S]*?)<\/script>/);
if (!m) { console.log('FAIL: no data block'); process.exit(1); }

const raw = m[1];
const unescaped = raw.split('<\\/script>').join('</script>');
let d;
try { d = JSON.parse(unescaped); } catch (e) { fail('JSON parse: ' + e.message); process.exit(1); }

console.log('data block: ' + raw.length + ' B, parses OK');
console.log('rules=' + d.rules_total + ' subjects=' + d.subjects_total + ' findings=' + d.findings.length);
console.log('severity=' + JSON.stringify(d.severity_counts));
console.log('counts=' + JSON.stringify(d.counts));
console.log('scanned_at=' + d.scanned_at + ' baseline=' + (d.baseline_at || 'none'));

for (const f of d.findings) {
  const miss = ['rule_id', 'title', 'severity', 'state', 'subject', 'key', 'fingerprint', 'advice']
    .filter((k) => f[k] === undefined || f[k] === null || f[k] === '');
  const evKeys = Object.keys(f.evidence || {});
  const line = '   ' + f.rule_id + ' ' + (f.severity + '    ').slice(0, 6) +
    (f.state + '          ').slice(0, 11) + ' ' + f.subject;
  console.log(line + ' | ' + f.title + ' | ev=' + evKeys.length +
    (miss.length ? ' MISSING:' + miss.join(',') : ''));
  if (miss.length) fail(f.rule_id + '|' + f.subject + ' missing ' + miss.join(','));
}

// Every field a rule may cite in `show` needs a Chinese label in the template, or
// the report renders a raw key next to a Chinese sentence. Checked against all
// rule files rather than only the findings that fired on this box: a rule whose
// condition is idle here (PS-03..PS-06 on a clean machine) still ships its fields.
const tpl = fs.readFileSync(path.join(root, 'render', 'template.html'), 'utf8');
const cited = new Set();
for (const n of fs.readdirSync(path.join(root, 'rules'))) {
  if (!n.endsWith('.json')) continue;
  const rj = JSON.parse(fs.readFileSync(path.join(root, 'rules', n), 'utf8'));
  for (const r of (rj.rules || [])) for (const k of (r.show || [])) cited.add(k);
}
const unlabeled = [...cited].filter((k) => !new RegExp('\\n\\s+' + k + ': \\[').test(tpl));
const firedKeys = new Set();
for (const f of d.findings) for (const k of Object.keys(f.evidence || {})) firedKeys.add(k);
console.log('--- label coverage ---');
console.log('citable evidence fields: ' + cited.size +
  ' | fired on this box: ' + firedKeys.size +
  ' | without a Chinese label: ' + unlabeled.length);
if (unlabeled.length) fail('unlabeled fields ' + unlabeled.join(','));

console.log('--- i18n ---');
// The report is bilingual, so "is it translated" is now a checkable property of
// three separate artefacts: the renderer's own locale tables, the rule files'
// i18n.en overlays, and the overlay the engine attached to each finding row.
// All three are read from source rather than from a screenshot, because a
// missing translation is invisible in a screenshot that happens to be Chinese.
const CJK = /[\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]/;
const lt = tpl.match(/WP-LOCALE-TABLES-BEGIN[\s\S]*?--\s*\*\/([\s\S]*?)\/\*[\s\S]*?WP-LOCALE-TABLES-END/);
if (!lt) {
  fail('locale table block not found between the WP-LOCALE-TABLES markers');
} else {
  let tables;
  try {
    tables = new Function(lt[1] +
      ';return {S:S,F:F,HIT:HIT,KIND:KIND,DRV:DRV,DOC:DOC,BLIND:BLIND,SEV:SEV,ST:ST};')();
  } catch (e) {
    fail('locale tables do not evaluate: ' + e.message);
    tables = {};
  }
  const rows = [];
  for (const name of Object.keys(tables)) {
    for (const k of Object.keys(tables[name] || {})) rows.push([name, k, tables[name][k]]);
  }
  const notPair = rows.filter((r) => !Array.isArray(r[2]) || r[2].length !== 2);
  const emptyHalf = rows.filter((r) => Array.isArray(r[2]) &&
    r[2].some((s) => typeof s !== 'string' || s.trim() === ''));
  const zhInEn = rows.filter((r) => Array.isArray(r[2]) && CJK.test(String(r[2][1])))
    .map((r) => r[0] + '.' + r[1]);
  // A translated sentence that drops a %1 placeholder renders a card with a hole
  // in it, and the hole only appears in the language nobody screenshotted.
  const slotMismatch = rows.filter((r) => {
    if (!Array.isArray(r[2]) || r[2].length !== 2) return false;
    const g = (s) => (String(s).match(/%\d/g) || []).sort().join(',');
    return g(r[2][0]) !== g(r[2][1]);
  }).map((r) => r[0] + '.' + r[1]);
  console.log('locale rows: ' + rows.length + ' | not a pair: ' + notPair.length +
    ' | empty half: ' + emptyHalf.length + ' | Chinese inside English: ' + zhInEn.length +
    ' | %N mismatch: ' + slotMismatch.length);
  if (notPair.length) fail('not a [zh,en] pair: ' + notPair.map((r) => r[0] + '.' + r[1]).join(','));
  if (emptyHalf.length) fail('empty wording in ' + emptyHalf.map((r) => r[0] + '.' + r[1]).join(','));
  if (zhInEn.length) fail('untranslated English half: ' + zhInEn.join(','));
  if (slotMismatch.length) fail('placeholder count differs: ' + slotMismatch.join(','));
  // The label-coverage regex above only proves the key appears in the file; this
  // proves the renderer can actually reach it, which is what a card needs.
  const missing = [...cited].filter((k) => !(tables.F || {})[k]);
  console.log('citable fields with no table entry: ' + missing.length);
  if (missing.length) fail('evidence fields absent from F: ' + missing.join(','));
}

// Rule overlays: the engine refuses to load a rule whose overlay is short, but
// the engine only runs on a Windows box, and the rule JSON is the part a
// contributor edits. This is the same contract checked where it can be checked
// from any platform.
//
// English rule prose is allowed to contain Chinese, and must: PS-01's evidence
// names the task 自动拨号 and PS-07's names the signer 济南快安网络科技. Those are
// values a reader has to be able to find on their own machine, so translating
// them would destroy the evidence. The failure mode worth catching is the
// opposite - a field that was never translated at all - and that is a ratio: a
// sentence written in English with a quoted proper noun inside is a few percent
// CJK, a copy-pasted Chinese paragraph is all of it.
const CJK_ALL = new RegExp(CJK.source + '+', 'g');
function cjkRatio(s) {
  const m = String(s).match(CJK_ALL);
  return (m ? m.length : 0) / Math.max(1, String(s).length);
}
let overlayRules = 0, overlayShort = [], survivorRuns = new Set();
for (const n of fs.readdirSync(path.join(root, 'rules'))) {
  if (!n.endsWith('.json')) continue;
  const rj = JSON.parse(fs.readFileSync(path.join(root, 'rules', n), 'utf8'));
  if (!rj.i18n || !rj.i18n.en || !rj.i18n.en.group_title) overlayShort.push(n + ':group_title');
  for (const r of (rj.rules || [])) {
    overlayRules++;
    const en = r.i18n && r.i18n.en;
    if (!en) { overlayShort.push(n + ':' + r.id); continue; }
    const fields = ['title', 'why', 'verified_evidence']
      .map((k) => [k, String(en[k] || ''), String(r[k] || '')])
      .concat((en.advice || []).map((a, i) => ['advice[' + i + ']', String(a), '']));
    let bad = '';
    for (const [k, enText, zhText] of fields) {
      if (!enText) { bad = k + ' empty'; break; }
      if (zhText && enText === zhText) { bad = k + ' is a copy of the Chinese'; break; }
      if (cjkRatio(enText) > 0.1) { bad = k + ' is ' + Math.round(cjkRatio(enText) * 100) + '% Chinese'; break; }
      for (const run of (enText.match(CJK_ALL) || [])) survivorRuns.add(run);
    }
    if (!Array.isArray(en.advice) || en.advice.length !== (r.advice || []).length) bad = 'advice count';
    if (bad) overlayShort.push(n + ':' + r.id + ' (' + bad + ')');
  }
}
console.log('rules with a complete English overlay: ' +
  (overlayRules - overlayShort.length) + '/' + overlayRules);
console.log('Chinese kept inside English prose (data, not untranslated text): ' +
  (survivorRuns.size ? [...survivorRuns].join(' | ') : 'none'));
if (overlayShort.length) fail('overlay missing/short on ' + overlayShort.join(','));

// And the artefact the reader actually opens: every row, including a retired
// conclusion, has to arrive with both wordings attached.
let noEn = 0;
for (const f of d.findings) if (!f.i18n || !f.i18n.en || !f.i18n.en.title) noEn++;
const res = Array.isArray(d.resolved) ? d.resolved : [];
let noEnRes = 0;
for (const r of res) if (!r.i18n || !r.i18n.en || !r.i18n.en.title) noEnRes++;
console.log('findings without i18n.en: ' + noEn + ' | resolved rows without it: ' + noEnRes +
  ' (resolved total ' + res.length + ')');
if (noEn) fail(noEn + ' findings ship with no English wording');
if (res.length && noEnRes) fail(noEnRes + ' retired conclusions ship with no English wording');

console.log('--- redaction ---');
// Every facts file the engine consumed is local-only output, but each one is a
// separate chance to leak an absolute home path into the shipped report, so the
// redaction check covers all of them rather than just the browser probe.
const factFiles = fs.readdirSync(path.join(root, 'out'))
  .filter((n) => /^facts-.*\.json$/.test(n))
  .map((n) => ({ name: n, text: fs.readFileSync(path.join(root, 'out', n), 'utf8') }));

const user = process.env.USERNAME || '';
const prof = process.env.USERPROFILE || '';
const host = process.env.COMPUTERNAME || '';
// The report embeds the findings as JSON, and ConvertTo-Json escapes every
// backslash, so a home path is present as C:\\Users\\<name>. Counting only the
// raw form would report "0 occurrences" for a path that is really there - the
// escaped form has to be searched too or this check proves nothing.
const profEsc = prof ? prof.split('\\').join('\\\\') : '';
const probes = {
  username: user ? (html.split(user).length - 1) : 0,
  userprofile: prof ? (html.split(prof).length - 1) : 0,
  userprofile_escaped: profEsc ? (html.split(profEsc).length - 1) : 0,
  hostname: host ? (html.split(host).length - 1) : 0
};
console.log('username "' + user + '" occurrences in report: ' + probes.username);
console.log('userprofile raw occurrences: ' + probes.userprofile);
console.log('userprofile JSON-escaped occurrences: ' + probes.userprofile_escaped);
console.log('hostname occurrences: ' + probes.hostname);
if (probes.userprofile > 0 || probes.userprofile_escaped > 0) fail('absolute home path leaked');
// The bare username is only printed, never asserted: a short or generic account
// name ("admin", "app") legitimately occurs inside words like "Administrator",
// so treating any hit as a leak would fail CI on innocent forks. The home path
// above is the unambiguous test, and it covers the name wherever a path appears.

// The facts files are local-only output and are gitignored, so full paths there
// are expected and are not a leak. They are printed to make the difference
// explicit: report.html must be 0, facts files must be non-zero.
for (const f of factFiles) {
  console.log(f.name + ' keeps paths (expected, local only): ' +
    ((f.text.split(prof).length - 1) + (profEsc ? (f.text.split(profEsc).length - 1) : 0)) + ' occurrences');
}

// A scheduled task on this box runs `rasdial <connection> <user> <password>`, so
// its command line carries a dial-up account and password in plaintext. That row
// is a healthy Windows command (the bare name resolves to System32\rasdial.exe),
// so the residue rule must not surface it. The secret tokens are read out of the
// facts file rather than hardcoded here - this file is shipped, the facts are not.
let secrets = [];
for (const f of factFiles) {
  let doc;
  try { doc = JSON.parse(f.text); } catch (e) { continue; }
  for (const e of (doc.entries || [])) {
    if (!/^rasdial\s/i.test(String(e.command || '').trim())) continue;
    const toks = String(e.command).trim().split(/\s+/).slice(1);
    // Everything after the connection name is account and password.
    secrets = secrets.concat(toks.slice(1));
  }
}
secrets = secrets.filter((s) => s.length > 3);
const leaked = secrets.filter((s) => html.includes(s));
console.log('dial-task secret tokens in facts: ' + secrets.length + ' | present in report: ' + leaked.length);
if (leaked.length) fail('credential from a task command line reached the report');
// The residue rule must not carry that row's command line into evidence at all.
for (const f of d.findings) {
  const cmd = String((f.evidence || {}).command || '');
  if (/^rasdial\s/i.test(cmd.trim())) fail(f.rule_id + ' surfaced the dial task as a finding');
}

console.log('--- committed demo ---');
// demo/index.html is the one artefact in this repo that is published as-is, so it
// is checked like a shipped binary: it must render, it must show the states a
// clean machine cannot, and it must carry nobody's home path.
const demoPath = path.join(root, 'demo', 'index.html');
if (!fs.existsSync(demoPath)) {
  fail('demo/index.html missing (run tools/make-demo.ps1)');
} else {
  const demo = fs.readFileSync(demoPath, 'utf8');
  const dm = demo.match(/<script id="wp-data" type="application\/json">([\s\S]*?)<\/script>/);
  if (!dm) fail('demo has no data block');
  else {
    let dd;
    try { dd = JSON.parse(dm[1].split('<\\/script>').join('</script>')); }
    catch (e) { fail('demo JSON parse: ' + e.message); }
    if (dd) {
      const st = {};
      for (const f of dd.findings) st[f.state] = (st[f.state] || 0) + 1;
      const res = Array.isArray(dd.resolved) ? dd.resolved.length : (dd.resolved ? 1 : 0);
      console.log('demo findings=' + dd.findings.length + ' ' + JSON.stringify(st) + ' resolved=' + res);
      // A demo that only shows PERSIST rows is a screenshot, not a demo.
      for (const need of ['NEW', 'CHANGED', 'PERSIST']) {
        if (!st[need]) fail('demo shows no ' + need + ' rows');
      }
      if (!res) fail('demo shows no retired (RESOLVED) conclusions');
      if (!/data-demo="1"/.test(demo)) fail('demo is not marked as synthetic in its own <html>');
      // The demo is the one page a visitor reads before they run anything, so it
      // is also the page where a stale build is worst: an English reader clicking
      // "English" on a pre-bilingual artefact gets Chinese anyway.
      if (!/WP-LOCALE-TABLES-BEGIN/.test(demo)) fail('demo was rendered before the bilingual template');
      let dNoEn = 0;
      for (const f of dd.findings) if (!f.i18n || !f.i18n.en || !f.i18n.en.title) dNoEn++;
      const dRes = Array.isArray(dd.resolved) ? dd.resolved : [];
      for (const r of dRes) if (!r.i18n || !r.i18n.en || !r.i18n.en.title) dNoEn++;
      console.log('demo rows without an English wording: ' + dNoEn + ' of ' + (dd.findings.length + dRes.length));
      if (dNoEn) fail(dNoEn + ' demo rows cannot be read in English');
      const dprof = prof ? ((demo.split(prof).length - 1) + (profEsc ? (demo.split(profEsc).length - 1) : 0)) : 0;
      console.log('demo home-path occurrences: ' + dprof);
      if (dprof) fail('the published demo contains an absolute home path');
    }
  }
}

console.log(bad === 0 ? 'VERIFY: OK' : 'VERIFY: ' + bad + ' problem(s)');
process.exit(bad === 0 ? 0 : 1);
