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

console.log(bad === 0 ? 'VERIFY: OK' : 'VERIFY: ' + bad + ' problem(s)');
process.exit(bad === 0 ? 0 : 1);
