const fs = require('fs');
const f = JSON.parse(fs.readFileSync(process.argv[2] || 'out/facts-persistence.json', 'utf8'));
const e = f.entries;
console.log('probe=' + f.probe + ' at=' + f.captured_at + ' entries=' + e.length);
console.log('elam_members=' + JSON.stringify(f.elam_members));
console.log('');
const byKind = {};
for (const x of e) (byKind[x.kind] = byKind[x.kind] || []).push(x);
for (const k of Object.keys(byKind).sort()) {
  console.log('### ' + k + ' (' + byKind[k].length + ')');
  for (const x of byKind[k]) {
    console.log('   ' + String(x.name).slice(0, 40).padEnd(42) +
      ' exists=' + (x.exe_exists ? 'Y' : 'n') +
      ' status=' + String(x.sig_status || '-').slice(0, 10).padEnd(11) +
      ' signer=' + String(x.signer || '-').slice(0, 26).padEnd(27) +
      ' win=' + (x.in_windows ? 'Y' : 'n') +
      (x.is_wrapper ? ' WRAP' : '') +
      (x.payload ? ' payload=' + String(x.payload).slice(0, 46) : '') +
      (x.host_count !== undefined ? ' hostLines=' + x.host_count : ''));
    if (k === 'hosts_file') console.log('      content: ' + x.command);
  }
  console.log('');
}
