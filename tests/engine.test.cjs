const test = require('node:test');
const assert = require('node:assert/strict');
const SL = require('../src/engine.js');

const SYSMON = 'Microsoft-Windows-Sysmon/Operational';
const recs = (...evs) => SL.loadEvents(evs.map((e) => JSON.stringify(e)).join('\n'), 't').recs;
const proc = (o) => ({ '@timestamp': '2026-01-05T10:00:00Z', Channel: SYSMON, EventID: 1, ...o });
const hits = (rule, rs, profile) => SL.runRule(SL.compileRule(rule, profile), rs).length;

test('yaml: maps, lists, quotes, flow lists, comments, block scalars', () => {
  const y = SL.parseYaml(`
title: Test # comment
description: |
  line one
  line two
tags: [attack.execution, 'attack.t1059']
detection:
    sel:
        Image|endswith:
            - '\\cmd.exe'
            - "C:\\\\x"
        CommandLine: 'it''s # not a comment'
    list:
      - a: 1
        b: 2
      - c: 3
    condition: sel
`);
  assert.equal(y.title, 'Test');
  assert.equal(y.description, 'line one\nline two');
  assert.deepEqual(y.tags, ['attack.execution', 'attack.t1059']);
  assert.deepEqual(y.detection.sel['Image|endswith'], ['\\cmd.exe', 'C:\\x']);
  assert.equal(y.detection.sel.CommandLine, "it's # not a comment");
  assert.deepEqual(y.detection.list, [{ a: '1', b: '2' }, { c: '3' }]);
});

test('yaml: list at same indent as key, and errors carry the line', () => {
  assert.deepEqual(SL.parseYaml('k:\n- a\n- b\n'), { k: ['a', 'b'] });
  assert.throws(() => SL.parseYaml("a: 'open\n"), /line 1/);
  assert.throws(() => SL.parseYaml('a: 1\na: 2\n'), /duplicate key/);
});

test('events: evtx_dump nested JSON is flattened and timestamped', () => {
  const r = SL.loadEvents(JSON.stringify({ Event: { System: { EventID: 4698, Channel: 'Security', Computer: 'PC', TimeCreated: { '#attributes': { SystemTime: '2026-01-05T10:00:00.1234567Z' } } }, EventData: { TaskName: '\\Evil' } } }), 'x').recs[0];
  assert.equal(r.ev.EventID, 4698);
  assert.equal(r.ev.TaskName, '\\Evil');
  assert.equal(new Date(r.t).toISOString(), '2026-01-05T10:00:00.123Z');
});

test('search: fields, wildcards, booleans, negation, comparisons, exists', () => {
  const rs = recs(
    proc({ Image: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'cmd /c whoami' }),
    proc({ Image: 'C:\\Users\\Public\\x.exe', CommandLine: 'x.exe -run', EventID: 3 }),
  );
  const idx = SL.buildFieldIndex(rs);
  const n = (q) => rs.filter(SL.compileQuery(q, idx)).length;
  assert.equal(n(''), 2);
  assert.equal(n('Image:*cmd.exe'), 1);
  assert.equal(n('image:*CMD.EXE'), 1, 'field names and values are case-insensitive');
  assert.equal(n('whoami'), 1);
  assert.equal(n('EventID:1 OR EventID:3'), 2);
  assert.equal(n('NOT EventID:3'), 1);
  assert.equal(n('-Image:*cmd.exe'), 1);
  assert.equal(n('EventID:>=3'), 1);
  assert.equal(n('_exists_:CommandLine AND (Image:*public* x.exe)'), 1);
  assert.equal(n('CommandLine:"cmd /c whoami"'), 1);
  assert.throws(() => SL.compileQuery('(a', idx), /missing/);
});

test('sigma: modifiers and wildcards', () => {
  const rs = recs(
    proc({ Image: 'C:\\Windows\\System32\\certutil.exe', CommandLine: 'certutil -urlcache -f http://a/b c', OriginalFileName: 'CertUtil.exe' }),
    proc({ Image: 'C:\\Users\\Public\\x.exe', CommandLine: 'x.exe /urlcache /f http://a/b c', OriginalFileName: 'CertUtil.exe' }),
  );
  const rule = (det) => ({ logsource: { category: 'process_creation', product: 'windows' }, detection: det });
  assert.equal(hits(rule({ s: { 'Image|endswith': '\\certutil.exe' }, condition: 's' }), rs), 1);
  assert.equal(hits(rule({ s: { OriginalFileName: 'certutil.exe' }, condition: 's' }), rs), 2);
  assert.equal(hits(rule({ s: { 'CommandLine|contains|windash': '-urlcache' }, condition: 's' }), rs), 2);
  assert.equal(hits(rule({ s: { 'CommandLine|contains|all': ['urlcache', 'http'] }, condition: 's' }), rs), 2);
  assert.equal(hits(rule({ s: { Image: 'C:\\Users\\\\*' }, condition: 's' }), rs), 1, '\\\\* = backslash + wildcard');
  assert.equal(hits(rule({ s: { Image: 'C:\\Users\\*' }, condition: 's' }), rs), 0, '\\* = literal asterisk (Sigma spec)');
  assert.equal(hits(rule({ s: { 'CommandLine|re': '^x\\.exe' }, condition: 's' }), rs), 1);
  assert.equal(hits(rule({ s: { 'Image|cased': 'c:\\users\\public\\x.exe' }, condition: 's' }), rs), 0);
  assert.equal(hits(rule({ s: { Missing: null }, condition: 's' }), rs), 2);
  assert.throws(() => SL.compileRule(rule({ s: { 'A|base64': 'x' }, condition: 's' })), /not supported/);
});

test('sigma: conditions, "of" quantifiers, keywords', () => {
  const rs = recs(proc({ Image: 'a.exe', CommandLine: 'one' }), proc({ Image: 'b.exe', CommandLine: 'two' }));
  const rule = (det) => ({ logsource: { category: 'process_creation', product: 'windows' }, detection: det });
  const det = { sel_a: { Image: 'a.exe' }, sel_b: { Image: 'b.exe' }, filter: { CommandLine: 'two' } };
  assert.equal(hits(rule({ ...det, condition: '1 of sel_*' }), rs), 2);
  assert.equal(hits(rule({ ...det, condition: 'all of sel_*' }), rs), 0);
  assert.equal(hits(rule({ ...det, condition: '1 of sel_* and not filter' }), rs), 1);
  assert.equal(hits(rule({ ...det, condition: 'not (sel_a or sel_b)' }), rs), 0);
  assert.equal(hits(rule({ kw: ['*ONE*'], condition: 'kw' }), rs), 1);
  assert.throws(() => SL.compileRule(rule({ ...det, condition: 'sel_c' })), /unknown search identifier/);
  assert.throws(() => SL.compileRule(rule({ ...det, condition: 'sel_a | count() > 5' })), /not supported/);
});

test('sigma: logsource mapping and Security 4688 aliases', () => {
  const rs = recs(
    proc({ Image: 'C:\\w\\cmd.exe' }),
    { '@timestamp': '2026-01-05T10:00:00Z', Channel: SYSMON, EventID: 3, Image: 'C:\\w\\cmd.exe' },
    { '@timestamp': '2026-01-05T10:00:00Z', Channel: 'Security', EventID: 4688, NewProcessName: 'C:\\w\\cmd.exe' },
  );
  const r = { logsource: { category: 'process_creation', product: 'windows' }, detection: { s: { 'Image|endswith': '\\cmd.exe' }, condition: 's' } };
  assert.equal(hits(r, rs, 'sysmon'), 1);
  assert.equal(hits(r, rs, 'security'), 1);
  assert.equal(hits(r, rs, 'both'), 2);
  const svc = { logsource: { product: 'windows', service: 'security' }, detection: { s: { EventID: 4688 }, condition: 's' } };
  assert.equal(hits(svc, rs), 1);
});
