const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const SL = require('../src/engine.js');

const load = (...evs) => SL.loadEvents(evs.map((e) => JSON.stringify(e)).join('\n'), 't').recs;
const hits = (rule, rs) => SL.runRule(SL.compileRule(rule), rs).length;
const rule = (logsource, sel) => ({ logsource, detection: { sel, condition: 'sel' } });

const T = '2026-11-08T09:00:00Z';
const SAMPLES = {
  windows: { '@timestamp': T, Channel: 'Security', EventID: 4625, TargetUserName: 'lucia', IpAddress: '203.0.113.7' },
  sshd: { '@timestamp': T, host: 'web01', program: 'sshd', pid: 811, message: 'Failed password for root from 203.0.113.7 port 50122 ssh2' },
  journald: { __REALTIME_TIMESTAMP: '1794128400000000', _HOSTNAME: 'web01', SYSLOG_IDENTIFIER: 'sudo', MESSAGE: 'deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash' },
  auditd: { '@timestamp': T, type: 'EXECVE', auid: 1001, a0: 'curl', a1: 'http://198.51.100.9/x.sh' },
  cloudtrail: { eventTime: T, eventSource: 'iam.amazonaws.com', eventName: 'CreateAccessKey', sourceIPAddress: '203.0.113.7', userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::111122223333:user/ana' } },
  signin: { TimeGenerated: T, Type: 'SigninLogs', UserPrincipalName: 'ana@orvia.example', ResultType: '50126', IPAddress: '203.0.113.7', AppDisplayName: 'Office 365' },
  m365: { CreationTime: '2026-11-08T09:00:00', Operation: 'New-InboxRule', Workload: 'Exchange', RecordType: 1, UserId: 'ana@orvia.example', Parameters: [{ Name: 'ForwardTo', Value: 'x@evil.example' }] },
  okta: { published: T, eventType: 'user.session.start', displayMessage: 'User login to Okta', actor: { alternateId: 'ana@orvia.example' }, outcome: { result: 'FAILURE' } },
  gcp: { timestamp: T, protoPayload: { methodName: 'SetIamPolicy', authenticationInfo: { principalEmail: 'ana@orvia.example' } } },
  suricata: { timestamp: '2026-11-08T09:00:00.000000+0000', flow_id: 1, event_type: 'alert', src_ip: '10.0.0.5', dest_ip: '198.51.100.9', alert: { signature_id: 2024897, signature: 'ET MALWARE Cobalt Strike Beacon' } },
  zeek: { ts: 1794128400.5, uid: 'C1', 'id.orig_h': '10.0.0.5', 'id.resp_h': '10.0.0.53', 'id.resp_p': 53, query: 'xk2.evil.example', qtype_name: 'A' },
  proxy: { '@timestamp': T, 'c-ip': '10.0.0.5', 'c-uri': 'http://198.51.100.9/payload.hta', 'cs-method': 'GET', 'sc-status': 200, 'c-useragent': 'mshta' },
  web: { date: '2026-11-08', time: '09:00:00', 'c-ip': '203.0.113.7', 'cs-method': 'GET', 'cs-uri-stem': '/index.php', 'cs-uri-query': "id=1' OR '1'='1", 'sc-status': 500 },
  firewall: { '@timestamp': T, src_ip: '10.0.0.5', dst_ip: '198.51.100.9', dst_port: 4444, action: 'allow' },
  dns: { '@timestamp': T, src_ip: '10.0.0.5', query: 'xk2.evil.example', record_type: 'A', answer: '198.51.100.9' },
};

test('sources: each sample is recognised as the right product / service / category', () => {
  const rs = load(...Object.values(SAMPLES));
  const by = Object.fromEntries(Object.keys(SAMPLES).map((k, i) => [k, SL.sourceOf(rs[i].ev)]));
  assert.equal(by.windows.product, 'windows');
  assert.deepEqual([by.sshd.product, by.sshd.services.includes('sshd'), by.sshd.services.includes('auth')], ['linux', true, true]);
  assert.deepEqual([by.journald.product, by.journald.services.includes('sudo')], ['linux', true]);
  assert.deepEqual([by.auditd.product, by.auditd.services], ['linux', ['auditd']]);
  assert.deepEqual([by.cloudtrail.product, by.cloudtrail.id], ['aws', 'CreateAccessKey']);
  assert.deepEqual([by.signin.product, by.signin.services, by.signin.id], ['azure', ['signinlogs'], '50126']);
  assert.deepEqual([by.m365.product, by.m365.services], ['m365', ['audit', 'exchange']]);
  assert.equal(by.okta.product, 'okta');
  assert.equal(by.gcp.product, 'gcp');
  assert.deepEqual([by.suricata.product, by.suricata.id], ['suricata', 'alert 2024897']);
  assert.deepEqual([by.zeek.product, by.zeek.services], ['zeek', ['dns']]);
  assert.equal(by.proxy.category, 'proxy');
  assert.equal(by.web.category, 'webserver');
  assert.equal(by.firewall.category, 'firewall');
  assert.equal(by.dns.category, 'dns');
  // the hidden source never leaks into the data
  assert.ok(!Object.keys(rs[1].ev).includes('__sl'));
  assert.ok(!rs[1].text().includes('linux'));
});

test('sources: times from every format end up on the same instant', () => {
  const want = Date.parse(T);
  const rs = load(...Object.values(SAMPLES));
  Object.keys(SAMPLES).forEach((k, i) => {
    if (k === 'zeek') assert.equal(rs[i].t, want + 500, k);
    else assert.equal(rs[i].t, want, k);
  });
});

test('sources: logsource selects only its own events', () => {
  const rs = load(...Object.values(SAMPLES));
  const any = { 'IpAddress|exists': true };
  assert.equal(hits(rule({ product: 'aws', service: 'cloudtrail' }, { eventName: 'CreateAccessKey' }), rs), 1);
  assert.equal(hits(rule({ product: 'azure', service: 'signinlogs' }, { ResultType: 50126 }), rs), 1);
  assert.equal(hits(rule({ product: 'azure', service: 'auditlogs' }, { 'ResultType|exists': true }), rs), 0);
  assert.equal(hits(rule({ product: 'linux', service: 'sshd' }, ['Failed password']), rs), 1);
  assert.equal(hits(rule({ product: 'linux', service: 'auth' }, { 'MESSAGE|contains': 'COMMAND=' }), rs), 1, 'sudo is part of auth');
  assert.equal(hits(rule({ product: 'linux', service: 'auditd' }, { type: 'EXECVE', a0: 'curl' }), rs), 1);
  assert.equal(hits(rule({ product: 'm365', service: 'exchange' }, { Operation: 'New-InboxRule', 'Parameters.Name|contains': 'ForwardTo' }), rs), 1);
  assert.equal(hits(rule({ product: 'okta', service: 'okta' }, { 'outcome.result': 'FAILURE' }), rs), 1);
  assert.equal(hits(rule({ product: 'gcp', service: 'gcp.audit' }, { 'protoPayload.methodName': 'SetIamPolicy' }), rs), 1);
  assert.equal(hits(rule({ product: 'suricata', service: 'alert' }, { 'alert.signature|contains': 'cobalt' }), rs), 1);
  assert.equal(hits(rule({ product: 'zeek', service: 'dns' }, { 'query|endswith': '.evil.example' }), rs), 1);
  assert.equal(hits(rule({ category: 'proxy' }, { 'c-uri|endswith': '.hta' }), rs), 1);
  assert.equal(hits(rule({ category: 'webserver' }, { 'cs-uri-query|contains': "' OR '" }), rs), 1);
  assert.equal(hits(rule({ category: 'firewall' }, { dst_port: 4444 }), rs), 1);
  assert.equal(hits(rule({ category: 'dns' }, { 'query|endswith': '.evil.example' }), rs), 1, 'Zeek dns is not the dns category');
  assert.equal(hits(rule({ product: 'windows' }, any), rs), 1);
  assert.equal(hits(rule({ product: 'windows', service: 'security' }, { EventID: 4625 }), rs), 1);
  // keyword rules on one product don't see the others
  assert.equal(hits(rule({ product: 'linux' }, ['203.0.113.7']), rs), 1);
  assert.equal(hits({ detection: { kw: ['203.0.113.7'], condition: 'kw' } }, rs), 5, 'no logsource: every event');
});

test('sources: unmapped parts are reported, not silently dropped', () => {
  assert.match(SL.compileRule(rule({ product: 'aws', service: 'guardduty' }, { a: 1 })).notes[0], /not mapped for aws/);
  assert.match(SL.compileRule(rule({ product: 'zscaler', category: 'proxy' }, { a: 1 })).notes.join(' '), /zscaler/);
  assert.match(SL.compileRule(rule({ product: 'macos', category: 'process_creation' }, { a: 1 })).notes[0], /not mapped/);
  assert.equal(SL.compileRule(rule({ product: 'aws', service: 'cloudtrail' }, { a: 1 })).logsourceDesc, 'AWS events · service cloudtrail');
});

test('search: _source_ pseudo-field', () => {
  const rs = load(...Object.values(SAMPLES));
  const idx = SL.buildFieldIndex(rs);
  const n = (q) => rs.filter(SL.compileQuery(q, idx)).length;
  assert.equal(n('_source_:linux'), 3);
  assert.equal(n('_source_:sshd'), 1);
  assert.equal(n('_source_:aws OR _source_:azure'), 2);
  assert.equal(n('_source_:proxy'), 1);
  assert.equal(n('_source_:zeek*'), 1);
  assert.equal(n('203.0.113.7 AND NOT _source_:windows'), 4);
});

test('loader: CloudTrail Records files, pretty-printed JSON and Proofpoint TAP responses', () => {
  const ct = JSON.stringify({ Records: [SAMPLES.cloudtrail, { ...SAMPLES.cloudtrail, eventName: 'ConsoleLogin' }] }, null, 2);
  const r1 = SL.loadEvents(ct, 'ct.json');
  assert.equal(r1.recs.length, 2);
  assert.deepEqual(r1.errors, []);
  assert.equal(r1.recs[1].ev['userIdentity.arn'], 'arn:aws:iam::111122223333:user/ana');

  const tap = {
    queryEndTime: '2026-11-08T10:00:00Z',
    messagesDelivered: [{
      GUID: 'g1', QID: 'q1', messageTime: T, sender: 'it@0rvia.example', fromAddress: ['it@0rvia.example'], recipient: ['ana@orvia.example'],
      subject: 'Actualiza tu contraseña', spamScore: 10, phishScore: 100, senderIP: '203.0.113.20',
      threatsInfoMap: [{ threat: 'http://0rvia.example/login', threatType: 'url', classification: 'phish', threatStatus: 'active' }],
      messageParts: [{ filename: 'text.html', contentType: 'text/html', sha256: 'aa' }],
    }],
    messagesBlocked: [],
    clicksPermitted: [{ GUID: 'g1', clickTime: '2026-11-08T09:05:00Z', clickIP: '10.0.0.5', recipient: 'ana@orvia.example', url: 'http://0rvia.example/login', classification: 'phish', threatTime: T }],
    clicksBlocked: [],
  };
  const r2 = SL.loadEvents(JSON.stringify(tap), 'tap.json').recs;
  assert.equal(r2.length, 2);
  assert.equal(r2[0].ev.tap_event, 'messagesDelivered');
  assert.equal(r2[0].ev['threatsInfoMap.classification'], 'phish');
  assert.deepEqual(SL.sourceOf(r2[1].ev).services, ['tap', 'tap_clicks']);
  assert.equal(hits(rule({ product: 'proofpoint', service: 'tap_messages' }, { 'threatsInfoMap.classification|contains': 'phish', 'phishScore|gte': 90 }), r2), 1);
  assert.equal(hits(rule({ product: 'proofpoint', service: 'tap_clicks' }, { classification: 'phish' }), r2), 1);
  assert.equal(r2[1].t, Date.parse('2026-11-08T09:05:00Z'));
});

test('eml: headers, authentication results, hops, URLs and attachments', () => {
  const attachment = Buffer.from('MZ fake invoice payload');
  const html = '<p>Hola Ana, revisa <a href="https://0rvia.example/factura?id=7&amp;u=ana">la factura</a>.</p>';
  const eml = [
    'Delivered-To: ana@orvia.example',
    'Received: from mx1.orvia.example (mx1.orvia.example [10.1.0.5])',
    '\tby mail.orvia.example with ESMTP; Sat, 08 Nov 2026 10:00:02 +0100',
    'Received: from smtp.0rvia.example (unknown [203.0.113.20])',
    '\tby mx1.orvia.example with ESMTPS; Sat, 08 Nov 2026 10:00:01 +0100',
    'Authentication-Results: mx1.orvia.example; spf=fail smtp.mailfrom=0rvia.example;',
    ' dkim=none; dmarc=fail header.from=orvia.example',
    'From: "Soporte IT" <it@orvia.example>',
    'Reply-To: soporte@0rvia.example',
    'Return-Path: <bounce@0rvia.example>',
    'To: ana@orvia.example',
    'Subject: =?UTF-8?B?QWN0dWFsaXphIHR1IGNvbnRyYXNlw7Fh?=',
    'Date: Sat, 08 Nov 2026 10:00:00 +0100',
    'Message-Id: <abc@0rvia.example>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="XX"',
    '',
    'preamble',
    '--XX',
    'Content-Type: multipart/alternative; boundary="YY"',
    '',
    '--YY',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Hola Ana, revisa la factura: https://0rvia.example/factura?id=3D7 contrase=C3=B1a',
    '--YY',
    'Content-Type: text/html; charset=utf-8',
    '',
    html,
    '--YY--',
    '--XX',
    'Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="factura.xlsm"',
    'Content-Disposition: attachment; filename="factura.xlsm"',
    'Content-Transfer-Encoding: base64',
    '',
    attachment.toString('base64').replace(/(.{20})/g, '$1\r\n'),
    '--XX--',
    '',
  ].join('\r\n');
  const { recs, errors } = SL.loadEml(eml, 'factura.eml');
  assert.deepEqual(errors, []);
  const ev = recs[0].ev;
  assert.equal(ev.Subject, 'Actualiza tu contraseña');
  assert.equal(ev['Message-ID'], '<abc@0rvia.example>', 'header names are normalised');
  assert.equal(recs[0].t, Date.parse('2026-11-08T09:00:00Z'));
  assert.equal(ev['eml.from_domain'], 'orvia.example');
  assert.equal(ev['eml.from_display_name'], 'Soporte IT');
  assert.equal(ev['eml.reply_to_domain'], '0rvia.example');
  assert.equal(ev['eml.return_path_domain'], '0rvia.example');
  assert.deepEqual([ev['eml.spf'], ev['eml.dkim'], ev['eml.dmarc']], ['fail', 'none', 'fail']);
  assert.equal(ev['eml.hops'], 2);
  assert.equal(ev['eml.received_ips'], '10.1.0.5, 203.0.113.20');
  assert.equal(ev['eml.origin_ip'], '203.0.113.20');
  assert.match(ev['eml.urls'], /https:\/\/0rvia\.example\/factura\?id=7&u=ana/);
  assert.equal(ev['eml.url_domains'], '0rvia.example');
  assert.equal(ev['eml.attachments'], 'factura.xlsm');
  assert.equal(ev['eml.attachment_sha256'], crypto.createHash('sha256').update(attachment).digest('hex'));
  assert.match(ev['eml.body'], /contraseña/);
  assert.match(ev.Received, /203\.0\.113\.20/);
  assert.equal(SL.sourceOf(ev).product, 'email');
  const r = rule({ product: 'email', service: 'eml' }, { 'eml.spf': 'fail', 'eml.attachments|endswith': ['.xlsm', '.docm'] });
  assert.equal(SL.runRule(SL.compileRule(r), recs).length, 1);
  assert.match(SL.loadEml('just text', 'x.eml').errors[0], /not an email/);

  // Parsed emails saved as JSONL and loaded back are still recognised as email.
  const back = load(...recs.map((x) => x.ev));
  assert.equal(back.length, 1);
  assert.equal(SL.sourceOf(back[0].ev).product, 'email');
  assert.equal(SL.runRule(SL.compileRule(r), back).length, 1);
});
