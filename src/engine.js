/*
 * SigmaLens engine. No dependencies; runs in the browser and in Node.
 *  - parseYaml / parseYamlDocs: the YAML subset used by Sigma rules
 *  - loadEvents: JSON / JSONL / evtx_dump-style JSON -> flat records
 *  - loadEml: an .eml message -> one record with its headers analysed
 *  - sourceOf: which product / service / category an event comes from (by its shape)
 *  - compileQuery: Lucene-like search language
 *  - compileRule: Sigma rule -> matcher (detection, condition, modifiers, logsource mapping)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.SigmaLens = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class SLError extends Error {
    constructor(msg, line) {
      super(line ? `line ${line}: ${msg}` : msg);
      this.line = line || null;
    }
  }

  // ───────────────────────── YAML (Sigma subset) ─────────────────────────

  function stripComment(line) {
    let q = null;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (q) {
        if (q === '"' && c === '\\') { i++; continue; }
        if (c === q) {
          if (q === "'" && line[i + 1] === "'") { i++; continue; }
          q = null;
        }
        continue;
      }
      if (c === "'" || c === '"') {
        const prev = line.slice(0, i).trimEnd();
        if (prev === '' || /[:\-[,{]$/.test(prev)) q = c;
        continue;
      }
      if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
    }
    return line;
  }

  function yamlLines(src) {
    const out = [];
    String(src).replace(/^﻿/, '').replace(/\r\n?/g, '\n').split('\n').forEach((raw, idx) => {
      if (/^(---|\.\.\.)\s*$/.test(raw)) { out.push({ doc: true, no: idx + 1 }); return; }
      const t = stripComment(raw.replace(/\t/g, '  '));
      if (!t.trim()) return;
      out.push({ indent: t.length - t.trimStart().length, text: t.trim(), raw, no: idx + 1 });
    });
    return out;
  }

  function splitKV(text) {
    let q = null;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (q === '"' && c === '\\') { i++; continue; }
        if (c === q) q = null;
        continue;
      }
      if ((c === '"' || c === "'") && i === 0) { q = c; continue; }
      if (c === ':' && (i + 1 === text.length || text[i + 1] === ' ')) {
        let k = text.slice(0, i).trim();
        if (/^(['"]).*\1$/.test(k)) k = parseScalar(k);
        return [k, text.slice(i + 1).trim()];
      }
    }
    return null;
  }

  function splitFlow(s, no) {
    const items = [];
    let q = null, depth = 0, cur = '';
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) {
        cur += c;
        if (q === '"' && c === '\\') { cur += s[++i] || ''; continue; }
        if (c === q) q = null;
        continue;
      }
      if (c === '"' || c === "'") { q = c; cur += c; continue; }
      if (c === '[' || c === '{') depth++;
      if (c === ']' || c === '}') depth--;
      if (c === ',' && depth === 0) { items.push(cur.trim()); cur = ''; continue; }
      cur += c;
    }
    if (q || depth) throw new SLError('unterminated flow collection', no);
    if (cur.trim()) items.push(cur.trim());
    return items;
  }

  function parseScalar(s, no) {
    if (s === '' || s === '~' || /^(null|Null|NULL)$/.test(s)) return null;
    if (s[0] === "'") {
      if (s.length < 2 || s[s.length - 1] !== "'") throw new SLError('unterminated single-quoted string', no);
      return s.slice(1, -1).replace(/''/g, "'");
    }
    if (s[0] === '"') {
      if (s.length < 2 || s[s.length - 1] !== '"') throw new SLError('unterminated double-quoted string', no);
      const map = { n: '\n', t: '\t', r: '\r', 0: '\0', '\\': '\\', '"': '"', '/': '/' };
      return s.slice(1, -1).replace(/\\(.)/g, (m, c) => (c in map ? map[c] : c));
    }
    if (s[0] === '[') {
      if (s[s.length - 1] !== ']') throw new SLError('unterminated flow list', no);
      return splitFlow(s.slice(1, -1), no).map((x) => parseScalar(x, no));
    }
    if (s[0] === '{') {
      if (s[s.length - 1] !== '}') throw new SLError('unterminated flow map', no);
      const o = {};
      for (const part of splitFlow(s.slice(1, -1), no)) {
        const kv = splitKV(part);
        if (!kv) throw new SLError('expected "key: value" in flow map', no);
        o[kv[0]] = parseScalar(kv[1], no);
      }
      return o;
    }
    return s; // numbers and booleans stay strings: matching is string based
  }

  const isItem = (t) => t === '-' || t.startsWith('- ');
  const live = (L, i) => i < L.length && !L[i].doc;

  function parseNode(L, i, indent) {
    return isItem(L[i].text) ? parseList(L, i, indent) : parseMap(L, i, indent);
  }

  function parseList(L, i, indent) {
    const arr = [];
    while (live(L, i) && L[i].indent === indent && isItem(L[i].text)) {
      const text = L[i].text;
      const rest = text.slice(1).trim();
      const restCol = indent + (text.length - text.slice(1).trimStart().length);
      if (rest === '') {
        if (live(L, i + 1) && L[i + 1].indent > indent) {
          const [v, j] = parseNode(L, i + 1, L[i + 1].indent);
          arr.push(v); i = j;
        } else { arr.push(null); i++; }
      } else if (rest[0] !== '[' && rest[0] !== '{' && splitKV(rest)) {
        L[i] = { indent: restCol, text: rest, raw: L[i].raw, no: L[i].no };
        const [v, j] = parseMap(L, i, restCol);
        arr.push(v); i = j;
      } else {
        arr.push(parseScalar(rest, L[i].no)); i++;
      }
    }
    if (live(L, i) && L[i].indent > indent) throw new SLError('bad indentation', L[i].no);
    return [arr, i];
  }

  function parseMap(L, i, indent) {
    const obj = {};
    while (live(L, i) && L[i].indent === indent && !isItem(L[i].text)) {
      const kv = splitKV(L[i].text);
      if (!kv) throw new SLError(`expected "key: value", got "${L[i].text}"`, L[i].no);
      const [k, rest] = kv;
      const no = L[i].no;
      if (Object.prototype.hasOwnProperty.call(obj, k)) throw new SLError(`duplicate key "${k}"`, no);
      i++;
      if (rest === '') {
        if (live(L, i) && L[i].indent > indent) { const [v, j] = parseNode(L, i, L[i].indent); obj[k] = v; i = j; }
        else if (live(L, i) && L[i].indent === indent && isItem(L[i].text)) { const [v, j] = parseList(L, i, indent); obj[k] = v; i = j; }
        else obj[k] = null;
      } else if (/^[|>][+-]?$/.test(rest)) {
        const parts = [];
        while (live(L, i) && L[i].indent > indent) { parts.push(L[i].raw.trim()); i++; }
        obj[k] = rest[0] === '|' ? parts.join('\n') : parts.join(' ');
      } else {
        obj[k] = parseScalar(rest, no);
      }
    }
    if (live(L, i) && L[i].indent > indent) throw new SLError('bad indentation', L[i].no);
    return [obj, i];
  }

  function parseYamlDocs(src) {
    const docs = [];
    let cur = [];
    for (const l of yamlLines(src)) {
      if (l.doc) { if (cur.length) docs.push(cur); cur = []; } else cur.push(l);
    }
    if (cur.length) docs.push(cur);
    return docs.map((L) => {
      const [v, i] = parseNode(L, 0, L[0].indent);
      if (i < L.length) throw new SLError('unexpected content', L[i].no);
      return v;
    });
  }

  function parseYaml(src) {
    const docs = parseYamlDocs(src);
    if (docs.length !== 1) throw new SLError(`expected one YAML document, found ${docs.length}`);
    return docs[0];
  }

  // ───────────────────────── Events ─────────────────────────

  const TIME_FIELDS = ['@timestamp', 'TimeCreated', 'SystemTime', 'UtcTime', 'timestamp', 'Timestamp', 'time',
    'eventTime', 'TimeGenerated', 'CreationTime', 'createdDateTime', 'CreatedDateTime', 'published',
    'messageTime', 'clickTime', 'ts', '__REALTIME_TIMESTAMP', 'Date'];

  function parseTime(v) {
    if (v == null || v === '') return NaN;
    let s = String(v).trim();
    if (/^\d{9,17}(\.\d+)?$/.test(s)) {
      // epoch: seconds (Zeek ts), milliseconds or microseconds (journald)
      const n = Number(s);
      return n > 1e14 ? Math.floor(n / 1000) : n > 1e11 ? n : Math.round(n * 1000);
    }
    if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) {
      s = s.replace(' ', 'T').replace(/(\.\d{3})\d+/, '$1');
      if (!/(Z|[+-]\d{2}:?\d{2})$/.test(s)) s += 'Z';
    }
    return Date.parse(s);
  }

  function flatten(o, prefix, out) {
    for (const [k, v] of Object.entries(o)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
      else if (Array.isArray(v)) {
        if (v.every((x) => x === null || typeof x !== 'object')) { out[key] = v.join(', '); continue; }
        out[key] = JSON.stringify(v);
        // [{classification:'phish'},{classification:'spam'}] -> key.classification = 'phish, spam'
        const subs = new Map();
        for (const x of v) {
          if (!x || typeof x !== 'object' || Array.isArray(x)) continue;
          for (const [sk, sv] of Object.entries(x)) {
            if (sv !== null && typeof sv === 'object') continue;
            if (!subs.has(sk)) subs.set(sk, new Set());
            subs.get(sk).add(String(sv));
          }
        }
        for (const [sk, set] of subs) if (!(`${key}.${sk}` in out)) out[`${key}.${sk}`] = [...set].join(', ');
      } else out[key] = v;
    }
    return out;
  }

  // evtx_dump / python-evtx JSON: {"Event":{"System":{...},"EventData":{...}}}
  function fromEvtxJson(e) {
    const sys = e.System || {};
    const attr = (x, a) => (x && typeof x === 'object' ? (x['#attributes'] || {})[a] : undefined);
    const text = (x) => (x && typeof x === 'object' ? x['#text'] : x);
    const out = {
      '@timestamp': attr(sys.TimeCreated, 'SystemTime'),
      EventID: text(sys.EventID),
      Channel: sys.Channel,
      Computer: sys.Computer,
      EventRecordID: sys.EventRecordID,
      Provider: attr(sys.Provider, 'Name'),
    };
    for (const part of [e.EventData, e.UserData]) {
      if (!part || typeof part !== 'object') continue;
      const clean = Object.assign({}, part);
      delete clean['#attributes'];
      flatten(clean, '', out);
    }
    return out;
  }

  function normalizeEvent(o) {
    if (o && o.Event && typeof o.Event === 'object' && o.Event.System) return fromEvtxJson(o.Event);
    return flatten(o, '', {});
  }

  class Rec {
    constructor(ev, t, src, i) { this.ev = ev; this.t = t; this.src = src; this.i = i; this._x = null; }
    text() {
      if (this._x === null) {
        this._x = Object.values(this.ev).map((v) => (v == null ? '' : String(v))).join('\n').toLowerCase();
      }
      return this._x;
    }
  }

  function loadEvents(text, src, startIndex) {
    const recs = [];
    const errors = [];
    let objs = [];
    const s = String(text).replace(/^﻿/, '').trim();
    if (!s) return { recs, errors };
    let whole = null;
    if (s[0] === '[' || s[0] === '{') { try { whole = JSON.parse(s); } catch (e) { whole = null; } }
    if (whole !== null) objs = Array.isArray(whole) ? whole : [whole];
    else if (s[0] === '[') errors.push(`${src}: invalid JSON array`);
    else {
      s.split(/\r?\n/).forEach((line, n) => {
        if (!line.trim()) return;
        try { objs.push(JSON.parse(line)); } catch (e) { if (errors.length < 20) errors.push(`${src}:${n + 1}: invalid JSON line`); }
      });
    }
    let i = startIndex || 0;
    for (const o of unwrap(objs)) {
      if (!o || typeof o !== 'object') continue;
      const ev = normalizeEvent(o);
      recs.push(new Rec(ev, eventTime(ev), src, i++));
    }
    return { recs, errors };
  }

  const TAP_LISTS = ['messagesDelivered', 'messagesBlocked', 'clicksPermitted', 'clicksBlocked'];

  // Containers that hold the real events: CloudTrail / Azure storage exports ({"Records":[…]})
  // and Proofpoint TAP SIEM API responses ({"messagesDelivered":[…],"clicksPermitted":[…]…}).
  function unwrap(objs) {
    const out = [];
    for (const o of objs) {
      if (o && typeof o === 'object' && !Array.isArray(o)) {
        const tap = TAP_LISTS.filter((k) => Array.isArray(o[k]));
        if (tap.length) {
          for (const k of tap) for (const x of o[k]) if (x && typeof x === 'object') out.push(Object.assign({ tap_event: k }, x));
          continue;
        }
        const recArr = Array.isArray(o.Records) ? o.Records : Array.isArray(o.records) ? o.records : null;
        if (recArr && Object.keys(o).length <= 3) { out.push(...recArr); continue; }
      }
      out.push(o);
    }
    return out;
  }

  function eventTime(ev) {
    // W3C web/proxy logs keep date and time apart
    if (/^\d{4}-\d{2}-\d{2}$/.test(String(ev.date || '')) && /^\d{2}:\d{2}/.test(String(ev.time || ''))) {
      const t = parseTime(`${ev.date}T${ev.time}`);
      if (!isNaN(t)) return t;
    }
    for (const f of TIME_FIELDS) {
      if (ev[f] != null && ev[f] !== '') { const t = parseTime(ev[f]); if (!isNaN(t)) return t; }
    }
    return NaN;
  }

  // ───────────────────────── Sources ─────────────────────────
  // Where an event comes from, worked out from the fields it has. Cached on the event
  // as a non-enumerable property, so it is never shown, searched or exported.

  const lc = (x) => String(x == null ? '' : x).toLowerCase();
  const has = (ev, k) => ev[k] != null && ev[k] !== '';
  const mk = (product, services, category, label, id) => ({ product, services: services || [], category: category || null, label: label || null, id: id == null ? '' : String(id) });

  const LINUX_PROGRAMS = {
    sshd: ['sshd', 'auth'], sudo: ['sudo', 'auth'], su: ['auth'], login: ['auth'], 'systemd-logind': ['auth'],
    passwd: ['auth'], useradd: ['auth'], usermod: ['auth'], userdel: ['auth'], groupadd: ['auth'], groupmod: ['auth'],
    gpasswd: ['auth'], chpasswd: ['auth'], chage: ['auth'], unix_chkpwd: ['auth'], polkitd: ['auth'], pkexec: ['auth'],
    cron: ['cron'], crond: ['cron'], anacron: ['cron'], vsftpd: ['vsftpd'], clamd: ['clamav'], freshclam: ['clamav'],
  };
  const AUDITD_TYPE = /^(SYSCALL|EXECVE|PATH|PROCTITLE|CWD|SOCKADDR|LOGIN|TTY|AVC|BPRM_FCAPS|CONFIG_CHANGE|KERN_MODULE|NETFILTER_CFG|SERVICE_START|SERVICE_STOP|(ADD|DEL)_(USER|GROUP)|(USER|CRED|ANOM|DAEMON|SYSTEM|MAC)_[A-Z_]+)$/;
  const LINUX_SYSMON = { 1: 'process_creation', 3: 'network_connection', 5: 'process_termination', 11: 'file_event', 23: 'file_delete' };
  const HTTP_ID = (ev) => [ev['cs-method'], ev['sc-status']].filter((x) => x != null && x !== '').join(' ');

  function detectSource(ev) {
    const ch = lc(ev.Channel);
    if (ch && has(ev, 'EventID')) {
      if (ch.startsWith('linux-sysmon')) return mk('linux', ['sysmon'], LINUX_SYSMON[Number(ev.EventID)], 'Sysmon Linux', ev.EventID);
      return mk('windows', Object.keys(CH).filter((k) => CH[k].toLowerCase() === ch), null, null, ev.EventID);
    }
    if (/\.amazonaws\.com$/i.test(String(ev.eventSource || '')) && has(ev, 'eventName')) return mk('aws', ['cloudtrail'], null, 'CloudTrail', ev.eventName);
    if (has(ev, 'protoPayload.methodName')) return mk('gcp', ['gcp.audit'], null, 'GCP audit', ev['protoPayload.methodName']);
    const az = lc(ev.Type || ev.category);
    if (az === 'signinlogs' || az === 'noninteractiveusersigninlogs' || (has(ev, 'UserPrincipalName') && ev.ResultType != null && has(ev, 'AppDisplayName'))) {
      return mk('azure', ['signinlogs'], null, 'Entra sign-in', ev.ResultType != null ? ev.ResultType : ev.resultType);
    }
    if (az === 'auditlogs' || (has(ev, 'OperationName') && has(ev, 'Category') && Object.keys(ev).some((k) => /^(InitiatedBy|TargetResources)/.test(k)))) {
      return mk('azure', ['auditlogs'], null, 'Entra audit', ev.OperationName || ev.operationName);
    }
    if (az === 'azureactivity' || has(ev, 'OperationNameValue')) return mk('azure', ['activitylogs'], null, 'Azure activity', ev.OperationNameValue || ev.OperationName || ev.operationName);
    if (has(ev, 'Operation') && has(ev, 'Workload') && (ev.RecordType != null || has(ev, 'UserId'))) {
      const w = lc(ev.Workload), svc = ['audit'];
      if (w === 'exchange') svc.push('exchange');
      if (w === 'securitycompliancecenter' || w === 'threatintelligence') svc.push('threat_management');
      return mk('m365', svc, null, `M365 ${ev.Workload}`, ev.Operation);
    }
    if (has(ev, 'eventType') && (has(ev, 'actor.alternateId') || has(ev, 'displayMessage'))) return mk('okta', ['okta'], null, 'Okta', ev.eventType);
    if (has(ev, 'GUID') && (ev.threatsInfoMap != null || has(ev, 'clickTime') || ev.spamScore != null || ev.phishScore != null)) {
      const click = has(ev, 'clickTime') || /^clicks/.test(String(ev.tap_event || ''));
      return mk('proofpoint', ['tap', click ? 'tap_clicks' : 'tap_messages'], null, 'Proofpoint TAP', ev.tap_event || (click ? 'click' : 'message'));
    }
    if (has(ev, 'event_type') && (ev.flow_id != null || (has(ev, 'src_ip') && has(ev, 'dest_ip')))) {
      const t = lc(ev.event_type);
      return mk('suricata', [t], null, 'Suricata', t === 'alert' && ev['alert.signature_id'] != null ? `alert ${ev['alert.signature_id']}` : t);
    }
    if (has(ev, 'uid') && has(ev, 'id.orig_h')) {
      const p = lc(ev._path) || (has(ev, 'query') ? 'dns' : has(ev, 'method') ? 'http' : has(ev, 'server_name') || has(ev, 'ja3') ? 'ssl' : has(ev, 'mailfrom') ? 'smtp' : 'conn');
      return mk('zeek', [p], null, `Zeek ${p}`, p);
    }
    if (has(ev, 'type') && AUDITD_TYPE.test(String(ev.type)) && (ev.auid != null || ev.syscall != null || has(ev, 'msg') || has(ev, 'exe') || ev.a0 != null)) {
      return mk('linux', ['auditd'], null, 'auditd', ev.type);
    }
    const prog = [ev.program, ev.appname, ev.ident, ev.SYSLOG_IDENTIFIER, ev['process.name'], ev['syslog.appname']].find((x) => x != null && x !== '');
    const msg = [ev.message, ev.MESSAGE, ev.msg].find((x) => x != null);
    if (prog != null && msg != null && !Object.keys(ev).some((k) => k.startsWith('winlog.'))) {
      const svc = new Set(LINUX_PROGRAMS[lc(prog)] || []);
      if (/auth\.log|\/secure$/.test(lc(ev.log_file || ev['log.file.path'] || ev.file))) svc.add('auth');
      svc.add('syslog');
      return mk('linux', [...svc], null, 'Linux', prog);
    }
    if (has(ev, 'c-uri') || has(ev, 'r-dns') || (has(ev, 'cs-host') && has(ev, 'c-useragent'))) return mk(null, [], 'proxy', 'Proxy', HTTP_ID(ev));
    if (has(ev, 'cs-uri-stem') || has(ev, 'cs-uri-query') || (has(ev, 'cs-method') && ev['sc-status'] != null)) return mk(null, [], 'webserver', 'Web', HTTP_ID(ev));
    if ((has(ev, 'src_ip') || has(ev, 'src')) && (has(ev, 'dst_ip') || has(ev, 'dst')) && (has(ev, 'action') || ev.dst_port != null)) return mk(null, [], 'firewall', 'Firewall', ev.action);
    if (has(ev, 'query') && (has(ev, 'record_type') || has(ev, 'answer') || has(ev, 'qtype') || has(ev, 'query_type'))) return mk(null, [], 'dns', 'DNS', ev.record_type || ev.qtype || ev.query_type);
    return mk(null, [], null, null, '');
  }

  function sourceOf(ev) {
    if (!ev.__sl) Object.defineProperty(ev, '__sl', { value: detectSource(ev), enumerable: false, writable: true, configurable: true });
    return ev.__sl;
  }

  // For the guide: what SigmaLens recognises and the logsource that selects it.
  const SOURCES = [
    { name: 'Windows event logs', logsource: 'product: windows + category / service', how: 'Channel and EventID' },
    { name: 'Linux syslog / journald', logsource: 'product: linux · service: auth, sshd, sudo, cron, syslog', how: 'program / appname / SYSLOG_IDENTIFIER + message' },
    { name: 'Linux auditd', logsource: 'product: linux · service: auditd', how: 'type (SYSCALL, EXECVE, USER_LOGIN…)' },
    { name: 'Sysmon for Linux', logsource: 'product: linux · category: process_creation, network_connection, file_event', how: 'Channel Linux-Sysmon/Operational' },
    { name: 'AWS CloudTrail', logsource: 'product: aws · service: cloudtrail', how: 'eventSource *.amazonaws.com + eventName (also {"Records":[…]} files)' },
    { name: 'Entra ID sign-ins', logsource: 'product: azure · service: signinlogs', how: 'Type/category SigninLogs, or UserPrincipalName + ResultType + AppDisplayName' },
    { name: 'Entra ID audit', logsource: 'product: azure · service: auditlogs', how: 'Type/category AuditLogs' },
    { name: 'Azure activity', logsource: 'product: azure · service: activitylogs', how: 'Type AzureActivity or OperationNameValue' },
    { name: 'Microsoft 365 audit', logsource: 'product: m365 · service: audit, exchange, threat_management', how: 'Operation + Workload' },
    { name: 'Google Cloud audit', logsource: 'product: gcp · service: gcp.audit', how: 'protoPayload.methodName' },
    { name: 'Okta system log', logsource: 'product: okta · service: okta', how: 'eventType + actor.alternateId' },
    { name: 'Proofpoint TAP', logsource: 'product: proofpoint · service: tap, tap_messages, tap_clicks', how: 'GUID + threatsInfoMap / clickTime (also SIEM API responses)' },
    { name: 'Email (.eml)', logsource: 'product: email · service: eml', how: 'loaded from .eml files' },
    { name: 'Suricata EVE', logsource: 'product: suricata · service: alert, dns, http, tls, flow…', how: 'event_type + flow_id' },
    { name: 'Zeek', logsource: 'product: zeek · service: conn, dns, http, ssl…', how: 'uid + id.orig_h (_path if present)' },
    { name: 'Web proxy', logsource: 'category: proxy', how: 'c-uri, r-dns or cs-host + c-useragent' },
    { name: 'Web server', logsource: 'category: webserver', how: 'cs-uri-stem, cs-uri-query or cs-method + sc-status' },
    { name: 'Firewall', logsource: 'category: firewall', how: 'src_ip + dst_ip + action / dst_port' },
    { name: 'DNS server', logsource: 'category: dns', how: 'query + record_type / answer' },
  ];

  // ───────────────────────── Email (.eml) ─────────────────────────

  const B64 = (() => { const t = new Int16Array(128).fill(-1); 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('').forEach((c, i) => { t[c.charCodeAt(0)] = i; }); return t; })();
  function b64bytes(str) {
    const out = new Uint8Array(Math.ceil(str.length * 3 / 4));
    let n = 0, buf = 0, bits = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i), v = c < 128 ? B64[c] : -1;
      if (v < 0) continue;
      buf = ((buf << 6) | v) & 0xffffff; bits += 6;
      if (bits >= 8) { bits -= 8; out[n++] = (buf >> bits) & 255; }
    }
    return out.subarray(0, n);
  }
  const utf8 = (str) => new TextEncoder().encode(str);
  function qpbytes(str) {
    const s = str.replace(/=\r?\n/g, '');
    const out = [];
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; continue; }
      const c = s.charCodeAt(i);
      if (c < 128) out.push(c); else out.push(...utf8(s[i]));
    }
    return Uint8Array.from(out);
  }
  function decodeBytes(bytes, charset) {
    try { return new TextDecoder(charset || 'utf-8').decode(bytes); } catch (e) { return new TextDecoder('utf-8').decode(bytes); }
  }
  // RFC 2047: =?utf-8?B?…?= and =?iso-8859-1?Q?…?=
  function decodeWords(v) {
    return String(v || '').replace(/(\?=)\s+(=\?)/g, '$1$2').replace(/=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g, (m, cs, enc, txt) => {
      const bytes = enc.toUpperCase() === 'B' ? b64bytes(txt) : qpbytes(txt.replace(/_/g, ' '));
      return decodeBytes(bytes, cs.split('*')[0]);
    });
  }
  function splitMessage(raw) {
    const m = /\r?\n\r?\n/.exec(raw);
    const head = m ? raw.slice(0, m.index) : raw, body = m ? raw.slice(m.index + m[0].length) : '';
    const headers = [];
    for (const line of head.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
      const i = line.indexOf(':');
      if (i > 0 && /^[!-9;-~]+$/.test(line.slice(0, i))) headers.push([line.slice(0, i), line.slice(i + 1).trim()]);
    }
    return { headers, body };
  }
  function headerParams(v) {
    const out = {};
    const re = /;\s*([\w*.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)/g;
    let m;
    while ((m = re.exec(String(v || '')))) {
      let k = m[1].toLowerCase(), val = m[2].trim();
      if (val[0] === '"') val = val.slice(1, -1).replace(/\\(.)/g, '$1');
      if (k.endsWith('*')) { // RFC 2231: utf-8''na%C3%AFve.pdf
        k = k.slice(0, -1);
        const p = /^([^']*)'[^']*'(.*)$/.exec(val);
        if (p) { try { val = decodeURIComponent(p[2]); } catch (e) { val = p[2]; } }
      }
      out[k] = val;
    }
    return out;
  }
  function walkPart(raw, acc, depth) {
    const { headers, body } = splitMessage(raw);
    const get = (n) => { const h = headers.find(([k]) => k.toLowerCase() === n); return h ? h[1] : ''; };
    const ctype = get('content-type') || 'text/plain';
    const type = ctype.split(';')[0].trim().toLowerCase();
    const params = headerParams(ctype);
    const disp = get('content-disposition');
    if (type.startsWith('multipart/') && params.boundary && depth < 12) {
      const b = `--${params.boundary}`;
      let cur = null;
      for (const line of body.split(/\r?\n/)) {
        const t = line.trimEnd();
        if (t === b || t === `${b}--`) {
          if (cur) walkPart(cur.join('\n'), acc, depth + 1);
          cur = t === b ? [] : null;
          if (!cur) break;
          continue;
        }
        if (cur) cur.push(line);
      }
      return;
    }
    const cte = get('content-transfer-encoding').trim().toLowerCase();
    const bytes = cte === 'base64' ? b64bytes(body) : cte === 'quoted-printable' ? qpbytes(body) : utf8(body);
    const name = decodeWords(headerParams(disp).filename || params.name || '');
    const isFile = !!name || /^attachment/i.test(disp) || !(type.startsWith('text/') || type.startsWith('multipart/'));
    if (isFile) acc.files.push({ name: name || '(unnamed)', type, size: bytes.length, sha256: sha256(bytes) });
    else if (type === 'text/html') acc.html.push(decodeBytes(bytes, params.charset));
    else acc.text.push(decodeBytes(bytes, params.charset));
  }

  const CANON_HEADERS = ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID', 'Return-Path', 'Reply-To', 'Sender',
    'Received', 'Received-SPF', 'Authentication-Results', 'DKIM-Signature', 'X-Mailer', 'User-Agent', 'X-Originating-IP',
    'Content-Type', 'MIME-Version', 'List-Unsubscribe', 'X-Priority', 'Delivered-To', 'In-Reply-To', 'References'];
  const CANON = new Map(CANON_HEADERS.map((h) => [h.toLowerCase(), h]));
  const addrOf = (v) => { const m = /<([^<>\s]+@[^<>\s]+)>/.exec(v || '') || /([^\s<>",;]+@[^\s<>",;]+)/.exec(v || ''); return m ? m[1].toLowerCase() : ''; };
  const domainOf = (a) => (a.includes('@') ? a.split('@').pop().replace(/[>\]]+$/, '') : '');
  function isPrivateIp(ip) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  function hopIp(received) {
    const from = String(received).split(/\sby\s/i)[0];
    const m = /\[(\d{1,3}(?:\.\d{1,3}){3})\]/.exec(from) || /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(from);
    return m ? m[1] : '';
  }

  function loadEml(text, src, startIndex) {
    const raw = String(text).replace(/^\uFEFF/, '');
    const { headers } = splitMessage(raw);
    const hk = new Set(headers.map(([k]) => k.toLowerCase()));
    if (!hk.has('from') && !hk.has('received') && !hk.has('subject')) return { recs: [], errors: [`${src}: not an email message (no From, Subject or Received header)`] };
    const acc = { files: [], text: [], html: [] };
    walkPart(raw, acc, 0);
    const H = {};
    for (const [k, v] of headers) {
      const name = CANON.get(k.toLowerCase()) || k;
      const val = decodeWords(v).trim();
      H[name] = H[name] != null ? `${H[name]}\n${val}` : val;
    }
    const all = (n) => headers.filter(([k]) => k.toLowerCase() === n.toLowerCase()).map(([, v]) => v);
    const t = Date.parse(String(H.Date || '').replace(/\s*\([^)]*\)\s*$/, ''));
    const ev = { '@timestamp': isNaN(t) ? '' : new Date(t).toISOString() };
    Object.assign(ev, H);

    const from = addrOf(H.From), ret = addrOf(H['Return-Path']), reply = addrOf(H['Reply-To']);
    const auth = all('Authentication-Results')[0] || '';
    const res = (k) => { const m = new RegExp(`\\b${k}=([a-z]+)`, 'i').exec(auth); return m ? m[1].toLowerCase() : ''; };
    let spf = res('spf');
    if (!spf) { const r = /^\s*([a-z]+)/i.exec(all('Received-SPF')[0] || ''); spf = r ? r[1].toLowerCase() : ''; }
    const hops = all('Received').map(hopIp);
    const ips = hops.filter(Boolean);
    const publicIps = ips.filter((ip) => !isPrivateIp(ip));
    const origin = publicIps.length ? publicIps[publicIps.length - 1] : ips.length ? ips[ips.length - 1] : (String(H['X-Originating-IP'] || '').replace(/[[\]\s]/g, ''));

    const htmlAll = acc.html.join('\n');
    const urls = new Set();
    const addUrl = (u) => { const c = u.replace(/&amp;/g, '&').replace(/[.,;:!?)\]]+$/, ''); if (/^https?:\/\/[^\s/]+/i.test(c)) urls.add(c); };
    for (const m of htmlAll.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) addUrl(m[1]);
    for (const m of (acc.text.join('\n') + '\n' + htmlAll).matchAll(/\bhttps?:\/\/[^\s"'<>()]+/gi)) addUrl(m[0]);
    const urlDomains = new Set([...urls].map((u) => (/^https?:\/\/([^/:?#]+)/i.exec(u) || [])[1]).filter(Boolean).map((d) => d.toLowerCase()));
    const bodyText = (acc.text.join('\n') || htmlAll.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&'))
      .replace(/\s+/g, ' ').trim();
    const dn = /^\s*"?([^"<]*?)"?\s*</.exec(H.From || '');

    Object.assign(ev, {
      'eml.from_address': from,
      'eml.from_display_name': dn ? dn[1].trim() : '',
      'eml.from_domain': domainOf(from),
      'eml.return_path_domain': domainOf(ret),
      'eml.reply_to_domain': domainOf(reply),
      'eml.spf': spf,
      'eml.dkim': res('dkim'),
      'eml.dmarc': res('dmarc'),
      'eml.hops': hops.length,
      'eml.received_ips': ips.join(', '),
      'eml.origin_ip': origin,
      'eml.urls': [...urls].join(', '),
      'eml.url_domains': [...urlDomains].join(', '),
      'eml.attachments': acc.files.map((f) => f.name).join(', '),
      'eml.attachment_types': [...new Set(acc.files.map((f) => f.type))].join(', '),
      'eml.attachment_sha256': acc.files.map((f) => f.sha256).join(', '),
      'eml.body': bodyText.length > 20000 ? `${bodyText.slice(0, 20000)}…` : bodyText,
    });
    Object.defineProperty(ev, '__sl', { value: mk('email', ['eml'], null, 'Email', 'message'), enumerable: false, writable: true, configurable: true });
    return { recs: [new Rec(ev, isNaN(t) ? NaN : t, src, startIndex || 0)], errors: [] };
  }

  // SHA-256 (sync, for attachment hashes). Constants from the first 64 primes, as in FIPS 180-4.
  let SHA_K = null, SHA_H = null;
  function sha256(bytes) {
    if (!SHA_K) {
      const primes = [];
      for (let n = 2; primes.length < 64; n++) if (primes.every((p) => n % p)) primes.push(n);
      const frac = (x) => ((x - Math.floor(x)) * 4294967296) >>> 0;
      SHA_K = primes.map((p) => frac(Math.cbrt(p)));
      SHA_H = primes.slice(0, 8).map((p) => frac(Math.sqrt(p)));
    }
    const l = bytes.length, nb = ((l + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(nb);
    m.set(bytes); m[l] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(nb - 4, (l * 8) >>> 0);
    dv.setUint32(nb - 8, Math.floor(l / 0x20000000));
    const h = SHA_H.slice(), w = new Uint32Array(64);
    const rot = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < nb; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rot(w[i - 15], 7) ^ rot(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rot(w[i - 2], 17) ^ rot(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, k] = h;
      for (let i = 0; i < 64; i++) {
        const t1 = (k + (rot(e, 6) ^ rot(e, 11) ^ rot(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) >>> 0;
        const t2 = ((rot(a, 2) ^ rot(a, 13) ^ rot(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        k = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      [a, b, c, d, e, f, g, k].forEach((x, i) => { h[i] = (h[i] + x) >>> 0; });
    }
    return h.map((x) => x.toString(16).padStart(8, '0')).join('');
  }

  // ───────────────────────── Patterns ─────────────────────────

  const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Sigma value syntax: * and ? are wildcards; \* \? \\ escape them.
  function sigmaPattern(v) {
    let src = '', lit = '', wild = false;
    for (let i = 0; i < v.length; i++) {
      const c = v[i];
      if (c === '\\' && i + 1 < v.length && '*?\\'.includes(v[i + 1])) { const n = v[++i]; src += escRe(n); lit += n; continue; }
      if (c === '*') { src += '.*'; wild = true; continue; }
      if (c === '?') { src += '.'; wild = true; continue; }
      src += escRe(c); lit += c;
    }
    return { src, lit, wild };
  }

  // kind: exact | contains | startswith | endswith
  function textMatcher(pat, kind, cased) {
    if (!pat.wild) {
      const want = cased ? pat.lit : pat.lit.toLowerCase();
      const norm = cased ? (x) => x : (x) => x.toLowerCase();
      switch (kind) {
        case 'contains': return (x) => norm(x).includes(want);
        case 'startswith': return (x) => norm(x).startsWith(want);
        case 'endswith': return (x) => norm(x).endsWith(want);
        default: return (x) => norm(x) === want;
      }
    }
    const pre = kind === 'contains' || kind === 'endswith' ? '.*' : '';
    const post = kind === 'contains' || kind === 'startswith' ? '.*' : '';
    const re = new RegExp(`^(?:${pre}${pat.src}${post})$`, cased ? 's' : 'is');
    return (x) => re.test(x);
  }

  function ipv4ToInt(ip) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip).trim());
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some((x) => x > 255)) return null;
    return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  }

  // ───────────────────────── Search language ─────────────────────────
  // field:value · field:"phrase with spaces" · field:*part* · field:>=10 · _exists_:field
  // free text · AND / OR / NOT (also && || ! and a leading -) · parentheses. Implicit AND.

  function tokenizeQuery(q) {
    const toks = [];
    let i = 0;
    while (i < q.length) {
      const c = q[i];
      if (/\s/.test(c)) { i++; continue; }
      if (c === '(' || c === ')') { toks.push({ t: c }); i++; continue; }
      if (q.startsWith('&&', i)) { toks.push({ t: 'AND' }); i += 2; continue; }
      if (q.startsWith('||', i)) { toks.push({ t: 'OR' }); i += 2; continue; }
      if ((c === '!' || c === '-') && i + 1 < q.length && !/\s/.test(q[i + 1]) && (i === 0 || /[\s(]/.test(q[i - 1]))) {
        toks.push({ t: 'NOT' }); i++; continue;
      }
      // a term: [field:]value
      let field = null;
      const fm = /^([@A-Za-z_][\w.@\-]*):/.exec(q.slice(i));
      if (fm) { field = fm[1]; i += fm[0].length; }
      let value = '', quoted = false;
      if (q[i] === '"') {
        quoted = true; i++;
        while (i < q.length && q[i] !== '"') {
          if (q[i] === '\\' && (q[i + 1] === '"' || q[i + 1] === '\\')) { value += q[i + 1]; i += 2; continue; }
          value += q[i++];
        }
        if (q[i] !== '"') throw new SLError('unterminated quote in search');
        i++;
      } else {
        while (i < q.length && !/[\s()]/.test(q[i])) value += q[i++];
      }
      if (!field && !quoted && /^(AND|OR|NOT)$/.test(value)) { toks.push({ t: value }); continue; }
      if (field && value === '' && !quoted) throw new SLError(`missing value after "${field}:"`);
      toks.push({ t: 'TERM', field, value, quoted });
    }
    return toks;
  }

  function compileQuery(q, fieldIndex) {
    const query = String(q || '').trim();
    if (!query) return () => true;
    const toks = tokenizeQuery(query);
    let p = 0;
    const peek = () => toks[p];
    // Every real field name that matches (case-insensitive); the name as typed if none is known.
    const resolve = (f) => {
      const known = fieldIndex && fieldIndex.get(f.toLowerCase());
      if (!known) return [f];
      return Array.isArray(known) ? known : [known];
    };
    const values = (r, fs) => { const out = []; for (const f of fs) { const x = r.ev[f]; if (x != null && x !== '') out.push(x); } return out; };

    function term(tok) {
      const v = tok.value;
      if (tok.field === '_source_') {
        const re = new RegExp(`^${v.split('*').map(escRe).join('.*')}$`, 'i');
        return (r) => { const s = sourceOf(r.ev); return [s.product, s.category, s.label, ...s.services].some((x) => x && re.test(x)); };
      }
      if (tok.field === '_exists_') {
        const fs = resolve(v);
        return (r) => values(r, fs).length > 0;
      }
      if (!tok.field) {
        if (v.includes('*')) {
          const re = new RegExp(v.split('*').map(escRe).join('.*'), 'is');
          return (r) => re.test(r.text());
        }
        const want = v.toLowerCase();
        return (r) => r.text().includes(want);
      }
      const fs = resolve(tok.field);
      const cmp = !tok.quoted && /^(>=|<=|>|<)(.+)$/.exec(v);
      if (cmp) {
        const op = cmp[1], raw = cmp[2], num = Number(raw);
        const useNum = !isNaN(num);
        const test = (x) => {
          const a = useNum ? Number(x) : String(x), b = useNum ? num : raw;
          if (useNum && isNaN(a)) return false;
          return op === '>' ? a > b : op === '<' ? a < b : op === '>=' ? a >= b : a <= b;
        };
        return (r) => values(r, fs).some(test);
      }
      if (v === '*' && !tok.quoted) return (r) => values(r, fs).length > 0;
      const m = v.includes('*')
        ? (() => { const re = new RegExp(`^${v.split('*').map(escRe).join('.*')}$`, 'is'); return (x) => re.test(x); })()
        : (() => { const want = v.toLowerCase(); return (x) => x.toLowerCase() === want; })();
      return (r) => values(r, fs).some((x) => m(String(x)));
    }

    function parseOr() {
      let left = parseAnd();
      while (peek() && peek().t === 'OR') { p++; const a = left, b = parseAnd(); left = (r) => a(r) || b(r); }
      return left;
    }
    function parseAnd() {
      let left = parseNot();
      while (peek() && peek().t !== 'OR' && peek().t !== ')') {
        if (peek().t === 'AND') p++;
        const a = left, b = parseNot();
        left = (r) => a(r) && b(r);
      }
      return left;
    }
    function parseNot() {
      if (peek() && peek().t === 'NOT') { p++; const a = parseNot(); return (r) => !a(r); }
      return parseAtom();
    }
    function parseAtom() {
      const tok = toks[p++];
      if (!tok) throw new SLError('search ends unexpectedly');
      if (tok.t === '(') {
        const e = parseOr();
        if (!peek() || peek().t !== ')') throw new SLError('missing ")" in search');
        p++;
        return e;
      }
      if (tok.t === 'TERM') return term(tok);
      throw new SLError(`unexpected "${tok.t}" in search`);
    }
    const fn = parseOr();
    if (p < toks.length) throw new SLError(`unexpected "${toks[p].t === 'TERM' ? toks[p].value : toks[p].t}" in search`);
    return fn;
  }

  // ───────────────────────── Sigma ─────────────────────────

  const CH = {
    sysmon: 'Microsoft-Windows-Sysmon/Operational',
    security: 'Security',
    system: 'System',
    application: 'Application',
    powershell: 'Microsoft-Windows-PowerShell/Operational',
    'powershell-classic': 'Windows PowerShell',
    taskscheduler: 'Microsoft-Windows-TaskScheduler/Operational',
    windefend: 'Microsoft-Windows-Windows Defender/Operational',
    bits: 'Microsoft-Windows-Bits-Client/Operational',
    wmi: 'Microsoft-Windows-WMI-Activity/Operational',
  };

  // category -> [channel, eventIDs[]]
  const CATEGORIES = {
    process_creation: [[CH.sysmon, [1]]],
    process_termination: [[CH.sysmon, [5]]],
    network_connection: [[CH.sysmon, [3]]],
    driver_load: [[CH.sysmon, [6]]],
    image_load: [[CH.sysmon, [7]]],
    create_remote_thread: [[CH.sysmon, [8]]],
    raw_access_thread: [[CH.sysmon, [9]]],
    process_access: [[CH.sysmon, [10]]],
    file_event: [[CH.sysmon, [11]]],
    registry_add: [[CH.sysmon, [12]]],
    registry_delete: [[CH.sysmon, [12]]],
    registry_set: [[CH.sysmon, [13]]],
    registry_rename: [[CH.sysmon, [14]]],
    registry_event: [[CH.sysmon, [12, 13, 14]]],
    create_stream_hash: [[CH.sysmon, [15]]],
    pipe_created: [[CH.sysmon, [17, 18]]],
    wmi_event: [[CH.sysmon, [19, 20, 21]]],
    dns_query: [[CH.sysmon, [22]]],
    file_delete: [[CH.sysmon, [23, 26]]],
    file_change: [[CH.sysmon, [2]]],
    ps_script: [[CH.powershell, [4104]]],
    ps_module: [[CH.powershell, [4103]]],
    ps_classic_start: [[CH['powershell-classic'], [400]]],
    ps_classic_provider_start: [[CH['powershell-classic'], [600]]],
  };

  // Security 4688 fields under Sigma's process_creation names
  const SECURITY_4688_ALIASES = {
    Image: (ev) => ev.NewProcessName,
    ParentImage: (ev) => ev.ParentProcessName,
    ProcessId: (ev) => ev.NewProcessId,
    User: (ev) => (ev.SubjectUserName ? `${ev.SubjectDomainName ? ev.SubjectDomainName + '\\' : ''}${ev.SubjectUserName}` : undefined),
  };

  const PROFILES = {
    sysmon: { label: 'Sysmon (process_creation = Sysmon 1)', processCreation: [[CH.sysmon, [1]]] },
    security: { label: 'Security (process_creation = 4688)', processCreation: [[CH.security, [4688]]] },
    both: { label: 'Sysmon 1 + Security 4688', processCreation: [[CH.sysmon, [1]], [CH.security, [4688]]] },
  };

  const PRODUCT_LABEL = {
    windows: 'Windows', linux: 'Linux', aws: 'AWS', azure: 'Azure / Entra ID', m365: 'Microsoft 365', gcp: 'Google Cloud',
    okta: 'Okta', proofpoint: 'Proofpoint', email: 'Email (.eml)', suricata: 'Suricata', zeek: 'Zeek',
  };
  // null = any service name is accepted (Suricata event_type, Zeek log name)
  const PRODUCT_SERVICES = {
    linux: ['auth', 'sshd', 'sudo', 'cron', 'syslog', 'auditd', 'vsftpd', 'clamav', 'sysmon'],
    aws: ['cloudtrail'], azure: ['signinlogs', 'auditlogs', 'activitylogs'], m365: ['audit', 'exchange', 'threat_management'],
    gcp: ['gcp.audit'], okta: ['okta'], proofpoint: ['tap', 'tap_messages', 'tap_clicks'], email: ['eml'], suricata: null, zeek: null,
  };
  const GENERIC_CATEGORIES = { proxy: 'Web proxy', webserver: 'Web server', firewall: 'Firewall', dns: 'DNS server' };
  const LINUX_CATEGORY_IDS = { process_creation: [1], network_connection: [3], process_termination: [5], file_event: [11], file_delete: [23] };

  function logsourceFilter(ls, profileName) {
    const profile = PROFILES[profileName] || PROFILES.sysmon;
    const notes = [];
    const noAlias = () => null;
    if (!ls || typeof ls !== 'object') return { fn: () => true, aliasFor: noAlias, desc: 'all events', notes: ['no logsource: rule runs on every event'] };
    let product = ls.product ? lc(ls.product) : null;
    const category = ls.category ? lc(ls.category) : null;
    const service = ls.service ? lc(ls.service) : null;
    if (product && !PRODUCT_LABEL[product]) { notes.push(`product "${product}" is not mapped: matching on all events`); product = null; }

    // proxy / webserver / firewall / dns: recognised by the shape of the event, whatever the vendor
    if (category && GENERIC_CATEGORIES[category]) {
      if (product) notes.push(`category "${category}" is recognised by its fields: product "${product}" is not checked`);
      if (service) notes.push(`service "${service}" is ignored for category "${category}"`);
      return { fn: (ev) => sourceOf(ev).category === category, aliasFor: noAlias, desc: `${GENERIC_CATEGORIES[category]} events (category ${category})`, notes };
    }

    const windows = product === 'windows' || (!product && ((category && CATEGORIES[category]) || (service && CH[service])));
    if (windows) {
      let pairs = null;
      if (category) {
        pairs = category === 'process_creation' ? profile.processCreation : CATEGORIES[category];
        if (!pairs) notes.push(`category "${category}" is not mapped: matching on all events`);
      }
      let svcChannel = null;
      if (service) {
        svcChannel = CH[service];
        if (!svcChannel) notes.push(`service "${service}" is not mapped: ignoring it`);
      }
      const sets = pairs ? pairs.map(([ch, ids]) => [ch.toLowerCase(), new Set(ids)]) : null;
      const svc = svcChannel ? svcChannel.toLowerCase() : null;
      const onlyProduct = product === 'windows' && !sets && !svc;
      const aliasFor = (ev) => (String(ev.Channel || '').toLowerCase() === 'security' && Number(ev.EventID) === 4688 ? SECURITY_4688_ALIASES : null);
      const desc = [
        sets ? pairs.map(([ch, ids]) => `${ch} EventID ${ids.join('/')}`).join(' or ') : null,
        svc ? `Channel ${svcChannel}` : null,
        onlyProduct ? 'Windows events' : null,
      ].filter(Boolean).join(' and ') || 'all events';
      return {
        fn: (ev) => {
          if (onlyProduct) return sourceOf(ev).product === 'windows';
          const ch = String(ev.Channel || '').toLowerCase();
          if (svc && ch !== svc) return false;
          if (sets) {
            const id = Number(ev.EventID);
            return sets.some(([c, ids]) => c === ch && ids.has(id));
          }
          return true;
        },
        aliasFor,
        desc,
        notes,
      };
    }

    if (!product) {
      if (category) notes.push(`category "${category}" is not mapped: matching on all events`);
      if (service) notes.push(`service "${service}" is not mapped: ignoring it`);
      return { fn: () => true, aliasFor: noAlias, desc: 'all events', notes };
    }

    // another product: Linux, cloud, identity, email, network sensors
    const known = PRODUCT_SERVICES[product];
    let svc = service;
    if (svc && known && !known.includes(svc)) { notes.push(`service "${svc}" is not mapped for ${product}: ignoring it`); svc = null; }
    let ids = null;
    if (category) {
      if (product === 'linux' && LINUX_CATEGORY_IDS[category]) ids = new Set(LINUX_CATEGORY_IDS[category]);
      else notes.push(`category "${category}" is not mapped for ${product}: ignoring it`);
    }
    const desc = [`${PRODUCT_LABEL[product]} events`, svc ? `service ${svc}` : null, ids ? `Sysmon for Linux EventID ${[...ids].join('/')}` : null].filter(Boolean).join(' · ');
    return {
      fn: (ev) => {
        const s = sourceOf(ev);
        if (s.product !== product) return false;
        if (svc && !s.services.includes(svc)) return false;
        if (ids && !(s.services.includes('sysmon') && ids.has(Number(ev.EventID)))) return false;
        return true;
      },
      aliasFor: noAlias,
      desc,
      notes,
    };
  }

  const KNOWN_MODS = new Set(['contains', 'startswith', 'endswith', 'all', 're', 'i', 'm', 's', 'cased', 'exists', 'gt', 'gte', 'lt', 'lte', 'cidr', 'windash']);

  function windashVariants(v) {
    const dashes = ['-', '/', '–', '—', '―'];
    if (!/(^|\s)-/.test(v)) return [v];
    return dashes.map((d) => v.replace(/(^|\s)-/g, `$1${d}`));
  }

  function valueMatcher(raw, mods) {
    const cased = mods.includes('cased');
    if (mods.includes('exists')) {
      const want = String(raw).toLowerCase() !== 'false';
      return { exists: true, fn: (x) => (x !== undefined && x !== null) === want };
    }
    if (raw === null) return { fn: (x) => x === undefined || x === null || x === '' };
    const v = String(raw);
    if (mods.includes('re')) {
      let flags = '';
      if (mods.includes('i')) flags += 'i';
      if (mods.includes('m')) flags += 'm';
      if (mods.includes('s')) flags += 's';
      let re;
      try { re = new RegExp(v, flags); } catch (e) { throw new SLError(`invalid regular expression ${v}: ${e.message}`); }
      return { fn: (x) => x != null && re.test(String(x)) };
    }
    for (const op of ['gt', 'gte', 'lt', 'lte']) {
      if (mods.includes(op)) {
        const n = Number(v);
        if (isNaN(n)) throw new SLError(`|${op} needs a number, got "${v}"`);
        return {
          fn: (x) => {
            const a = Number(x);
            if (x == null || x === '' || isNaN(a)) return false;
            return op === 'gt' ? a > n : op === 'gte' ? a >= n : op === 'lt' ? a < n : a <= n;
          },
        };
      }
    }
    if (mods.includes('cidr')) {
      const [net, bits] = v.split('/');
      const base = ipv4ToInt(net), b = Number(bits);
      if (base === null || isNaN(b) || b < 0 || b > 32) throw new SLError(`unsupported CIDR "${v}" (IPv4 only)`);
      const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
      return { fn: (x) => { const ip = ipv4ToInt(x); return ip !== null && ((ip & mask) >>> 0) === ((base & mask) >>> 0); } };
    }
    const kind = mods.includes('contains') ? 'contains' : mods.includes('startswith') ? 'startswith' : mods.includes('endswith') ? 'endswith' : 'exact';
    const variants = mods.includes('windash') ? windashVariants(v) : [v];
    const ms = variants.map((s) => textMatcher(sigmaPattern(s), kind, cased));
    return { fn: (x) => x != null && ms.some((m) => m(String(x))) };
  }

  function fieldMatcher(key, value) {
    const [field, ...mods] = String(key).split('|');
    for (const m of mods) {
      if (!KNOWN_MODS.has(m)) throw new SLError(`modifier |${m} is not supported by SigmaLens`);
    }
    const values = Array.isArray(value) ? value : [value];
    if (!values.length) throw new SLError(`field "${field}" has an empty value list`);
    if (values.some((v) => v !== null && typeof v === 'object')) throw new SLError(`field "${field}" has a nested value`);
    const matchers = values.map((v) => valueMatcher(v, mods));
    const all = mods.includes('all');
    return {
      field,
      fn: (ev, alias) => {
        let x = ev[field];
        if (x === undefined && alias && alias[field]) x = alias[field](ev);
        return all ? matchers.every((m) => m.fn(x)) : matchers.some((m) => m.fn(x));
      },
    };
  }

  function keywordMatcher(values) {
    const ms = values.map((v) => {
      if (v === null || typeof v === 'object') throw new SLError('keyword lists can only contain strings');
      return textMatcher(sigmaPattern(String(v)), 'contains', false);
    });
    return (ev) => {
      const vals = Object.values(ev);
      return ms.some((m) => vals.some((x) => x != null && m(String(x))));
    };
  }

  function searchMatcher(name, def) {
    if (def === null || def === undefined) throw new SLError(`search identifier "${name}" is empty`);
    if (typeof def === 'string') return keywordMatcher([def]);
    if (Array.isArray(def)) {
      if (def.every((x) => x === null || typeof x !== 'object')) return keywordMatcher(def);
      const maps = def.map((m) => {
        if (!m || typeof m !== 'object' || Array.isArray(m)) throw new SLError(`search identifier "${name}" mixes maps and plain values`);
        return mapMatcher(m);
      });
      return (ev, alias) => maps.some((f) => f(ev, alias));
    }
    if (typeof def === 'object') return mapMatcher(def);
    throw new SLError(`search identifier "${name}" has an unsupported type`);
  }

  function mapMatcher(m) {
    const fields = Object.entries(m).map(([k, v]) => fieldMatcher(k, v));
    return (ev, alias) => fields.every((f) => f.fn(ev, alias));
  }

  function globToRe(g) {
    return new RegExp(`^${g.split('*').map(escRe).join('.*')}$`);
  }

  function compileCondition(cond, names) {
    if (/\|/.test(cond)) throw new SLError('aggregations in the condition ("| count() ...") are not supported');
    const toks = cond.match(/\(|\)|[^\s()]+/g) || [];
    let p = 0;
    const peek = () => (toks[p] || '').toLowerCase();

    function ofExpr(quant) {
      p++; // "of"
      const target = toks[p++];
      if (!target) throw new SLError(`condition: "${quant} of" needs a target`);
      let group;
      if (target.toLowerCase() === 'them') group = names.filter((n) => !n.startsWith('_'));
      else {
        const re = globToRe(target);
        group = names.filter((n) => re.test(n));
      }
      if (!group.length) throw new SLError(`condition: "${target}" matches no search identifier`);
      if (quant === 'all') return (get) => group.every((n) => get(n));
      const k = Number(quant);
      return (get) => group.filter((n) => get(n)).length >= k;
    }
    function atom() {
      const t = toks[p];
      if (!t) throw new SLError('condition ends unexpectedly');
      const lt = t.toLowerCase();
      if (t === '(') {
        p++;
        const e = orE();
        if (toks[p] !== ')') throw new SLError('condition: missing ")"');
        p++;
        return e;
      }
      if ((lt === 'all' || /^\d+$/.test(lt)) && (toks[p + 1] || '').toLowerCase() === 'of') { p++; return ofExpr(lt); }
      if (['and', 'or', 'not', ')'].includes(lt)) throw new SLError(`condition: unexpected "${t}"`);
      p++;
      if (!names.includes(t)) throw new SLError(`condition: unknown search identifier "${t}"`);
      return (get) => get(t);
    }
    function notE() {
      if (peek() === 'not') { p++; const a = notE(); return (g) => !a(g); }
      return atom();
    }
    function andE() {
      let l = notE();
      while (peek() === 'and') { p++; const a = l, b = notE(); l = (g) => a(g) && b(g); }
      return l;
    }
    function orE() {
      let l = andE();
      while (peek() === 'or') { p++; const a = l, b = andE(); l = (g) => a(g) || b(g); }
      return l;
    }
    const fn = orE();
    if (p < toks.length) throw new SLError(`condition: unexpected "${toks[p]}"`);
    return fn;
  }

  function compileRule(input, profile) {
    const rule = typeof input === 'string' ? parseYaml(input) : input;
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new SLError('a Sigma rule must be a YAML map');
    if (rule.correlation) throw new SLError('correlation rules are not supported');
    const det = rule.detection;
    if (!det || typeof det !== 'object') throw new SLError('missing "detection" section');
    if (det.condition == null) throw new SLError('missing "detection.condition"');
    if (det.timeframe) throw new SLError('"timeframe" (aggregation) is not supported');
    const names = Object.keys(det).filter((k) => k !== 'condition');
    if (!names.length) throw new SLError('detection has no search identifiers');
    const searches = {};
    for (const n of names) {
      try { searches[n] = searchMatcher(n, det[n]); } catch (e) { throw new SLError(`${n}: ${e.message}`); }
    }
    const conds = (Array.isArray(det.condition) ? det.condition : [det.condition]).map((c) => compileCondition(String(c), names));
    const ls = logsourceFilter(rule.logsource, profile);
    const match = (ev) => {
      if (!ls.fn(ev)) return false;
      const alias = ls.aliasFor(ev);
      const memo = {};
      const get = (n) => (n in memo ? memo[n] : (memo[n] = searches[n](ev, alias)));
      return conds.some((c) => c(get));
    };
    return {
      title: rule.title || '(untitled rule)',
      id: rule.id || null,
      level: rule.level || null,
      status: rule.status || null,
      description: rule.description || null,
      tags: Array.isArray(rule.tags) ? rule.tags : [],
      logsource: rule.logsource || null,
      logsourceDesc: ls.desc,
      notes: ls.notes,
      match,
    };
  }

  function runRule(compiled, recs) {
    const hits = [];
    for (const r of recs) if (compiled.match(r.ev)) hits.push(r);
    return hits;
  }

  // lower-case field name -> field name as it appears in the data (first seen wins)
  function buildFieldIndex(recs) {
    const idx = new Map();
    for (const r of recs) {
      for (const k of Object.keys(r.ev)) {
        // Field names are case-insensitive in searches. Different sources may spell the same name
        // differently (Windows IpAddress, Entra ID IPAddress), so keep every spelling.
        const lk = k.toLowerCase();
        const all = idx.get(lk);
        if (!all) idx.set(lk, [k]);
        else if (!all.includes(k)) all.push(k);
      }
    }
    return idx;
  }

  return {
    SLError, parseYaml, parseYamlDocs, loadEvents, loadEml, normalizeEvent, parseTime, sourceOf, sha256,
    compileQuery, compileRule, runRule, buildFieldIndex, PROFILES, CATEGORIES, CHANNELS: CH, SOURCES,
  };
});
