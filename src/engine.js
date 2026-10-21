/*
 * SigmaLens engine. No dependencies; runs in the browser and in Node.
 *  - parseYaml / parseYamlDocs: the YAML subset used by Sigma rules
 *  - loadEvents: JSON / JSONL / evtx_dump-style JSON -> flat records
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

  const TIME_FIELDS = ['@timestamp', 'TimeCreated', 'SystemTime', 'UtcTime', 'timestamp', 'Timestamp', 'time'];

  function parseTime(v) {
    if (v == null || v === '') return NaN;
    let s = String(v).trim();
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
      else if (Array.isArray(v)) out[key] = v.every((x) => x === null || typeof x !== 'object') ? v.join(', ') : JSON.stringify(v);
      else out[key] = v;
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
    if (s[0] === '[') {
      try { objs = JSON.parse(s); } catch (e) { errors.push(`${src}: invalid JSON array (${e.message})`); }
    } else {
      s.split(/\r?\n/).forEach((line, n) => {
        if (!line.trim()) return;
        try { objs.push(JSON.parse(line)); } catch (e) { if (errors.length < 20) errors.push(`${src}:${n + 1}: invalid JSON line`); }
      });
    }
    let i = startIndex || 0;
    for (const o of objs) {
      if (!o || typeof o !== 'object') continue;
      const ev = normalizeEvent(o);
      let t = NaN;
      for (const f of TIME_FIELDS) { if (ev[f] != null && ev[f] !== '') { t = parseTime(ev[f]); if (!isNaN(t)) break; } }
      recs.push(new Rec(ev, t, src, i++));
    }
    return { recs, errors };
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
    const resolve = (f) => (fieldIndex && fieldIndex.get(f.toLowerCase())) || f;

    function term(tok) {
      const v = tok.value;
      if (tok.field === '_exists_') {
        const f = resolve(v);
        return (r) => r.ev[f] != null && r.ev[f] !== '';
      }
      if (!tok.field) {
        if (v.includes('*')) {
          const re = new RegExp(v.split('*').map(escRe).join('.*'), 'is');
          return (r) => re.test(r.text());
        }
        const want = v.toLowerCase();
        return (r) => r.text().includes(want);
      }
      const f = resolve(tok.field);
      const cmp = !tok.quoted && /^(>=|<=|>|<)(.+)$/.exec(v);
      if (cmp) {
        const op = cmp[1], raw = cmp[2], num = Number(raw);
        const useNum = !isNaN(num);
        return (r) => {
          const x = r.ev[f];
          if (x == null || x === '') return false;
          const a = useNum ? Number(x) : String(x), b = useNum ? num : raw;
          if (useNum && isNaN(a)) return false;
          return op === '>' ? a > b : op === '<' ? a < b : op === '>=' ? a >= b : a <= b;
        };
      }
      if (v === '*' && !tok.quoted) return (r) => r.ev[f] != null && r.ev[f] !== '';
      const m = v.includes('*')
        ? (() => { const re = new RegExp(`^${v.split('*').map(escRe).join('.*')}$`, 'is'); return (x) => re.test(x); })()
        : (() => { const want = v.toLowerCase(); return (x) => x.toLowerCase() === want; })();
      return (r) => { const x = r.ev[f]; return x != null && m(String(x)); };
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

  function logsourceFilter(ls, profileName) {
    const profile = PROFILES[profileName] || PROFILES.sysmon;
    const notes = [];
    if (!ls || typeof ls !== 'object') return { fn: () => true, notes: ['no logsource: rule runs on every event'] };
    const product = ls.product ? String(ls.product).toLowerCase() : null;
    const category = ls.category ? String(ls.category).toLowerCase() : null;
    const service = ls.service ? String(ls.service).toLowerCase() : null;
    if (product && product !== 'windows') notes.push(`product "${product}" is not mapped: matching on all events`);

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
    const aliasFor = (ev) => (String(ev.Channel || '').toLowerCase() === 'security' && Number(ev.EventID) === 4688 ? SECURITY_4688_ALIASES : null);
    const desc = [
      sets ? pairs.map(([ch, ids]) => `${ch} EventID ${ids.join('/')}`).join(' or ') : null,
      svc ? `Channel ${svcChannel}` : null,
    ].filter(Boolean).join(' and ') || 'all events';
    return {
      fn: (ev) => {
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
        const lk = k.toLowerCase();
        if (!idx.has(lk)) idx.set(lk, k);
      }
    }
    return idx;
  }

  return {
    SLError, parseYaml, parseYamlDocs, loadEvents, normalizeEvent, parseTime,
    compileQuery, compileRule, runRule, buildFieldIndex, PROFILES, CATEGORIES, CHANNELS: CH,
  };
});
