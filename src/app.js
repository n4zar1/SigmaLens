/* SigmaLens UI. Plain DOM, no framework. Every value from the logs is escaped before it reaches innerHTML. */
(function () {
  'use strict';
  const SL = window.SigmaLens;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtN = (n) => n.toLocaleString('en-US');
  const PAGE = 200;

  const CHANNEL_SHORT = {
    'microsoft-windows-sysmon/operational': 'Sysmon',
    security: 'Security',
    system: 'System',
    application: 'Application',
    'microsoft-windows-powershell/operational': 'PowerShell',
    'windows powershell': 'PS classic',
    'microsoft-windows-taskscheduler/operational': 'TaskSched',
    'microsoft-windows-windows defender/operational': 'Defender',
  };

  const state = {
    recs: [], sources: [], fieldIndex: new Map(), profile: 'sysmon',
    results: [], sortDesc: false, shown: PAGE, open: new Set(),
    extraCols: [], openField: null,
    rules: [], editing: null, sigmaHits: [], sigmaShown: PAGE, sigmaOpen: new Set(),
  };

  // ───────── helpers ─────────
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  function fmtTime(t) {
    if (!isFinite(t)) return '—';
    const d = new Date(t);
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}`;
  }
  const toLocalInput = (t) => fmtTime(t).slice(0, 19).replace(' ', 'T');
  const fromInput = (v) => (v ? Date.parse(v.length === 16 ? `${v}:00Z` : `${v}Z`) : NaN);
  const chanShort = (c) => CHANNEL_SHORT[String(c || '').toLowerCase()] || (c ? String(c).split('/')[0].replace('Microsoft-Windows-', '') : '—');

  function details(ev) {
    const id = Number(ev.EventID), ch = String(ev.Channel || '').toLowerCase();
    const sysmon = ch.includes('sysmon');
    const j = (...xs) => xs.filter((x) => x != null && x !== '' && x !== '-').join(' ');
    if (sysmon) {
      if (id === 1) return ev.CommandLine || ev.Image;
      if (id === 3) return j(ev.Image, '→', `${ev.DestinationIp}:${ev.DestinationPort}`, ev.DestinationHostname ? `(${ev.DestinationHostname})` : '');
      if (id === 22) return j(ev.Image, '→', ev.QueryName);
      if (id === 11 || id === 23 || id === 26) return j(ev.Image, '→', ev.TargetFilename);
      if (id >= 12 && id <= 14) return j(ev.EventType, ev.TargetObject, ev.Details ? `= ${ev.Details}` : '');
      if (id === 5) return ev.Image;
      if (id === 7) return j(ev.Image, 'loaded', ev.ImageLoaded);
      if (id === 10) return j(ev.SourceImage, '→', ev.TargetImage, ev.GrantedAccess);
    }
    if (ev.ScriptBlockText) return ev.ScriptBlockText;
    if (id === 4688) return ev.CommandLine || ev.NewProcessName;
    if (id >= 4698 && id <= 4702) return j(ev.SubjectUserName, '·', ev.TaskName);
    if (id === 4624 || id === 4625) return j(ev.TargetDomainName ? `${ev.TargetDomainName}\\${ev.TargetUserName}` : ev.TargetUserName, 'type', ev.LogonType, ev.IpAddress && ev.IpAddress !== '-' ? `from ${ev.IpAddress}` : '');
    const skip = new Set(['@timestamp', 'EventID', 'Channel', 'Computer', 'EventRecordID', 'Provider', 'Level', 'Task', 'Keywords', 'Version', 'Opcode']);
    return Object.entries(ev).filter(([k, v]) => !skip.has(k) && v != null && v !== '').slice(0, 4).map(([k, v]) => `${k}=${v}`).join('  ');
  }

  function busy(msg) { const b = $('busy'); if (msg) { b.textContent = msg; b.hidden = false; } else b.hidden = true; }
  const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));

  // ───────── views ─────────
  function show(view) {
    const hasData = state.recs.length > 0;
    document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.view === view)));
    $('welcome').hidden = !(view === 'search' && !hasData);
    $('view-search').hidden = !(view === 'search' && hasData);
    $('view-sigma').hidden = view !== 'sigma';
    $('view-rules').hidden = view !== 'rules';
    $('view-guide').hidden = view !== 'guide';
    state.view = view;
    try { localStorage.setItem('sigmalens.view', view); } catch (e) { /* storage blocked */ }
  }

  function updateStat() {
    const ts = state.recs.map((r) => r.t).filter(isFinite);
    let span = '';
    if (ts.length) {
      let lo = Infinity, hi = -Infinity;
      for (const t of ts) { if (t < lo) lo = t; if (t > hi) hi = t; }
      span = ` · ${fmtTime(lo).slice(0, 16)} → ${fmtTime(hi).slice(0, 16)} UTC`;
    }
    $('stat').innerHTML = state.recs.length
      ? `<b>${fmtN(state.recs.length)}</b> events from <b>${state.sources.length}</b> file${state.sources.length === 1 ? '' : 's'}${esc(span)}`
      : 'No data loaded';
    $('rulecount').textContent = state.rules.length;
  }

  // ───────── loading ─────────
  async function addEventsText(text, name) {
    busy(`Parsing ${name}…`);
    await nextFrame();
    const { recs, errors } = SL.loadEvents(text, name, state.recs.length);
    for (const r of recs) state.recs.push(r);
    state.sources.push({ name, count: recs.length });
    state.fieldIndex = SL.buildFieldIndex(state.recs);
    if (errors.length) console.warn(errors);
    busy();
    return { count: recs.length, errors };
  }

  function splitDocs(text) {
    return text.replace(/\r\n?/g, '\n').split(/^---\s*$/m).map((s) => s.trim()).filter(Boolean);
  }

  function addRulesText(text, name) {
    const docs = splitDocs(text);
    docs.forEach((doc, i) => state.rules.push({ name: docs.length > 1 ? `${name} #${i + 1}` : name, text: doc + '\n', hits: null, error: null, compiled: null }));
    compileRules();
  }

  async function handleFiles(files) {
    let evFiles = 0, ruleFiles = 0;
    const errs = [];
    for (const f of files) {
      const text = await f.text();
      if (/\.ya?ml$/i.test(f.name)) { addRulesText(text, f.name); ruleFiles++; }
      else {
        const r = await addEventsText(text, f.name);
        evFiles++;
        if (r.errors.length) errs.push(...r.errors.slice(0, 3));
      }
    }
    updateStat();
    if (evFiles) { show('search'); runSearch(); }
    else if (ruleFiles) { renderRules(); show(state.recs.length ? 'rules' : state.view || 'search'); }
    if (errs.length) alertBar(errs.join('\n'));
  }

  function alertBar(msg) {
    const e = $('qerr');
    e.textContent = msg;
    e.hidden = false;
  }

  // ───────── search ─────────
  function runSearch() {
    if (!state.recs.length) { show('search'); return; }
    const qerr = $('qerr');
    let pred;
    try { pred = SL.compileQuery($('q').value, state.fieldIndex); qerr.hidden = true; }
    catch (e) { qerr.textContent = e.message; qerr.hidden = false; return; }
    const from = fromInput($('from').value), to = fromInput($('to').value);
    const out = [];
    for (const r of state.recs) {
      if (isFinite(from) && !(r.t >= from)) continue;
      if (isFinite(to) && !(r.t <= to)) continue;
      if (pred(r)) out.push(r);
    }
    sortRecs(out, state.sortDesc);
    state.results = out;
    state.shown = PAGE;
    state.open.clear();
    renderHisto();
    renderFields();
    renderResults();
    saveQuery();
  }

  function sortRecs(arr, desc) {
    arr.sort((a, b) => {
      const ta = isFinite(a.t) ? a.t : Infinity, tb = isFinite(b.t) ? b.t : Infinity;
      return (ta - tb || a.i - b.i) * (desc ? -1 : 1);
    });
  }

  function saveQuery() {
    try { localStorage.setItem('sigmalens.q', $('q').value); } catch (e) { /* storage blocked */ }
  }

  const INTERVALS = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 10800, 21600, 43200, 86400, 604800].map((s) => s * 1000);

  function renderHisto() {
    const box = $('histo');
    const ts = state.results.map((r) => r.t).filter(isFinite);
    if (!ts.length) { box.innerHTML = '<div class="empty">No timestamps to chart.</div>'; return; }
    let lo = Infinity, hi = -Infinity;
    for (const t of ts) { if (t < lo) lo = t; if (t > hi) hi = t; }
    const span = Math.max(hi - lo, 1000);
    const step = INTERVALS.find((s) => span / s <= 80) || INTERVALS[INTERVALS.length - 1];
    const start = Math.floor(lo / step) * step;
    const n = Math.floor((hi - start) / step) + 1;
    const counts = new Array(n).fill(0);
    for (const t of ts) counts[Math.floor((t - start) / step)]++;
    const max = Math.max(...counts);
    const w = 1000 / n;
    const bars = counts.map((c, i) => c
      ? `<rect class="bar" x="${(i * w + w * 0.08).toFixed(2)}" width="${(w * 0.84).toFixed(2)}" y="${(64 - (c / max) * 62).toFixed(2)}" height="${((c / max) * 62).toFixed(2)}" data-i="${i}"><title>${esc(fmtTime(start + i * step).slice(0, 19))} · ${fmtN(c)} events</title></rect>`
      : '').join('');
    const label = step >= 86400000 ? `${step / 86400000} d` : step >= 3600000 ? `${step / 3600000} h` : step >= 60000 ? `${step / 60000} min` : `${step / 1000} s`;
    box.innerHTML = `<svg viewBox="0 0 1000 64" preserveAspectRatio="none" role="img" aria-label="Events over time">${bars}</svg>
      <div class="axis"><span>${esc(fmtTime(start).slice(0, 19))}</span><span>${label} per bar · click a bar to zoom</span><span>${esc(fmtTime(start + n * step).slice(0, 19))}</span></div>`;
    box.querySelectorAll('rect.bar').forEach((el) => el.addEventListener('click', () => {
      const i = Number(el.dataset.i);
      $('from').value = toLocalInput(start + i * step);
      $('to').value = toLocalInput(start + (i + 1) * step - 1);
      runSearch();
    }));
  }

  function renderFields() {
    const counts = new Map();
    const sample = state.results.length > 20000 ? state.results.slice(0, 20000) : state.results;
    for (const r of sample) for (const k of Object.keys(r.ev)) counts.set(k, (counts.get(k) || 0) + 1);
    const filt = $('ffilter').value.trim().toLowerCase();
    const names = [...counts.keys()].filter((k) => !filt || k.toLowerCase().includes(filt))
      .sort((a, b) => counts.get(b) - counts.get(a) || a.localeCompare(b));
    $('fieldcount').textContent = counts.size ? `(${counts.size})` : '';
    const pct = (c) => `${Math.round((c / Math.max(sample.length, 1)) * 100)}%`;
    $('fields').innerHTML = names.map((k) => {
      const isCol = state.extraCols.includes(k);
      const open = state.openField === k;
      return `<div class="field${isCol ? ' col' : ''}" data-f="${esc(k)}"><button type="button" aria-expanded="${open}"><span>${esc(k)}</span><span>${pct(counts.get(k))}</span></button>${open ? topValues(k) : ''}</div>`;
    }).join('') || '<div class="muted" style="padding:10px">No fields.</div>';
  }

  function topValues(field) {
    const m = new Map();
    for (const r of state.results) {
      const v = r.ev[field];
      if (v == null || v === '') continue;
      const s = String(v);
      m.set(s, (m.get(s) || 0) + 1);
    }
    const top = [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const isCol = state.extraCols.includes(field);
    return `<div class="vals">${top.map(([v, c]) => `<div class="val" data-v="${esc(v)}"><span class="v" title="${esc(v)}">${esc(v)}</span><span class="n">${fmtN(c)}</span>
      <button class="ib" data-act="inc" title="Filter for this value">+</button><button class="ib" data-act="exc" title="Filter out this value">−</button></div>`).join('')}
      <div style="margin-top:6px;display:flex;gap:6px"><button class="btn sm" data-act="col">${isCol ? 'Remove column' : 'Add as column'}</button><span class="muted" style="font-size:11.5px;align-self:center">${fmtN(m.size)} distinct</span></div></div>`;
  }

  function addFilter(field, value, negate) {
    const v = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const term = `${negate ? 'NOT ' : ''}${field}:"${v}"`;
    const cur = $('q').value.trim();
    $('q').value = cur ? `${cur} AND ${term}` : term;
    show('search');
    runSearch();
  }

  function cols() { return ['Time', 'Source', 'ID', ...state.extraCols, 'Details']; }

  function rowsHtml(recs, shown, openSet, actions) {
    const c = cols();
    let html = `<table class="tbl"><thead><tr>${c.map((h) => `<th${h === 'Time' ? ' class="sortable" data-sort="1" title="Sort by time"' : ''}>${esc(h)}${h === 'Time' ? (state.sortDesc ? ' ↓' : ' ↑') : ''}</th>`).join('')}</tr></thead><tbody>`;
    for (const r of recs.slice(0, shown)) {
      const ev = r.ev;
      const det = String(details(ev) ?? '');
      const open = openSet.has(r.i);
      html += `<tr class="row${open ? ' open' : ''}" data-i="${r.i}"><td class="time">${esc(fmtTime(r.t))}</td><td><span class="chan">${esc(chanShort(ev.Channel))}</span></td><td>${esc(ev.EventID ?? '')}</td>`;
      for (const f of state.extraCols) html += `<td class="det">${esc(ev[f] ?? '')}</td>`;
      html += `<td class="det">${esc(det.length > 400 ? det.slice(0, 400) + '…' : det)}</td></tr>`;
      if (open) {
        const kv = Object.entries(ev).map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${esc(v ?? '')}</div><div class="a" data-f="${esc(k)}" data-v="${esc(v ?? '')}">${actions}</div>`).join('');
        html += `<tr class="detail"><td colspan="${c.length}"><div class="kv">${kv}<div class="k">source</div><div class="v">${esc(r.src)}</div><div></div></div></td></tr>`;
      }
    }
    html += '</tbody></table>';
    if (recs.length > shown) html += `<div class="more"><button class="btn sm" data-more="1">Show ${fmtN(Math.min(PAGE, recs.length - shown))} more (${fmtN(recs.length - shown)} left)</button></div>`;
    if (!recs.length) html += '<div class="muted" style="padding:14px">No events match.</div>';
    return html;
  }

  const SEARCH_ACTIONS = '<button class="ib" data-act="inc" title="Filter for value">+</button><button class="ib" data-act="exc" title="Filter out value">−</button><button class="ib" data-act="sig" title="Copy as Sigma field">σ</button>';

  function renderResults() {
    $('rescount').textContent = `${fmtN(state.results.length)} events`;
    $('results').innerHTML = rowsHtml(state.results, state.shown, state.open, SEARCH_ACTIONS);
  }

  function sigmaLine(field, value) {
    const v = String(value);
    return `${field}: '${v.replace(/'/g, "''")}'`;
  }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); flash('Copied to clipboard'); }
    catch (e) { window.prompt('Copy:', text); }
  }
  function flash(msg) { busy(msg); setTimeout(() => busy(), 1200); }

  function bindTable(container, getList, openSet, rerender, onPage) {
    container.addEventListener('click', (e) => {
      const more = e.target.closest('[data-more]');
      if (more) { onPage(); return; }
      if (e.target.closest('[data-sort]')) {
        state.sortDesc = !state.sortDesc;
        sortRecs(state.results, state.sortDesc);
        sortRecs(state.sigmaHits, state.sortDesc);
        renderResults(); renderSigmaHits();
        return;
      }
      const act = e.target.closest('[data-act]');
      if (act) {
        const holder = act.closest('[data-f]');
        const f = holder.dataset.f, v = holder.dataset.v;
        if (act.dataset.act === 'inc') addFilter(f, v, false);
        else if (act.dataset.act === 'exc') addFilter(f, v, true);
        else if (act.dataset.act === 'sig') copy(sigmaLine(f, v));
        return;
      }
      const row = e.target.closest('tr.row');
      if (row && !window.getSelection().toString()) {
        const i = Number(row.dataset.i);
        if (openSet.has(i)) openSet.delete(i); else openSet.add(i);
        rerender();
      }
    });
  }

  function exportCsv() {
    const keys = ['@timestamp', 'Channel', 'EventID', 'Computer', ...state.extraCols];
    const allKeys = new Set(keys);
    const q = (s) => `"${String(s ?? '').replace(/"/g, '""')}"`;
    const lines = [[...allKeys, 'Details'].map(q).join(',')];
    for (const r of state.results) lines.push([...[...allKeys].map((k) => (k === '@timestamp' ? fmtTime(r.t) : r.ev[k])), details(r.ev)].map(q).join(','));
    const blob = new Blob([lines.join('\r\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'sigmalens-results.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ───────── sigma editor ─────────
  const TEMPLATE = `title: My detection
status: experimental
description: Describe what this rule should catch.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    condition: selection
level: medium
`;

  function updateGutter(badLine) {
    const n = $('editor').value.split('\n').length;
    let s = '';
    for (let i = 1; i <= n; i++) s += (i === badLine ? `<span class="bad">${i}</span>` : i) + '\n';
    $('gutter').innerHTML = s;
    $('gutter').scrollTop = $('editor').scrollTop;
  }

  function runEditor() {
    const text = $('editor').value;
    try { localStorage.setItem('sigmalens.rule', text); } catch (e) { /* storage blocked */ }
    const info = $('ruleinfo');
    let c;
    try { c = SL.compileRule(text, state.profile); }
    catch (e) {
      info.innerHTML = `<div class="err">${esc(e.message)}</div>`;
      updateGutter(e.line);
      $('hitcount').textContent = '–'; $('hitcount').className = 'hitcount zero';
      $('hitlabel').textContent = 'Fix the rule to run it';
      return;
    }
    updateGutter();
    info.innerHTML = `<div><b>${esc(c.title)}</b> ${c.level ? `<span class="lvl ${esc(c.level)}">${esc(c.level)}</span>` : ''}</div>
      <div class="muted">Reads: <span class="mono">${esc(c.logsourceDesc)}</span></div>
      ${c.notes.map((n) => `<div class="note">${esc(n)}</div>`).join('')}`;
    if (!state.recs.length) {
      $('hitcount').textContent = '–'; $('hitcount').className = 'hitcount zero';
      $('hitlabel').textContent = 'Rule is valid. Load some logs to run it.';
      return;
    }
    state.sigmaHits = SL.runRule(c, state.recs);
    sortRecs(state.sigmaHits, state.sortDesc);
    state.sigmaShown = PAGE;
    state.sigmaOpen.clear();
    const n = state.sigmaHits.length;
    $('hitcount').textContent = fmtN(n);
    $('hitcount').className = `hitcount ${n ? 'some' : 'zero'}`;
    $('hitlabel').textContent = n === 1 ? 'match' : 'matches';
    renderSigmaHits();
  }

  function renderSigmaHits() {
    $('sigma-results').innerHTML = state.sigmaHits.length || state.recs.length ? rowsHtml(state.sigmaHits, state.sigmaShown, state.sigmaOpen, SEARCH_ACTIONS) : '';
  }

  // ───────── rules list ─────────
  function compileRules() {
    for (const r of state.rules) {
      try { r.compiled = SL.compileRule(r.text, state.profile); r.error = null; }
      catch (e) { r.compiled = null; r.error = e.message; }
      r.hits = null;
    }
  }

  function runAll() {
    compileRules();
    for (const r of state.rules) if (r.compiled) r.hits = SL.runRule(r.compiled, state.recs).length;
    renderRules();
  }

  function renderRules() {
    $('rulecount').textContent = state.rules.length;
    if (!state.rules.length) { $('rules').innerHTML = '<div class="muted" style="padding:14px">No rules loaded. Load .yml files or save one from the Sigma editor.</div>'; return; }
    $('rules').innerHTML = `<table class="tbl rules"><thead><tr><th>Rule</th><th>Level</th><th>Reads</th><th style="text-align:right">Hits</th><th></th></tr></thead><tbody>${state.rules.map((r, i) => `
      <tr><td><b>${esc(r.compiled ? r.compiled.title : r.name)}</b><div class="muted" style="font-size:12px">${esc(r.name)}</div>${r.error ? `<div class="err">${esc(r.error)}</div>` : ''}</td>
      <td>${r.compiled && r.compiled.level ? `<span class="lvl ${esc(r.compiled.level)}">${esc(r.compiled.level)}</span>` : ''}</td>
      <td class="muted" style="font-size:12px">${r.compiled ? esc(r.compiled.logsourceDesc) : ''}</td>
      <td class="n">${r.hits == null ? '–' : `<b style="color:${r.hits ? 'var(--hit)' : 'var(--muted)'}">${fmtN(r.hits)}</b>`}</td>
      <td style="white-space:nowrap"><button class="btn sm" data-open="${i}">Open</button> <button class="btn sm ghost" data-del="${i}" title="Remove">✕</button></td></tr>`).join('')}</tbody></table>`;
  }

  function openRule(i) {
    state.editing = i;
    $('editor').value = state.rules[i].text;
    show('sigma');
    runEditor();
  }

  // ───────── wiring ─────────
  function init() {
    const prof = $('profile');
    prof.innerHTML = Object.entries(SL.PROFILES).map(([k, p]) => `<option value="${k}">${esc(p.label)}</option>`).join('');
    try {
      state.profile = localStorage.getItem('sigmalens.profile') || 'sysmon';
      $('q').value = localStorage.getItem('sigmalens.q') || '';
      $('editor').value = localStorage.getItem('sigmalens.rule') || TEMPLATE;
      const th = localStorage.getItem('sigmalens.theme');
      if (th) document.documentElement.dataset.theme = th;
    } catch (e) { $('editor').value = TEMPLATE; }
    if (!SL.PROFILES[state.profile]) state.profile = 'sysmon';
    prof.value = state.profile;
    updateGutter();

    prof.addEventListener('change', () => {
      state.profile = prof.value;
      try { localStorage.setItem('sigmalens.profile', state.profile); } catch (e) { /* storage blocked */ }
      compileRules(); renderRules();
      if (state.view === 'sigma') runEditor();
    });
    document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => {
      show(t.dataset.view);
      if (t.dataset.view === 'sigma') runEditor();
      if (t.dataset.view === 'rules') renderRules();
    }));
    const pick = () => $('file').click();
    $('open').addEventListener('click', pick);
    $('open2').addEventListener('click', pick);
    $('loadrule').addEventListener('click', pick);
    $('loadrules').addEventListener('click', pick);
    $('file').addEventListener('change', (e) => { handleFiles([...e.target.files]); e.target.value = ''; });

    $('run').addEventListener('click', runSearch);
    $('q').addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });
    $('from').addEventListener('change', runSearch);
    $('to').addEventListener('change', runSearch);
    $('clear').addEventListener('click', () => { $('q').value = ''; $('from').value = ''; $('to').value = ''; runSearch(); });
    $('ffilter').addEventListener('input', renderFields);
    $('export').addEventListener('click', exportCsv);

    $('fields').addEventListener('click', (e) => {
      const fieldEl = e.target.closest('.field');
      if (!fieldEl) return;
      const f = fieldEl.dataset.f;
      const act = e.target.closest('[data-act]');
      if (act) {
        if (act.dataset.act === 'col') {
          state.extraCols = state.extraCols.includes(f) ? state.extraCols.filter((x) => x !== f) : [...state.extraCols, f];
          renderFields(); renderResults(); renderSigmaHits();
        } else {
          addFilter(f, act.closest('.val').dataset.v, act.dataset.act === 'exc');
        }
        return;
      }
      if (e.target.closest('.field > button')) { state.openField = state.openField === f ? null : f; renderFields(); }
    });

    bindTable($('results'), () => state.results, state.open, renderResults, () => { state.shown += PAGE; renderResults(); });
    bindTable($('sigma-results'), () => state.sigmaHits, state.sigmaOpen, renderSigmaHits, () => { state.sigmaShown += PAGE; renderSigmaHits(); });

    // editor
    const ed = $('editor');
    let t = null;
    ed.addEventListener('input', () => {
      updateGutter();
      if ($('live').checked && state.recs.length < 300000) { clearTimeout(t); t = setTimeout(runEditor, 350); }
    });
    ed.addEventListener('scroll', () => { $('gutter').scrollTop = ed.scrollTop; });
    ed.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runEditor(); return; }
      if (e.key === 'Tab') {
        e.preventDefault();
        const s = ed.selectionStart;
        ed.setRangeText('    ', s, ed.selectionEnd, 'end');
        updateGutter();
      }
    });
    $('runrule').addEventListener('click', runEditor);
    $('saverule').addEventListener('click', () => {
      const text = ed.value;
      let title = 'rule';
      try { title = SL.parseYaml(text).title || title; } catch (e) { /* keep default */ }
      if (state.editing != null && state.rules[state.editing]) state.rules[state.editing].text = text;
      else { state.rules.push({ name: `${title}.yml`, text }); state.editing = state.rules.length - 1; }
      compileRules(); renderRules(); flash('Saved to Rules');
    });
    $('hits2search').addEventListener('click', () => {
      state.results = state.sigmaHits.slice();
      state.shown = PAGE; state.open.clear();
      $('q').value = '';
      show('search');
      renderHisto(); renderFields(); renderResults();
      $('rescount').textContent = `${fmtN(state.results.length)} events (Sigma matches)`;
    });

    // rules list
    $('runall').addEventListener('click', runAll);
    $('rules').addEventListener('click', (e) => {
      const o = e.target.closest('[data-open]');
      if (o) { openRule(Number(o.dataset.open)); return; }
      const d = e.target.closest('[data-del]');
      if (d) {
        const i = Number(d.dataset.del);
        state.rules.splice(i, 1);
        if (state.editing === i) state.editing = null; else if (state.editing > i) state.editing--;
        renderRules();
      }
    });

    // drag and drop
    let depth = 0;
    window.addEventListener('dragenter', (e) => { if ([...e.dataTransfer.types].includes('Files')) { depth++; $('drop').hidden = false; } });
    window.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) $('drop').hidden = true; });
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => { e.preventDefault(); depth = 0; $('drop').hidden = true; if (e.dataTransfer.files.length) handleFiles([...e.dataTransfer.files]); });

    // misc
    $('help').addEventListener('click', () => $('helpdlg').showModal());
    $('helpclose').addEventListener('click', () => $('helpdlg').close());
    $('helpguide').addEventListener('click', () => { $('helpdlg').close(); show('guide'); });
    $('theme').addEventListener('click', () => {
      const root = document.documentElement;
      const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
      root.dataset.theme = dark ? 'light' : 'dark';
      try { localStorage.setItem('sigmalens.theme', root.dataset.theme); } catch (e) { /* storage blocked */ }
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault(); show('search'); $('q').focus();
      }
    });

    // demo dataset (only present in builds made with --demo)
    const demo = window.SIGMALENS_DEMO;
    let demoLoaded = false;
    async function loadDemo() {
      if (!demo) { pick(); return; }
      if (demoLoaded) { flash('Demo dataset already loaded'); return; }
      demoLoaded = true;
      await addEventsText(demo.events, 'demo-events.jsonl');
      for (const r of demo.rules) addRulesText(r.text, r.name);
      updateStat(); renderRules();
    }
    if (demo) {
      $('demo').hidden = false;
      $('demo').addEventListener('click', async () => { await loadDemo(); show('search'); runSearch(); });
    }

    // guide: mapping table from the engine, "Try it" buttons, links between views
    $('maptable').innerHTML = `<table class="ref"><thead><tr><th>category</th><th>reads</th></tr></thead><tbody>${
      Object.entries(SL.CATEGORIES).map(([cat, pairs]) => `<tr><td><code>${esc(cat)}</code></td><td>${
        cat === 'process_creation' ? 'depends on <b>Mapping</b> (below)' : pairs.map(([ch, ids]) => `${esc(chanShort(ch))} ${esc(ids.join(', '))}`).join(' · ')
      }</td></tr>`).join('')}</tbody></table>`;
    $('servicelist').innerHTML = Object.entries(SL.CHANNELS).map(([s, ch]) => `<code>${esc(s)}</code> → ${esc(ch)}`).join(', ');
    if (!demo) $('g-demo-hint').innerHTML = 'Examples marked <span class="try-badge">Try it</span> run against the loaded data. They were written for the demo dataset (<code>dist/sigmalens-demo.html</code>), so with your own logs some may return nothing.';
    document.addEventListener('click', async (e) => {
      const go = e.target.closest('[data-goto]');
      if (go) {
        e.preventDefault();
        if (go.dataset.goto === 'demo') { await loadDemo(); flash('Demo dataset loaded'); }
        else show(go.dataset.goto);
        return;
      }
      const tq = e.target.closest('[data-try-q]');
      if (tq) {
        if (!state.recs.length) await loadDemo();
        if (!state.recs.length) return;
        $('q').value = tq.dataset.tryQ;
        $('from').value = ''; $('to').value = '';
        show('search'); runSearch();
        return;
      }
      const tr = e.target.closest('[data-try-rule]');
      if (tr) {
        const pre = tr.closest('p').previousElementSibling;
        $('editor').value = pre.textContent.replace(/[ \t]+#.*$/gm, '') + '\n';
        state.editing = null;
        if (!state.recs.length && demo) await loadDemo();
        show('sigma'); updateGutter(); runEditor();
      }
    });

    updateStat();
    renderRules();
    let v = 'search';
    try { v = localStorage.getItem('sigmalens.view') || 'search'; } catch (e) { /* storage blocked */ }
    show(v);
    if (v === 'sigma') runEditor();
  }

  init();
})();
