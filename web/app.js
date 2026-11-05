// app.js — routes, live state and the four screens of the AdaptBox monitor.
//   #/live            run a sample and watch it be scored and contained
//   #/runs, #/runs/id saved runs, and one run replayed with its policy
//   #/benchmark       every sample once: detection and false positives
//   #/how             how the loop works, following one system call

const $ = (sel, root = document) => root.querySelector(sel);
const view = $('#view');
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

// ------------------------------------------------------------------ formatting

const f2 = (v) => (v == null ? '—' : Number(v).toFixed(2));
const secs = (t) => (t == null ? '—' : `${Number(t).toFixed(2)} s`);
const mib = (bytes) => `${Math.max(0, Math.round((bytes || 0) / 1048576))}`;
const count = (n) => new Intl.NumberFormat('en').format(n);
const STAGE = ['None', 'Network cut', 'Writes blocked', 'CPU & memory capped', 'Killed'];
// the same names inside a sentence (CPU keeps its capitals)
const STAGE_IN = ['none', 'network cut', 'writes blocked', 'CPU and memory capped', 'killed'];
const stageKind = (s) => (s >= 4 ? 'kill' : 'warn');
const html = (strings, ...vals) => strings.reduce((out, s, i) => out + s + (i < vals.length ? vals[i] : ''), '');
const dash = '<span class="dash">—</span>';

// ------------------------------------------------------------------ plain English
// The score, the rules and the system calls are the engine's own terms. For a
// viewer who has not read the code, each is paired here with a plain phrase.

// What a system call is, in a few words. Keys are the names strace reports.
const SYSCALL_MEANING = {
  openat: 'open a file', open: 'open a file', read: 'read from a file', pread64: 'read from a file',
  write: 'write to a file', close: 'close a file', lseek: 'move within a file',
  connect: 'connect to the network', socket: 'create a network socket', sendto: 'send network data',
  recvfrom: 'receive network data', bind: 'claim a network port',
  execve: 'start a program', execveat: 'start a program',
  clone: 'create a process', clone3: 'create a process', fork: 'create a process', vfork: 'create a process',
  mmap: 'request memory', munmap: 'release memory', brk: 'grow memory', mprotect: 'change memory access',
  stat: 'look up a file', newfstatat: 'look up a file', fstat: 'look up a file', access: 'check a file',
  getdents64: 'list a folder', ioctl: 'control a device', futex: 'wait on a lock',
  rt_sigaction: 'set a signal handler', uname: 'read the system name', getrandom: 'read random bytes',
  unlink: 'delete a file', unlinkat: 'delete a file',
  setuid: 'change user id', setgid: 'change group id', setreuid: 'change user id',
  setresuid: 'change user id', capset: 'change capabilities',
  init_module: 'load a kernel module', finit_module: 'load a kernel module', delete_module: 'unload a kernel module',
  ptrace: 'attach to a process', mount: 'mount a filesystem', umount2: 'unmount a filesystem',
  chroot: 'change root directory', pivot_root: 'swap the root filesystem',
};

// A rule reason ("sensitive read: /etc/shadow") split into a plain headline and
// the technical detail under it. Matched by the prefix before the colon.
const REASON_PLAIN = {
  'sensitive read': { title: 'Read a secret file', why: 'password, key or credential file' },
  'exec of shell/netcat': { title: 'Started a shell', why: 'a shell is how an attacker runs commands' },
  'outbound connect': { title: 'Opened a network connection', why: 'could send data out or pull more in' },
  'connect burst': { title: 'Scanned many ports at once', why: 'looking for services to attack' },
  'fork burst': { title: 'Spawned processes in bulk', why: 'a fork bomb, to exhaust the machine' },
  'fast memory growth': { title: 'Grabbed memory fast', why: 'memory exhaustion, to crash the host' },
  'system write': { title: 'Wrote to a protected location', why: 'persistence or tampering with the system' },
  'privilege escalation': { title: 'Tried to become root', why: 'to gain full control of the machine' },
  'kernel module load': { title: 'Tried to load a kernel module', why: 'the deepest level of control' },
  'process injection': { title: 'Tried to attach to another process', why: 'to inject code or steal data' },
  'filesystem escape': { title: 'Tried to mount or change root', why: 'a container or sandbox escape' },
  'raw/packet socket opened': { title: 'Opened a raw network socket', why: 'packet sniffing or spoofing' },
  'mass file deletion': { title: 'Deleted files in bulk', why: 'a wiper or ransomware pattern' },
};
function plainReason(reason) {
  const m = reason.match(/^([^:]+):\s*(.*)$/);
  const key = m ? m[1].trim() : reason;
  const detail = m ? m[2].trim() : '';
  const p = REASON_PLAIN[key];
  if (p) return { title: p.title, detail, why: p.why };
  // a hard timeout or an unmapped rule: show it as written
  return { title: reason, detail: '', why: '' };
}

function ago(ts) {
  if (!ts) return '—';
  const s = Date.now() / 1000 - ts;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}
function exitText(code) {
  if (code == null) return '—';
  if (code < 0) return `signal ${-code}`;
  return String(code);
}
function mini(stage) {
  return `<span class="mini" aria-hidden="true">${[1, 2, 3, 4].map((i) =>
    `<i${i <= stage ? ` data-on="${stageKind(i)}"` : ''}></i>`).join('')}</span>`;
}

// ------------------------------------------------------------------ state

const S = {
  samples: [],
  open: new Set(),         // sample ids whose description is expanded
  selected: null,          // sample id highlighted in the list
  run: null,               // the live run: { id, sample, cls, windows, stages, output, sys, end, t0 }
  bench: null,             // { rows, summary, finished_at } from the engine
  benchLive: null,         // while a benchmark runs: { order, rows: Map }
};
let current = null;        // the mounted screen's live handlers

function newRun(ev) {
  return { id: ev.run_id, sample: ev.sample, cls: ev.class, windows: [], stages: [], output: [],
           sys: {}, end: null, t0: performance.now(), windowSeconds: ev.window_seconds || 0.5 };
}

Engine.on((ev) => {
  switch (ev.type) {
    case 'conn': setEngineDot(ev.state); break;
    case 'busy': current?.onBusy?.(ev.busy); break;
    case 'start':
      S.run = newRun(ev); S.selected = ev.sample;
      current?.onStart?.(S.run); break;
    case 'window':
      if (!S.run || S.run.id !== ev.run_id) return;
      S.run.windows.push(ev);
      for (const [k, v] of Object.entries(ev.syscalls || {})) S.run.sys[k] = (S.run.sys[k] || 0) + v;
      current?.onWindow?.(ev, S.run); break;
    case 'stage':
      if (!S.run || S.run.id !== ev.run_id) return;
      S.run.stages.push(ev); current?.onStage?.(ev, S.run); break;
    case 'output':
      if (!S.run || S.run.id !== ev.run_id) return;
      S.run.output.push(ev); current?.onOutput?.(ev, S.run); break;
    case 'end':
      if (!S.run || S.run.id !== ev.run_id) return;
      S.run.end = ev; current?.onEnd?.(ev, S.run);
      if (S.benchLive && S.benchLive.rows.has(S.run.sample)) {
        S.benchLive.rows.get(S.run.sample).state = 'done';
      }
      break;
    case 'bench_start':
      S.benchLive = { order: ev.samples, rows: new Map(ev.samples.map((id) => [id, { state: 'waiting' }])) };
      current?.onBench?.(); break;
    case 'bench_row': {
      const id = S.samples.find((s) => s.name === ev.row.sample)?.id;
      if (S.benchLive && id) S.benchLive.rows.set(id, { state: 'done', row: ev.row });
      current?.onBench?.(); break;
    }
    case 'bench_end':
      S.benchLive = null;
      Engine.benchmark().then((b) => { S.bench = b; current?.onBench?.(); });
      break;
    case 'error': toast(ev.message); break;
  }
});

function setEngineDot(state) {
  const dot = $('#engine-dot'), tip = $('#engine-tip');
  dot.dataset.state = state;
  const text = {
    live: `Engine live at ${Engine.address}${Engine.info?.host ? ' on ' + Engine.info.host : ''}`,
    lost: 'Engine connection lost, retrying',
    simulated: 'Engine not reachable: simulated recordings',
  }[state] || 'Connecting';
  tip.textContent = text;
  dot.setAttribute('aria-label', 'Engine: ' + text);
}

function toast(msg) {
  const n = document.createElement('div');
  n.setAttribute('role', 'alert');
  Object.assign(n.style, {
    position: 'fixed', right: '24px', bottom: '24px', background: 'var(--raised)', color: 'var(--text)',
    border: '1px solid var(--control)', borderRadius: '6px', padding: '10px 14px', boxShadow: 'var(--shadow)',
    fontSize: '13px', zIndex: 50, maxWidth: '420px',
  });
  n.textContent = msg;
  document.body.appendChild(n);
  n.animate([{ opacity: 0, transform: 'translateY(8px)' }, { opacity: 1, transform: 'none' }], { duration: 200, easing: 'cubic-bezier(.2,.8,.2,1)' });
  setTimeout(() => n.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 200 }).onfinish = () => n.remove(), 4200);
}

// ------------------------------------------------------------------ shared pieces

function simulatedNotice() {
  if (Engine.mode !== 'simulated') return '';
  return html`<div class="notice" role="note">
    <span>The engine is not reachable at <code>${Engine.address.replace(/^https?:\/\//, '')}</code>, so these are simulated recordings computed with AdaptBox's own scoring code. To run for real, start it on Kali with <code>sudo python3 -m adaptbox.server</code>.</span>
    <button class="btn small" type="button" data-action="retry">Retry</button>
  </div>`;
}

function finding(run, sampleName) {
  if (!run) {
    const b = S.samples.filter((s) => s.class === 'benign').length;
    return `Nothing running. ${S.samples.length} samples ready: ${b} benign, ${S.samples.length - b} malicious.`;
  }
  const name = `<b class="mono">${esc(sampleName || run.sample.split('/').pop())}</b>`;
  const peak = Math.max(0, ...run.windows.map((w) => w.score));
  const stages = run.stages;
  if (!run.end) {
    if (!stages.length) return `Running ${name} with the loose profile. Score ${f2(run.windows.at(-1)?.score ?? 0)}.`;
    const s = stages.at(-1);
    return `Running ${name}: stage ${s.stage}, ${STAGE_IN[s.stage]}, since ${secs(s.t)}.`;
  }
  const e = run.end;
  if (!stages.length) {
    if (e.exit_code < 0) return `${name} was stopped by a cgroup limit at ${secs(e.duration)} before its score reached a stage (peak ${f2(peak)}).`;
    return `${name} ran free: the score peaked at ${f2(peak)} and it exited ${e.exit_code} after ${secs(e.duration)}.`;
  }
  const first = stages[0], last = stages.at(-1);
  let out = `${name} was contained: ${STAGE_IN[first.stage]} at ${secs(first.t)}`;
  out += last.stage >= 4 ? `, killed at ${secs(last.t)}` : `, held at stage ${last.stage}`;
  out += `. Peak score ${f2(peak)}.`;
  if (e.exit_code === 0) out += ` It had already finished its work when the first window was scored, so what it did counts as damage before containment.`;
  else if (last.stage < 4 && e.exit_code < 0) out += ` A cgroup limit then stopped it.`;
  return out;
}

function scorePanel({ title = 'Risk score', aside = '', replay = false } = {}) {
  return html`<section class="panel" aria-labelledby="score-h">
    <div class="panel-head">
      <div><h2 id="score-h">${title}</h2>
        <p class="sub">How dangerous the code looks right now, from 0 (harmless) to 1 (certainly malicious). Risky actions add points; they fade when it behaves. Each dashed line is a stage.</p></div>
      <span class="aside mono" id="score-aside">${aside}</span>
    </div>
    <div id="chart"></div>
    ${replay ? `<div class="replay-bar">
      <button class="btn small" type="button" id="play" aria-label="Play the run from the start">Replay</button>
      <input type="range" id="scrub" min="0" max="1" step="0.01" value="1" aria-label="Moment in the run">
      <span class="t" id="scrub-t">—</span></div>` : ''}
    <div class="kpis" id="kpis">
      <div class="kpi answer"><div class="label">Score</div><div class="value" id="k-score">0.00</div></div>
      <div class="kpi"><div class="label">Stage</div><div class="value" id="k-stage">0<span class="stage-name">None</span></div></div>
      <div class="kpi"><div class="label">Elapsed</div><div class="value" id="k-time">—</div></div>
      <div class="kpi"><div class="label">Memory</div><div class="value" id="k-mem">—</div></div>
      <div class="kpi"><div class="label">Processes</div><div class="value" id="k-pids">—</div></div>
    </div>
  </section>`;
}

function sysPanel() {
  return html`<section class="panel sys" aria-labelledby="sys-h">
    <div class="panel-head"><div><h2 id="sys-h">System calls</h2><p class="sub">Every request the code makes to the operating system, counted. This is what AdaptBox watches.</p></div><span class="aside mono" id="sys-total"></span></div>
    <ul class="bars" id="sys"></ul>
  </section>`;
}

function feedPair() {
  return html`<div class="pair">
  <section class="panel flush" aria-labelledby="ev-h">
    <div class="panel-head"><div><h2 id="ev-h">Why the score moved</h2><p class="sub">Each risky action, in plain terms, with the points it added</p></div></div>
    <ul class="feed" id="feed" aria-live="polite"></ul>
  </section>
  <section class="panel flush" aria-labelledby="out-h">
    <div class="panel-head"><div><h2 id="out-h">Program output</h2><p class="sub">What the sandboxed script printed</p></div></div>
    <div class="log" id="log" role="log"></div>
  </section></div>`;
}

// Feeds rendered from a run up to time t (replay) or as events arrive (live).
function feedItems(run, upto = Infinity) {
  const items = [];
  for (const w of run.windows) {
    if (w.ts > upto) break;
    for (const h of w.hits || []) items.push({ t: w.ts, kind: 'hit', h });
  }
  for (const s of run.stages) if (s.t <= upto) items.push({ t: s.t + 0.0001, kind: 'stage', s });
  items.sort((a, b) => b.t - a.t);
  return items;
}

function feedRow(item) {
  if (item.kind === 'stage') {
    const s = item.s;
    return `<li class="stage" data-kind="${stageKind(s.stage)}"><span class="t">${secs(s.t)}</span>
      <span class="what"><span class="dot"></span>Stage ${s.stage}: ${STAGE[s.stage]}${s.ok === false ? ' (failed)' : ''}
      <span class="detail">${esc(s.detail || '')}</span></span><span class="w score" title="risk score now">${f2(s.score)}</span></li>`;
  }
  const h = item.h;
  const p = plainReason(h.reason);
  const sub = [p.detail && `<span class="path">${esc(p.detail)}</span>`, p.why && `<span class="why">${esc(p.why)}</span>`]
    .filter(Boolean).join('');
  return `<li><span class="t">${secs(item.t)}</span>
    <span class="what">${esc(p.title)}${sub ? `<span class="detail">${sub}</span>` : ''}</span>
    <span class="w" title="added to the risk score">+${h.weight.toFixed(2)}</span></li>`;
}

function renderFeed(run, upto) {
  const ul = $('#feed');
  if (!ul) return;
  const items = feedItems(run, upto);
  ul.innerHTML = items.length ? items.map(feedRow).join('')
    : `<li class="quiet"><span class="t"></span><span class="what">No rule has fired${run.windows.length ? ' yet' : ''}.</span><span></span></li>`;
}

function logRows(run, upto = Infinity) {
  const rows = run.output.filter((o) => o.t <= upto).map((o) => ({ t: o.t, line: o.line }));
  for (const s of run.stages) if (s.t <= upto) rows.push({ t: s.t, sep: s.stage, line: `stage ${s.stage}: ${STAGE_IN[s.stage]}` });
  if (run.end && run.end.duration <= upto + 1e-6) {
    rows.push({ t: run.end.duration, sep: 0, line: run.end.exit_code < 0 ? `process ended by signal ${-run.end.exit_code}` : `process exited with code ${run.end.exit_code}` });
  }
  rows.sort((a, b) => a.t - b.t || (a.sep ? -1 : 1));
  return rows;
}
function logRow(r, arrive = false) {
  const cls = [r.sep != null ? 'sep' : '', arrive ? 'arrive' : ''].filter(Boolean).join(' ');
  const kind = r.sep ? ` data-kind="${stageKind(r.sep)}"` : '';
  return `<div class="${cls}"${kind}><span class="t">${secs(r.t)}</span><span class="line">${r.sep != null ? '── ' : ''}${esc(r.line)}${r.sep != null ? ' ──' : ''}</span></div>`;
}
function renderLog(run, upto) {
  const el = $('#log');
  if (!el) return;
  const rows = logRows(run, upto);
  el.innerHTML = rows.length ? rows.map((r) => logRow(r)).join('') : `<div><span class="t"></span><span class="line muted">Nothing printed${run.end ? '' : ' yet'}.</span></div>`;
  el.scrollTop = el.scrollHeight;
}

// Before any run, the side panels hold reference data instead of empty frames:
// the calls strace is told to trace, the rules that can fire, and what the log shows.
const TRACED = [
  ['openat', 'files opened'], ['open', 'files opened (old form)'], ['connect', 'network connections'],
  ['socket', 'sockets created'], ['sendto', 'data sent'], ['execve', 'programs started'],
  ['clone', 'new processes'], ['clone3', 'new processes'], ['fork', 'new processes'],
  ['vfork', 'new processes'], ['mmap', 'memory mapped'], ['brk', 'heap grown'],
];
const RULES = [
  ['sensitive read', 'a protected path is opened', '+0.40 each'],
  ['shell spawn', 'execve of sh, bash, nc', '+0.45'],
  ['outbound connect', 'each connect, under 10', '+0.15 each'],
  ['connect burst', '10 or more in a window', '+0.35'],
  ['fork burst', '20 or more in a window', '+0.40'],
  ['memory growth', '256 MiB or more in a window', '+0.35'],
];
function renderIdle() {
  const ul = $('#sys');
  ul.classList.add('reference');
  $('#sys-total').textContent = `${TRACED.length} traced`;
  ul.innerHTML = TRACED.slice(0, 8).map(([n, note]) =>
    `<li><span class="n">${n}<span class="note">${note}</span></span><span class="v">${dash}</span></li>`).join('');
  $('#feed').innerHTML = `<li class="quiet"><span class="t"></span><span class="what">Nothing has run yet. These rules can fire:</span><span></span></li>` +
    RULES.map(([r, when, w]) => `<li class="quiet"><span class="t"></span><span class="what">${r} <span class="detail">${when}</span></span><span class="w">${w}</span></li>`).join('');
  $('#log').innerHTML = `<div><span class="t"></span><span class="line muted">The script's own output appears here as it runs, with each stage marked where it locked.</span></div>`;
}

function renderSys(sysTotals) {
  const ul = $('#sys');
  if (!ul) return;
  ul.classList.remove('reference');
  const entries = Object.entries(sysTotals).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((n, [, v]) => n + v, 0);
  $('#sys-total').textContent = total ? `${count(total)} calls` : '';
  if (!entries.length) { ul.innerHTML = `<li><span class="n muted">No calls traced yet.</span></li>`; return; }
  const max = entries[0][1];
  const top = entries.slice(0, 8);
  // keep existing rows so their bars can grow instead of jumping
  const existing = new Map([...ul.querySelectorAll('li[data-k]')].map((li) => [li.dataset.k, li]));
  ul.innerHTML = '';
  for (const [k, v] of top) {
    let li = existing.get(k);
    if (!li) {
      li = document.createElement('li');
      li.dataset.k = k;
      const meaning = SYSCALL_MEANING[k];
      li.innerHTML = `<span class="n">${esc(k)}${meaning ? `<span class="note">${esc(meaning)}</span>` : ''}</span><span class="v"></span><span class="track"><span class="fill" style="display:block;transform:scaleX(0)"></span></span>`;
    }
    li.querySelector('.v').textContent = count(v);
    ul.appendChild(li);
    const fill = li.querySelector('.fill');
    requestAnimationFrame(() => { fill.style.transform = `scaleX(${(v / max).toFixed(4)})`; });
  }
}

function setKpis({ score, stage, t, mem, pids }) {
  if (!$('#k-score')) return;          // the score panel is not on this screen
  if (score != null) $('#k-score').textContent = f2(score);
  if (stage != null) $('#k-stage').innerHTML = `${stage}<span class="stage-name">${STAGE[stage]}</span>`;
  if (t !== undefined) $('#k-time').innerHTML = t == null ? '—' : `${t.toFixed(2)}<small>s</small>`;
  if (mem !== undefined) $('#k-mem').innerHTML = mem == null ? '—' : `${mib(mem)}<small>MiB</small>`;
  if (pids !== undefined) $('#k-pids').textContent = pids == null ? '—' : String(pids);
}

// ------------------------------------------------------------------ Live

function renderLive() {
  const busy = Engine.busy;
  view.innerHTML = html`
    <div class="title-row">
      <div><h1>Live monitor</h1><p class="finding" id="finding">${finding(S.run, null)}</p></div>
      <div class="title-actions"><a class="btn" href="#/benchmark" data-action="bench-go">Run benchmark</a></div>
    </div>
    ${simulatedNotice()}
    <div class="grid live-grid">
      <div class="stack">
        <section class="panel samples" aria-labelledby="samples-h">
          <div class="panel-head"><div><h2 id="samples-h">Samples</h2><p class="sub">Scripts that stand in for AI-generated code</p></div></div>
          <div class="samples-list" id="samples">${samplesList(busy)}</div>
        </section>
        ${sysPanel()}
      </div>
      <div class="stack">${scorePanel({ aside: S.run ? S.run.id : '' })}${feedPair()}</div>
    </div>`;

  attachLive({ refreshSidebar: () => { $('#samples').innerHTML = samplesList(Engine.busy); } });
}

// The live score/feed/log view, shared by the Live and Test screens. The caller
// has already rendered scorePanel(), feedPair() and (optionally) sysPanel().
function attachLive({ refreshSidebar = () => {}, nameOf = null } = {}) {
  const chart = new ScoreChart($('#chart'), { thresholds: Engine.info.thresholds });
  chart.onCursor = (t, s, st) => setKpis({ score: s, stage: st });
  let clock = null;
  const say = (run) => { const el = $('#finding'); if (el) el.innerHTML = finding(run, nameOf ? nameOf(run) : null); };

  const paintRun = (run) => {
    const end = run.end ? { t: run.end.duration, killed: run.end.exit_code < 0 } : null;
    chart.load(run.windows, run.stages, { end });
    const last = run.windows.at(-1);
    setKpis({ score: last?.score ?? 0, stage: run.stages.at(-1)?.stage ?? 0,
              t: run.end ? run.end.duration : (performance.now() - run.t0) / 1000,
              mem: last?.features?.mem_current_bytes ?? null, pids: last?.features?.pids_current ?? null });
    renderSys(run.sys); renderFeed(run); renderLog(run);
    const aside = $('#score-aside'); if (aside) aside.textContent = run.id;
  };
  const tick = () => {
    if (!S.run || S.run.end) return;
    setKpis({ t: (performance.now() - S.run.t0) / 1000 });
    clock = setTimeout(tick, 100);
  };

  if (S.run) { paintRun(S.run); tick(); } else { chart.reset(); renderIdle(); }

  current = {
    onBusy: () => refreshSidebar(),
    onStart: (run) => {
      chart.reset(); paintRun(run); refreshSidebar(); say(run);
      clearTimeout(clock); tick();
    },
    onWindow: (w, run) => {
      chart.addWindow(w, run.windowSeconds);
      setKpis({ mem: w.features?.mem_current_bytes, pids: w.features?.pids_current });
      renderSys(run.sys);
      const ul = $('#feed');
      if (w.hits?.length && ul) {
        if (ul.querySelector('.quiet')) ul.innerHTML = '';
        setTimeout(() => {               // arrive just as the line reaches this window
          if (!$('#feed')) return;
          const rows = w.hits.map((h) => feedRow({ t: w.ts, kind: 'hit', h })).join('');
          ul.insertAdjacentHTML('afterbegin', rows);
          [...ul.children].slice(0, w.hits.length).forEach((li) => li.classList.add('arrive'));
        }, reduced ? 0 : 200);
      }
      say(run);
    },
    onStage: (s, run) => {
      chart.addStage(s);
      setTimeout(() => {
        const ul = $('#feed'), log = $('#log');
        if (ul) {
          if (ul.querySelector('.quiet')) ul.innerHTML = '';
          ul.insertAdjacentHTML('afterbegin', feedRow({ t: s.t, kind: 'stage', s }));
          ul.firstElementChild.classList.add('arrive');
        }
        if (log) {
          if (log.querySelector('.muted')) log.innerHTML = '';
          log.insertAdjacentHTML('beforeend', logRow({ t: s.t, sep: s.stage, line: `stage ${s.stage}: ${STAGE_IN[s.stage]}` }, true));
          log.scrollTop = log.scrollHeight;
        }
        say(run);
      }, reduced ? 0 : 340);
    },
    onOutput: (o) => {
      const log = $('#log'); if (!log) return;
      if (log.querySelector('.muted')) log.innerHTML = '';
      log.insertAdjacentHTML('beforeend', logRow(o, true));
      log.scrollTop = log.scrollHeight;
    },
    onEnd: (e, run) => {
      chart.setEnd({ t: e.duration, killed: e.exit_code < 0 });
      clearTimeout(clock);
      setKpis({ t: e.duration });
      setTimeout(() => {
        if (!$('#log')) return;
        $('#log').insertAdjacentHTML('beforeend', logRow(logRows(run).at(-1), true));
        $('#log').scrollTop = $('#log').scrollHeight;
      }, reduced ? 0 : 420);
      say(run); refreshSidebar();
    },
    unmount: () => clearTimeout(clock),
  };
  return chart;
}

// ------------------------------------------------------------------ Test your own code

const CODE_EXAMPLES = {
  harmless: {
    name: 'my_task.py',
    code: `# A harmless task: should run free, score stays near 0.\nimport math\n\ntotal = 0\nfor n in range(1, 100000):\n    total += math.sqrt(n)\n\nwith open("result.txt", "w") as f:\n    f.write(f"sum of roots = {total:.2f}\\n")\n\nprint("done:", round(total, 2))\n`,
  },
  risky: {
    name: 'grabber.py',
    code: `# Looks like a helper, but reads secrets and phones home.\n# AdaptBox should catch it and contain it.\nimport socket\n\nfor path in ("/etc/shadow", "/etc/passwd"):\n    try:\n        data = open(path, "rb").read()\n        print(f"read {path}: {len(data)} bytes")\n    except OSError as e:\n        print("denied:", e)\n\ns = socket.socket()\ns.settimeout(0.5)\ntry:\n    s.connect(("127.0.0.1", 4444))   # a reverse-shell style callback\nexcept OSError as e:\n    print("connect:", e)\n`,
  },
};

function renderTest() {
  const liveOnly = Engine.mode !== 'live';
  const draft = S.testDraft || { name: 'my_task.py', code: '' };
  view.innerHTML = html`
    <div class="title-row">
      <div><h1>Test your own code</h1>
        <p class="finding" id="finding">Paste a Python or shell script. AdaptBox runs it in the sandbox and decides for itself whether to let it run or contain it.</p></div>
    </div>
    ${simulatedNotice()}
    ${liveOnly ? `<div class="notice" role="note"><span>Running new code needs the live engine. Start it on Kali with <code>sudo python3 -m adaptbox.server</code>, then reload. You can still browse the samples and saved runs.</span></div>` : ''}
    <section class="panel editor" aria-labelledby="editor-h" style="margin-bottom:var(--gap)">
      <div class="panel-head"><div><h2 id="editor-h">Your script</h2><p class="sub">AdaptBox runs it as an unprivileged user, in a throwaway folder in /tmp, with the same limits as the samples — then decides what to do</p></div></div>
      <div class="panel-body">
        <div class="editor-bar">
          <input id="fname" class="field" type="text" value="${esc(draft.name)}" spellcheck="false" aria-label="File name"
                 pattern="[A-Za-z0-9_][A-Za-z0-9_.-]*\\.(py|sh)" maxlength="64">
          <span class="lang" id="lang"></span>
          <span class="spacer"></span>
          <button class="btn small text" type="button" data-example="harmless">Load harmless example</button>
          <button class="btn small text" type="button" data-example="risky">Load risky example</button>
        </div>
        <textarea id="code" class="code-input" spellcheck="false" autocomplete="off" autocapitalize="off"
                  placeholder="# paste a .py or .sh script here, or load an example above" aria-label="Script to test">${esc(draft.code)}</textarea>
        <div class="editor-actions">
          <button class="btn primary" type="button" id="test-run"${liveOnly ? ' disabled aria-disabled="true"' : ''}>Test it</button>
          <span class="hint" id="test-hint">Python or shell, up to 200 KB. Ctrl+Enter to run.</span>
        </div>
      </div>
    </section>
    <div class="grid live-grid">
      <div class="stack">
        <section class="panel" aria-labelledby="safe-h">
          <div class="panel-head"><h2 id="safe-h">How your code is kept safe</h2></div>
          <div class="panel-body">${safetyList()}</div>
        </section>
        ${sysPanel()}
      </div>
      <div class="stack">${scorePanel({ aside: S.run ? S.run.id : '' })}${feedPair()}</div>
    </div>`;

  const updateLang = () => {
    const name = $('#fname').value.trim();
    const ext = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
    $('#lang').textContent = ext === 'sh' ? 'shell' : ext === 'py' ? 'Python' : '';
  };
  updateLang();
  $('#fname').addEventListener('input', updateLang);
  $('#code').addEventListener('input', () => { S.testDraft = { name: $('#fname').value, code: $('#code').value }; });

  attachLive({ nameOf: (run) => run.sample.split('/').pop() });
  // keep the Test button in step with the engine being busy
  const prevBusy = current.onBusy;
  current.onBusy = () => { prevBusy?.(); syncTestButton(); };

  view.querySelectorAll('[data-example]').forEach((b) => b.addEventListener('click', () => {
    const ex = CODE_EXAMPLES[b.dataset.example];
    $('#fname').value = ex.name; $('#code').value = ex.code;
    S.testDraft = { name: ex.name, code: ex.code };
    updateLang();
  }));

  $('#test-run').addEventListener('click', submitCode);
  $('#code').addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); submitCode(); }
  });
  syncTestButton();
}

function safetyList() {
  const row = (title, body) => `<div class="safe-row"><div class="safe-t">${title}</div><div class="safe-b">${body}</div></div>`;
  return row('Unprivileged user', 'Runs as <span class="mono">nobody</span>, not root, and can never regain privileges — so it cannot touch your files even before a stage fires.')
    + row('Throwaway folder', 'Its only writable place is a temporary folder in <span class="mono">/tmp</span>, deleted when the run ends.')
    + row('Same limits as the samples', 'Its own cgroup caps CPU, memory (no swap) and processes, with a 30-second timeout.')
    + row('Caught for trying', 'AdaptBox scores the attempt, so reading a secret counts against it even when the read is denied.');
}

function syncTestButton() {
  const b = $('#test-run'); if (!b) return;
  const busy = !!Engine.busy || Engine.mode !== 'live';
  b.disabled = busy; b.toggleAttribute('aria-disabled', busy);
  b.textContent = Engine.busy ? 'Running…' : 'Test it';
}

async function submitCode() {
  const name = $('#fname').value.trim();
  const code = $('#code').value;
  const hint = $('#test-hint');
  if (!code.trim()) { hint.textContent = 'Nothing to test yet — paste a script or load an example.'; hint.classList.add('bad'); return; }
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*\.(py|sh)$/.test(name)) {
    hint.textContent = 'File name must end in .py or .sh.'; hint.classList.add('bad'); return;
  }
  hint.classList.remove('bad'); hint.textContent = 'Python or shell, up to 200 KB.';
  $('#test-run').disabled = true;
  try {
    await Engine.startCode(name, code);
  } catch (e) {
    toast(e.message);
    syncTestButton();
  }
}

function samplesList(busy) {
  const group = (cls, label) => {
    const list = S.samples.filter((s) => s.class === cls);
    return `<div class="sgroup"><div class="group-label"><span>${label}</span><span class="mono">${list.length}</span></div>` +
      list.map((s) => {
        const running = busy === 'run:' + s.id || (S.run && S.run.sample === s.id && !S.run.end);
        const sel = S.selected === s.id ? ' data-selected' : '';
        const state = running ? '<span class="state">running</span>'
          : `<button class="btn small" type="button" data-run="${esc(s.id)}"${busy ? ' disabled' : ''} aria-label="Run ${esc(s.name)}">Run</button>`;
        const kind = s.kind.charAt(0).toUpperCase() + s.kind.slice(1);
        const open = S.open.has(s.id);
        const did = 'sd-' + s.id.replace(/[^a-z0-9]/gi, '-');
        const detail = s.why ? `<div class="sample-detail" id="${did}"><div><dl>
            <dt>Why it's here</dt><dd>${esc(s.why)}</dd>
            <dt>What it does</dt><dd>${esc(s.does)}</dd>
            <dt>What should happen</dt><dd>${esc(s.expect)}</dd></dl></div></div>` : '';
        return `<div class="sample"${sel}${open ? ' data-open' : ''}>
          <button class="sample-head" type="button" data-toggle="${esc(s.id)}" aria-expanded="${open}" aria-controls="${did}">
            <span class="sample-text"><span class="name">${esc(s.name)}</span><span class="kind">${esc(kind)}</span></span>
            <svg class="chev" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M4 6l4 4 4-4"/></svg>
          </button>${state}${detail}</div>`;
      }).join('') + '</div>';
  };
  return group('benign', 'Benign: should run free') + group('malicious', 'Malicious: should be contained');
}

// ------------------------------------------------------------------ Runs

async function renderRuns() {
  view.innerHTML = html`<div class="title-row"><div><h1>Runs</h1><p class="finding" id="finding">Loading saved runs…</p></div></div>
    ${simulatedNotice()}
    <section class="panel"><div class="table-scroll" id="runs-table">${skeletonTable(6)}</div></section>`;
  let rows;
  try { rows = await Engine.runs(); }
  catch (e) { $('#runs-table').innerHTML = `<div class="empty-row" style="margin:20px">Couldn't load runs: ${esc(e.message)}. <button class="btn text" data-action="reload">Retry</button></div>`; return; }
  const contained = rows.filter((r) => r.max_stage > 0).length;
  $('#finding').innerHTML = rows.length
    ? `<b>${rows.length}</b> saved run${rows.length === 1 ? '' : 's'}: ${contained} contained, ${rows.length - contained} ran free.`
    : 'No saved runs yet.';
  if (!rows.length) {
    $('#runs-table').innerHTML = `<div class="empty-row" style="margin:20px">No runs yet. Start one from the <a href="#/live">live monitor</a>.</div>`;
    return;
  }
  $('#runs-table').innerHTML = html`<table class="data">
    <thead><tr><th>Run</th><th>Sample</th><th>Class</th><th class="num">Peak score</th><th>Stage reached</th>
      <th class="num">First stage</th><th class="num">Duration</th><th class="num">Exit</th><th class="num">Started</th></tr></thead>
    <tbody>${rows.map((r) => html`<tr data-href="#/runs/${r.run_id}">
      <td class="id">${r.run_id}</td>
      <td><a class="mono" href="#/runs/${r.run_id}" style="text-decoration:none">${esc(r.sample)}</a></td>
      <td><span class="pill neutral">${r.class}</span></td>
      <td class="num">${f2(r.max_score)}</td>
      <td>${mini(r.max_stage)}<span class="soft">${r.max_stage ? STAGE[r.max_stage] : 'Ran free'}</span></td>
      <td class="num">${r.first_stage_t == null ? dash : secs(r.first_stage_t)}</td>
      <td class="num">${secs(r.duration)}</td>
      <td class="num">${exitText(r.exit_code)}</td>
      <td class="num soft">${ago(r.started_at)}</td></tr>`).join('')}</tbody></table>`;
}

function skeletonTable(n) {
  return `<div style="padding:16px 20px">${Array.from({ length: n }, () =>
    '<div style="height:13px;margin:15px 0;background:var(--raised);border-radius:3px;width:100%"></div>').join('')}</div>`;
}

// ------------------------------------------------------------------ One run (replay)

async function renderRun(id) {
  view.innerHTML = html`<div class="title-row"><div><p class="crumb"><a href="#/runs">Runs</a> / <span class="mono">${esc(id)}</span></p>
    <h1 id="run-h">Loading…</h1><p class="finding" id="finding"></p></div></div>${simulatedNotice()}`;
  let data;
  try { data = await Engine.run(id); }
  catch (e) { $('#run-h').textContent = 'Run not found'; $('#finding').textContent = e.message; return; }
  const r = data.result;
  const run = {
    id: r.run_id, sample: data.summary.sample, cls: data.summary.class,
    windows: r.timeline.map((w) => ({ ...w })), stages: r.stage_log || [], output: data.output || [],
    end: { duration: r.duration, exit_code: r.exit_code }, sys: {},
  };
  for (const w of run.windows) for (const [k, v] of Object.entries(w.syscalls || {})) run.sys[k] = (run.sys[k] || 0) + v;

  $('#run-h').innerHTML = `<span class="mono">${esc(run.sample)}</span>`;
  $('#finding').innerHTML = finding(run, run.sample);
  view.insertAdjacentHTML('beforeend', html`
    <div class="grid live-grid">
      <div class="stack">
        <section class="panel" aria-labelledby="facts-h">
          <div class="panel-head"><h2 id="facts-h">This run</h2></div>
          <div class="panel-body">${facts(run, r, data.summary)}</div>
        </section>
        ${sysPanel()}
      </div>
      <div class="stack">${scorePanel({ aside: run.id, replay: true })}${feedPair()}</div>
    </div>
    ${data.code ? html`<h2 class="section-title">Submitted code</h2>
      <section class="panel submitted" aria-labelledby="sub-h">
        <div class="panel-head"><div><h2 id="sub-h" class="mono">${esc(run.sample)}</h2>
          <p class="sub">The script that was tested, exactly as submitted</p></div></div>
        <div class="panel-body"><pre class="code">${esc(data.code)}</pre></div>
      </section>` : ''}
    <h2 class="section-title">Least-privilege policy</h2>
    <section class="panel" aria-labelledby="pol-h">${policyPanel(data.policy, run)}</section>`);

  const chart = new ScoreChart($('#chart'), { thresholds: r.thresholds || Engine.info.thresholds });
  const lastT = r.duration;
  const scrub = $('#scrub'), tOut = $('#scrub-t');
  scrub.max = lastT.toFixed(2);
  let shown = { feed: -1, log: -1 };
  const at = (t) => {
    const win = [...run.windows].reverse().find((w) => w.ts <= t + 1e-6);
    setKpis({ t, mem: win?.features?.mem_current_bytes ?? null, pids: win?.features?.pids_current ?? null });
    tOut.textContent = `${t.toFixed(2)} of ${lastT.toFixed(2)} s`;
    const nf = feedItems(run, t).length, nl = logRows(run, t).length;
    if (nf !== shown.feed) { renderFeed(run, t); shown.feed = nf; }
    if (nl !== shown.log) { renderLog(run, t); shown.log = nl; }
    const sys = {};
    for (const w of run.windows) { if (w.ts > t + 1e-6) break; for (const [k, v] of Object.entries(w.syscalls || {})) sys[k] = (sys[k] || 0) + v; }
    renderSys(sys);
  };
  chart.onCursor = (t, s, st) => { setKpis({ score: s, stage: st }); at(t); scrub.value = t.toFixed(2); };
  chart.load(run.windows, run.stages, { end: { t: lastT, killed: r.exit_code < 0 } });

  let raf = null;
  const stop = () => { cancelAnimationFrame(raf); raf = null; $('#play').textContent = 'Replay'; };
  $('#play').addEventListener('click', () => {
    if (raf) return stop();
    const from = Number(scrub.value) >= lastT - 0.01 ? 0 : Number(scrub.value);
    const t0 = performance.now() - from * 1000;
    $('#play').textContent = 'Pause';
    const frame = (now) => {
      const t = Math.min(lastT, (now - t0) / 1000);
      chart.setCursor(t);
      if (t < lastT) raf = requestAnimationFrame(frame); else stop();
    };
    raf = requestAnimationFrame(frame);
  });
  scrub.addEventListener('input', () => { stop(); chart.setCursor(Number(scrub.value)); });
  current = { unmount: stop };

  $('#copy-policy')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(data.policy, null, 2)); $('#copy-policy').textContent = 'Copied'; }
    catch { $('#copy-policy').textContent = 'Copy failed'; }
    setTimeout(() => { const b = $('#copy-policy'); if (b) b.textContent = 'Copy JSON'; }, 1600);
  });
}

function facts(run, r, summary) {
  const row = (k, v) => `<div style="display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-top:1px solid var(--rule)"><span class="muted">${k}</span><span>${v}</span></div>`;
  const stages = run.stages.map((s) => row(`Stage ${s.stage}`, `<span class="mono">${secs(s.t)}</span>`)).join('');
  return [
    row('Class', `<span class="pill neutral">${run.cls}</span>`),
    row('Started', ago(summary.started_at)),
    row('Duration', `<span class="mono">${secs(r.duration)}</span>`),
    row('Exit', `<span class="mono">${exitText(r.exit_code)}</span>`),
    row('Peak score', `<span class="mono">${f2(r.max_score)}</span>`),
    row('Scored every', `<span class="mono">${secs(r.window_seconds)}</span>`),
    stages || row('Stages', 'none: ran free'),
  ].join('').replace('border-top:1px solid var(--rule)', 'border-top:0');
}

function policyPanel(policy, run) {
  if (!policy) return `<div class="panel-body" style="padding-top:18px"><div class="empty-row" style="margin:0">No policy was written for this run.</div></div>`;
  const allowed = policy.syscalls?.[0]?.names || [];
  const seen = new Set(Object.keys(run.sys));
  const own = allowed.filter((n) => seen.has(n));
  const base = allowed.filter((n) => !seen.has(n));
  const json = JSON.stringify(policy, null, 2);
  return html`
    <div class="panel-head"><div><h2 id="pol-h">seccomp allow-list for this kind of code</h2>
      <p class="sub">${allowed.length} system calls allowed: the ${own.length} this run made, plus ${base.length} every Python program needs to start and exit. Any other call fails with EPERM.</p></div>
      <button class="btn small" type="button" id="copy-policy">Copy JSON</button></div>
    <div class="panel-body" style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:24px">
      <div>
        <p class="muted" style="margin:0 0 8px;font-size:12px">Made by this run</p>
        <div class="chips">${own.map((n) => `<span class="chip seen">${esc(n)}</span>`).join('') || dash}</div>
        <p class="muted" style="margin:16px 0 8px;font-size:12px">Needed by every Python start</p>
        <div class="chips">${base.map((n) => `<span class="chip">${esc(n)}</span>`).join('')}</div>
      </div>
      <pre class="code" aria-label="seccomp.json">${esc(json)}</pre>
    </div>`;
}

// ------------------------------------------------------------------ Benchmark

async function renderBenchmark() {
  view.innerHTML = html`<div class="title-row">
      <div><h1>Benchmark</h1><p class="finding" id="finding">Loading…</p></div>
      <div class="title-actions"><button class="btn primary" type="button" id="bench-run">Run benchmark</button></div>
    </div>
    ${simulatedNotice()}
    <div id="bench-body"></div>`;
  try { S.bench = await Engine.benchmark(); } catch (e) { S.bench = null; }
  const paint = () => {
    const b = $('#bench-body'); if (!b) return;
    $('#bench-run').disabled = !!Engine.busy;
    $('#bench-run').textContent = S.benchLive ? 'Running…' : 'Run benchmark';
    const rows = benchRows();
    const done = rows.filter((r) => r.row);
    const mal = done.filter((r) => r.row.label === 'malicious');
    const ben = done.filter((r) => r.row.label === 'benign');
    const caught = mal.filter((r) => r.row.detected).length;
    const fp = ben.filter((r) => r.row.detected).length;
    const killed = mal.filter((r) => r.row.max_stage >= 4).length;
    const times = mal.map((r) => r.row.time_to_containment_s).filter((v) => v != null).sort((a, b) => a - b);
    const median = times.length ? (times.length % 2 ? times[(times.length - 1) / 2] : (times[times.length / 2 - 1] + times[times.length / 2]) / 2) : null;

    if (!rows.length) {
      $('#finding').textContent = 'No benchmark yet.';
      b.innerHTML = `<section class="panel"><div class="panel-body" style="padding-top:20px"><div class="empty-row" style="margin:0">Run the benchmark to put every sample through AdaptBox once and measure detection and false positives.</div></div></section>`;
      return;
    }
    const when = S.benchLive ? `running now, ${done.length} of ${rows.length} done`
      : Engine.mode === 'simulated' ? 'simulated recording' : `finished ${ago(S.bench?.finished_at)}`;
    $('#finding').innerHTML = `<b>${caught} of ${mal.length}</b> malicious samples were contained and <b>${fp} of ${ben.length}</b> benign samples were restricted (${when}).`;
    b.innerHTML = html`
      <section class="panel" style="margin-bottom:var(--gap)">
        <div class="kpis" style="border-top:0">
          <div class="kpi answer"><div class="label">Malicious contained</div><div class="value">${caught}<small>/ ${mal.length}</small></div></div>
          <div class="kpi"><div class="label">Benign restricted (false positives)</div><div class="value">${fp}<small>/ ${ben.length}</small></div></div>
          <div class="kpi"><div class="label">Median time to first stage</div><div class="value">${median == null ? '—' : median.toFixed(2)}<small>s</small></div></div>
          <div class="kpi"><div class="label">Killed (stage 4)</div><div class="value">${killed}<small>/ ${mal.length}</small></div></div>
        </div>
      </section>
      <section class="panel"><div class="table-scroll"><table class="data">
        <thead><tr><th>Sample</th><th>Class</th><th>Expected</th><th class="num">Peak score</th><th>Stage reached</th>
          <th class="num">First stage</th><th class="num">Duration</th><th class="num">Exit</th><th>Run</th></tr></thead>
        <tbody>${rows.map((r) => benchRowHtml(r, arrived(r))).join('')}</tbody></table></div></section>
      <h2 class="section-title">Against existing sandboxes</h2>
      ${comparisonPanel()}`;
  };
  current = {
    onBench: paint, onBusy: paint,
    onWindow: (w, run) => {      // live score on the row that is running
      const cell = document.querySelector(`[data-live="${CSS.escape(run.sample)}"]`);
      if (cell) cell.textContent = f2(w.score);
    },
  };
  $('#bench-run').addEventListener('click', async () => {
    try { await Engine.startBenchmark(); } catch (e) { toast(e.message); }
  });
  paint();
}

function benchRows() {
  if (S.benchLive) {
    return S.benchLive.order.map((id) => {
      const s = S.samples.find((x) => x.id === id) || { id, name: id.split('/').pop(), class: id.split('/')[0] };
      const st = S.benchLive.rows.get(id);
      const running = st.state !== 'done' && S.run && S.run.sample === id && !S.run.end;
      return { s, row: st.row, state: running ? 'running' : st.state };
    });
  }
  if (!S.bench) return [];
  return S.bench.rows.map((row) => ({ s: S.samples.find((x) => x.name === row.sample) || { name: row.sample, class: row.label }, row, state: 'done' }));
}

// A result row fades in once, when it first arrives during a live benchmark;
// a static table and repaints draw rows as they are.
const benchSeen = new Set();
function arrived({ row }) {
  if (!row) return false;
  const key = row.run_id || row.sample;
  if (benchSeen.has(key)) return false;
  benchSeen.add(key);
  return !!S.benchLive;
}

function benchRowHtml({ s, row, state }, arrive = false) {
  const expect = s.class === 'benign' ? 'Run free' : 'Contained';
  if (!row) {
    return html`<tr><td class="mono">${esc(s.name)}</td><td><span class="pill neutral">${s.class}</span></td><td class="soft">${expect}</td>
      <td class="num" data-live="${esc(s.id)}">${state === 'running' ? '0.00' : dash}</td>
      <td class="soft">${state === 'running' ? 'running…' : 'waiting'}</td><td class="num">${dash}</td><td class="num">${dash}</td><td class="num">${dash}</td><td></td></tr>`;
  }
  const ok = (s.class === 'benign') === !row.detected;
  return html`<tr${arrive ? ' class="arrive"' : ''}>
    <td class="mono">${esc(row.sample)}</td><td><span class="pill neutral">${row.label}</span></td>
    <td>${ok ? `<span class="soft">${expect}</span>` : `<span class="pill neg">${row.label === 'benign' ? 'False positive' : 'Missed'}</span>`}</td>
    <td class="num">${f2(row.max_score)}</td>
    <td>${mini(row.max_stage)}<span class="soft">${row.max_stage ? STAGE[row.max_stage] : 'Ran free'}</span></td>
    <td class="num">${row.time_to_containment_s == null ? dash : secs(row.time_to_containment_s)}</td>
    <td class="num">${secs(row.duration_s)}</td><td class="num">${exitText(row.exit_code)}</td>
    <td>${row.run_id ? `<a class="mono soft" href="#/runs/${row.run_id}" style="text-decoration:none">${row.run_id}</a>` : ''}</td></tr>`;
}

// From the literature survey in the Review 1 report (section 5.1).
const COMPARISON = {
  cols: ['Live monitoring', 'Automatic containment', 'Graduated response', 'ML risk scoring', 'Auto least-privilege policy', 'No VM or kernel patch'],
  rows: [
    ['Docker default', 'No', 'No', 'No', 'No', 'No', 'Yes'],
    ['Static seccomp, AppArmor', 'No', 'No', 'No', 'No', 'Partial', 'Yes'],
    ['gVisor', 'No', 'No', 'No', 'No', 'No', 'Partial'],
    ['Firecracker', 'No', 'No', 'No', 'No', 'No', 'No'],
    ['Falco', 'Yes', 'Alerts only', 'No', 'No', 'No', 'Yes'],
    ['Tetragon', 'Yes', 'Rules only', 'No', 'No', 'No', 'Yes'],
    ['pH (2000)', 'Yes', 'Delays only', 'Yes', 'Yes', 'No', 'No'],
    ['Confine (2020)', 'No', 'No', 'No', 'No', 'Yes', 'Yes'],
    ['AdaptBox', 'Yes', 'Yes', 'Yes', 'Yes', 'Yes', 'Yes'],
  ],
};
function comparisonPanel() {
  const cell = (v) => `<td class="${v === 'Yes' ? 'yes' : 'no'}">${v}</td>`;
  return html`<section class="panel">
    <div class="panel-head"><div><h2>Capabilities</h2><p class="sub">From the literature survey in the Review 1 report. A measured comparison against Docker's default profile and a static seccomp profile is the next step.</p></div></div>
    <div class="table-scroll"><table class="data"><thead><tr><th>System</th>${COMPARISON.cols.map((c) => `<th>${c}</th>`).join('')}</tr></thead>
    <tbody>${COMPARISON.rows.map(([name, ...v]) => `<tr${name === 'AdaptBox' ? ' style="background:rgba(74,138,214,.06)"' : ''}><td${name === 'AdaptBox' ? ' style="font-weight:600"' : ''}>${name}</td>${v.map(cell).join('')}</tr>`).join('')}</tbody></table></div>
  </section>`;
}

// ------------------------------------------------------------------ How it works

const STEPS = [
  { tab: 'Launch', node: 'proc', path: null, at: [212, 92], title: 'The script starts inside the sandbox',
    text: 'The launcher first joins its own cgroup, so everything it starts inherits the loose limits: full CPU, 1 GiB of memory and no swap, 256 processes. Then it starts the script in new PID, mount, UTS and IPC namespaces, traced by strace.',
    code: '# in the child, before anything runs\necho 0 > /sys/fs/cgroup/adaptbox/f05c8a3d/cgroup.procs\n\nunshare --fork --mount-proc --pid --mount --uts --ipc \\\n  strace -f -ttt -o /dev/shm/adaptbox-f05c8a3d.strace.log \\\n  python3 samples/malicious/slow_escalation.py' },
  { tab: 'System call', node: 'proc', path: 'e1', title: 'It asks the kernel to open /etc/shadow',
    text: "Python's open() becomes the openat system call. strace writes one line for every call the process tree makes; 3 is the script's PID inside its own PID namespace.",
    code: '3  1793090588.751204 openat(AT_FDCWD, "/etc/shadow", O_RDONLY|O_CLOEXEC) = 3' },
  { tab: 'Parse', node: 'mon', path: null, at: [474, 92], title: 'The monitor turns the line into an event',
    text: 'Twice a second the monitor reads the lines strace has added, decodes each call and its argument, and checks paths against the sensitive list: /etc/shadow, SSH keys, cloud credentials, .env files.',
    code: 'SyscallEvent(name="openat", arg="/etc/shadow")\n  -> matches /etc/shadow  -> sensitive read' },
  { tab: 'Score', node: 'score', path: 'e2', title: 'The rules score the window',
    text: 'Each rule that fires adds its weight. The running score keeps 0.6 of the previous window, so a single odd call fades away while sustained bad behaviour climbs.',
    code: 'sensitive read: /etc/shadow        +0.40\n\nscore = 0.6 × 0.00 + 0.40 = 0.40' },
  { tab: 'Stage 1 locks', node: 'resp', path: 'e3', title: 'The score crosses 0.35, so stage 1 locks',
    text: "The controller applies the stage to the live process: an nftables rule drops every packet from the run's cgroup. Stages only tighten. Three more thresholds block writes, cap CPU and memory, then kill.",
    code: 'table inet adaptbox_f05c8a3d {\n  chain out {\n    type filter hook output priority 0;\n    socket cgroupv2 level 2 "adaptbox/f05c8a3d" drop\n  }\n}' },
  { tab: 'Confined', node: 'proc', path: 'loop', title: 'The process carries on, confined',
    text: 'Its next connect attempts get no reply. If it keeps going, the score keeps rising and the next rungs lock: in the staged sample the write after stage 2 fails with "Read-only file system", and stage 4 kills it.',
    code: 'phase 2: 4 loopback connects -> dropped, no reply, …\nphase 3: write marker file -> Read-only file system\n── stage 4: killed ──' },
  { tab: 'Policy', node: 'policy', path: null, title: 'After the run: a least-privilege policy',
    text: 'Every system call the run made, plus what Python needs to start, becomes a seccomp allow-list. Anything else fails with EPERM, so the next script of this kind can start already confined, with no rules written by hand.',
    code: '{\n  "defaultAction": "SCMP_ACT_ERRNO",\n  "syscalls": [{\n    "names": ["openat", "connect", "clone", "execve", "read", …],\n    "action": "SCMP_ACT_ALLOW"\n  }]\n}' },
];

function renderHow() {
  view.innerHTML = html`
    <div class="title-row"><div><h1>How it works</h1>
      <p class="finding">AdaptBox closes the loop between what code does and how tightly it is confined, on a stock Linux kernel. Follow one system call through it.</p></div></div>
    <section class="panel pipeline" style="margin-bottom:var(--gap)" aria-labelledby="pipe-h">
      <div class="panel-head"><div><h2 id="pipe-h">Run, monitor, score, respond</h2><p class="sub">The loop runs twice a second for as long as the script does</p></div></div>
      <div class="panel-body">${pipelineSvg()}</div>
      <div class="panel-body">
        <ol class="steps" id="steps">${STEPS.map((s, i) => `<li><button type="button" data-step="${i}">${s.tab}</button></li>`).join('')}</ol>
        <div class="step-body" id="step-body"></div>
        <div class="step-nav">
          <button class="btn small" type="button" id="step-prev">Back</button>
          <button class="btn small primary" type="button" id="step-next">Next</button>
        </div>
      </div>
    </section>
    <div class="grid how-grid">
      <section class="panel" aria-labelledby="rules-h">
        <div class="panel-head"><div><h2 id="rules-h">What raises the score</h2><p class="sub">Rules from rules.py, each tied to an OS-level threat. None fires on ordinary code.</p></div></div>
        <div class="table-scroll"><table class="data"><thead><tr><th>Threat</th><th>Fires when</th><th class="num">Weight</th></tr></thead><tbody>
          <tr><td>Secret read</td><td class="soft">opens a password, key or credential file</td><td class="num">+0.40 each</td></tr>
          <tr><td>System write</td><td class="soft">writes to /etc, a binary dir, cron, or a login file</td><td class="num">+0.45 each</td></tr>
          <tr><td>Privilege escalation</td><td class="soft">calls setuid to root</td><td class="num">+0.50 each</td></tr>
          <tr><td>Kernel tampering</td><td class="soft">loads or unloads a kernel module</td><td class="num">+0.60 each</td></tr>
          <tr><td>Filesystem escape</td><td class="soft">mount, chroot or pivot_root</td><td class="num">+0.50 each</td></tr>
          <tr><td>Process injection</td><td class="soft">ptrace onto another process</td><td class="num">+0.40 each</td></tr>
          <tr><td>Shell spawn</td><td class="soft">starts sh, bash, nc or ncat</td><td class="num">+0.45 each</td></tr>
          <tr><td>Raw socket</td><td class="soft">opens a raw or packet socket</td><td class="num">+0.40</td></tr>
          <tr><td>Outbound connect</td><td class="soft">each connection, under 10 per window</td><td class="num">+0.15 each</td></tr>
          <tr><td>Port scan</td><td class="soft">10 or more connections in a window</td><td class="num">+0.35</td></tr>
          <tr><td>Fork bomb</td><td class="soft">20 or more new processes in a window</td><td class="num">+0.40</td></tr>
          <tr><td>Memory exhaustion</td><td class="soft">256 MiB or more growth in a window</td><td class="num">+0.35</td></tr>
          <tr><td>Mass deletion</td><td class="soft">25 or more files deleted in a window</td><td class="num">+0.35</td></tr>
          <tr><td>Isolation Forest</td><td class="soft">behaviour unlike the benign runs it learned</td><td class="num">+0.5 × anomaly</td></tr>
        </tbody></table></div>
      </section>
      <section class="panel" aria-labelledby="stages-h">
        <div class="panel-head"><div><h2 id="stages-h">What each stage does in the kernel</h2><p class="sub">Applied to the live process; none needs a kernel patch</p></div></div>
        <div class="table-scroll"><table class="data wrap-last"><thead><tr><th>Stage</th><th class="num">Score</th><th>Mechanism</th></tr></thead><tbody>
          <tr><td>${mini(0)}Open</td><td class="num">below 0.35</td><td class="soft">the loose profile: network, writes, 100% CPU, 1 GiB, 256 processes</td></tr>
          <tr><td>${mini(1)}Network cut</td><td class="num">0.35</td><td class="soft">nftables drop rule matching the run's cgroup</td></tr>
          <tr><td>${mini(2)}Writes blocked</td><td class="num">0.55</td><td class="soft">filesystem remounted read-only in its mount namespace</td></tr>
          <tr><td>${mini(3)}CPU &amp; memory capped</td><td class="num">0.75</td><td class="soft">cgroup v2: cpu.max 10%, memory.max 128 MiB, pids.max 16</td></tr>
          <tr><td>${mini(4)}Killed</td><td class="num">0.90</td><td class="soft">cgroup.kill ends every process in the group</td></tr>
          <tr><td>After the run</td><td class="num">${dash}</td><td class="soft">seccomp allow-list of the calls it made, for the next script of its kind</td></tr>
        </tbody></table></div>
      </section>
    </div>`;

  let step = 0, raf = null;
  const svg = $('#pipe');
  const packet = $('#packet');
  const go = (i, animate = true) => {
    step = Math.max(0, Math.min(STEPS.length - 1, i));
    const s = STEPS[step];
    document.querySelectorAll('#steps button').forEach((b, j) => { if (j === step) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current'); });
    svg.querySelectorAll('.node').forEach((n) => n.toggleAttribute('data-active', n.dataset.node === s.node));
    $('#step-body').innerHTML = `<div class="swap"><h3>${s.title}</h3><p>${s.text}</p><pre class="code">${esc(s.code)}</pre></div>`;
    $('#step-prev').disabled = step === 0;
    $('#step-next').textContent = step === STEPS.length - 1 ? 'Start again' : 'Next';
    movePacket(s, animate);
  };
  // The dot is the system call in flight. It only travels along the arrows, never
  // across a box's text: a step that starts somewhere else (leaving the monitor
  // after parsing) fades it out, moves it, and fades it back, as if processed inside.
  const pos = () => [Number(packet.getAttribute('cx')), Number(packet.getAttribute('cy'))];
  const place = ([x, y]) => { packet.setAttribute('cx', x); packet.setAttribute('cy', y); };
  // a CSS transition plus a timer, not an animation's .finished promise: that only
  // resolves when frames are drawn, so in a background tab the steps fell behind
  const fade = (to, ms) => {
    packet.style.opacity = String(to);
    return new Promise((r) => setTimeout(r, reduced ? 0 : ms));
  };
  let token = 0;
  const movePacket = async (s, animate) => {
    cancelAnimationFrame(raf);
    const mine = ++token;
    if (s.node === 'policy') { fade(0, 200); return; }   // after the run, nothing is in flight
    const path = s.path && svg.querySelector(`#${s.path}`);
    const start = path ? path.getPointAtLength(0) : null;
    const from = start ? [start.x, start.y] : s.at;
    const end = path ? path.getPointAtLength(path.getTotalLength()) : null;
    if (!animate || reduced) { place(end ? [end.x, end.y] : from); fade(1, 0); return; }
    const [cx, cy] = pos();
    if (Math.hypot(cx - from[0], cy - from[1]) > 4) {
      await fade(0, 120); if (mine !== token) return;
      place(from);
    }
    await fade(1, 120); if (mine !== token) return;
    if (!path) return;
    const len = path.getTotalLength(), dur = Math.max(500, len * 2.2), t0 = performance.now();
    const ease = (k) => (k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2);
    const frame = (now) => {
      const k = Math.min(1, (now - t0) / dur);
      const p = path.getPointAtLength(len * ease(k));
      place([p.x, p.y]);
      if (k < 1) raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
  };
  $('#steps').addEventListener('click', (e) => { const b = e.target.closest('[data-step]'); if (b) go(Number(b.dataset.step)); });
  $('#step-prev').addEventListener('click', () => go(step - 1));
  $('#step-next').addEventListener('click', () => go(step === STEPS.length - 1 ? 0 : step + 1));
  go(0, false);
  current = { unmount: () => cancelAnimationFrame(raf) };
}

function pipelineSvg() {
  const node = (id, x, title, sub, mech, w = 196) => `
    <g class="node" data-node="${id}">
      <rect x="${x}" y="40" width="${w}" height="104" rx="6"/>
      <text class="title" x="${x + 16}" y="72">${title}</text>
      <text class="sub" x="${x + 16}" y="94">${sub}</text>
      <text class="mech" x="${x + 16}" y="124">${mech}</text>
    </g>`;
  return `<svg id="pipe" viewBox="0 0 1000 250" role="img" aria-label="The AdaptBox loop: the sandboxed process is monitored, scored, and the response tightens the process's confinement">
    <defs><marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0 0L8 4L0 8z" fill="#3a3a3e"/></marker></defs>
    <path id="e1" class="edge" d="M212 92H262" marker-end="url(#arr)"/>
    <path id="e2" class="edge" d="M474 92H524" marker-end="url(#arr)"/>
    <path id="e3" class="edge" d="M736 92H786" marker-end="url(#arr)"/>
    <path id="loop" class="edge loop" d="M882 144V206H110V150" marker-end="url(#arr)"/>
    <text class="edge-label" x="237" y="34" text-anchor="middle">syscalls</text>
    <text class="edge-label" x="499" y="34" text-anchor="middle">events</text>
    <text class="edge-label" x="761" y="34" text-anchor="middle">score</text>
    <text class="edge-label" x="496" y="230" text-anchor="middle">tightens the live process's confinement</text>
    ${node('proc', 16, 'Sandboxed process', 'the untrusted script', 'namespaces · cgroup v2')}
    ${node('mon', 278, 'Monitor', 'every system call', 'strace -f (eBPF next)')}
    ${node('score', 540, 'Score', 'rules + Isolation Forest', '0.6 × previous + hits')}
    ${node('resp', 802, 'Respond', 'four stages', 'nft · mount · cgroup', 182)}
    <circle id="packet" class="packet" r="6" cx="212" cy="92"/>
  </svg>`;
}

// ------------------------------------------------------------------ router

const ROUTES = [
  [/^#\/live$/, () => renderLive(), 'live'],
  [/^#\/test$/, () => renderTest(), 'test'],
  [/^#\/runs$/, () => renderRuns(), 'runs'],
  [/^#\/runs\/([0-9a-f]{8})$/, (m) => renderRun(m[1]), 'runs'],
  [/^#\/benchmark$/, () => renderBenchmark(), 'benchmark'],
  [/^#\/how$/, () => renderHow(), 'how'],
];

function route() {
  const hash = location.hash || '#/live';
  const match = ROUTES.map(([re, fn, nav]) => [hash.match(re), fn, nav]).find(([m]) => m);
  if (!match) { location.replace('#/live'); return; }
  const [m, fn, nav] = match;
  const swap = () => {
    current?.unmount?.(); current = null;
    document.querySelectorAll('.rail-link').forEach((a) => {
      if (a.dataset.route === nav) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    fn(m);
    view.scrollTop = 0; window.scrollTo(0, 0);
  };
  if (document.startViewTransition && !reduced && route.ready) document.startViewTransition(swap);
  else swap();
  route.ready = true;
}

// actions inside screens, delegated
view.addEventListener('click', async (e) => {
  const toggle = e.target.closest('[data-toggle]');
  if (toggle) {           // open or close a sample's description in place, so it animates
    const id = toggle.dataset.toggle, row = toggle.closest('.sample');
    const open = !S.open.has(id);
    if (open) S.open.add(id); else S.open.delete(id);
    row.toggleAttribute('data-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    return;
  }
  const run = e.target.closest('[data-run]');
  if (run) {
    S.selected = run.dataset.run;
    run.disabled = true;
    try { await Engine.start(run.dataset.run); }
    catch (err) { toast(err.message); run.disabled = false; }
    return;
  }
  const row = e.target.closest('tr[data-href]');
  if (row && !e.target.closest('a')) { location.hash = row.dataset.href; return; }
  const act = e.target.closest('[data-action]')?.dataset.action;
  if (act === 'retry') location.reload();
  if (act === 'reload') route();
  if (act === 'bench-go' && !Engine.busy) {
    e.preventDefault();
    location.hash = '#/benchmark';
    try { await Engine.startBenchmark(); } catch (err) { toast(err.message); }
  }
});

window.addEventListener('hashchange', route);

(async function boot() {
  try {
    await Engine.connect();
    if (Engine.mode === 'live') setEngineDot('live');
    S.samples = await Engine.samples();
  } catch (e) {
    view.innerHTML = `<div class="title-row"><div><h1>AdaptBox monitor</h1><p class="finding">Couldn't start: ${esc(e.message)}</p></div></div>`;
    return;
  }
  route();
})();
