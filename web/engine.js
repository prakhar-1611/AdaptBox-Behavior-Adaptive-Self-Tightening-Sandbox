// engine.js — one interface over two back ends.
//   live:      the AdaptBox server on Kali (fetch + Server-Sent Events)
//   simulated: recordings in demo-data.js, replayed in real time with the same events
// Views call Engine.* and listen with Engine.on(fn); they never know which one is behind it.
// Events: start, window, stage, output, end, busy, bench_start, bench_row, bench_end, error,
// plus conn {state: 'live' | 'lost' | 'simulated'} for the status dot.

const Engine = (() => {
  const listeners = new Set();
  const emit = (ev) => listeners.forEach((fn) => { try { fn(ev); } catch (e) { console.error(e); } });
  const params = new URLSearchParams(location.search);
  let mode = null;
  let base = '';
  let info = null;
  let busy = null;

  // ------------------------------------------------------------------ live

  async function getJSON(path, { timeout = 4000, method = 'GET', body } = {}) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeout);
    try {
      const res = await fetch(base + path, {
        method, signal: ctl.signal, cache: 'no-store',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { const err = new Error(data.error || res.statusText); err.status = res.status; throw err; }
      return data;
    } finally { clearTimeout(timer); }
  }

  function openStream() {
    const es = new EventSource(base + '/api/stream');
    es.onopen = () => emit({ type: 'conn', state: 'live' });
    es.onerror = () => emit({ type: 'conn', state: 'lost' });
    es.onmessage = (m) => {
      let ev; try { ev = JSON.parse(m.data); } catch { return; }
      if (ev.type === 'busy') busy = ev.busy;
      emit(ev);
    };
  }

  const live = {
    samples: () => getJSON('/api/samples'),
    runs: () => getJSON('/api/runs'),
    run: (id) => getJSON('/api/runs/' + encodeURIComponent(id)),
    benchmark: () => getJSON('/api/benchmark').catch((e) => { if (e.status === 404) return null; throw e; }),
    start: (sample) => getJSON('/api/runs', { method: 'POST', body: { sample } }),
    startCode: (filename, code) => getJSON('/api/runs', { method: 'POST', body: { filename, code } }),
    startBenchmark: () => getJSON('/api/benchmark', { method: 'POST', body: {} }),
  };

  // ------------------------------------------------------------- simulated

  const D = window.ADAPTBOX_DEMO;
  const session = new Map();          // runs replayed in this tab, by their new id
  let benchmark = D ? D.benchmark : null;
  const hex = () => Math.random().toString(16).slice(2, 10).padEnd(8, '0');
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  function setBusy(v) { busy = v; emit({ type: 'busy', busy: v }); }

  // Replays one recording as a stream of events on its own clock, then stores it.
  async function replay(sampleId) {
    const sample = D.samples.find((s) => s.id === sampleId);
    const rec = D.runs[D.bySample[sampleId]];
    const id = hex();
    const r = structuredClone(rec.result);
    r.run_id = id; r.started_at = Date.now() / 1000;
    const tag = (ev) => ({ ...ev, run_id: id, sample: sampleId, class: sample.class });
    const timeline = [];
    for (const o of rec.output) timeline.push({ t: o.t, ev: { type: 'output', ...o } });
    // the server publishes a window's stages just before the window itself
    for (const s of r.stage_log) timeline.push({ t: s.t - 0.0001, ev: { type: 'stage', ...s } });
    for (const w of r.timeline) timeline.push({ t: w.ts, ev: { type: 'window', ...w } });
    timeline.sort((a, b) => a.t - b.t);

    emit(tag({ type: 'start', target: r.target, pid: 3, window_seconds: r.window_seconds,
               thresholds: r.thresholds, stages: info.stages, started_at: r.started_at }));
    const t0 = performance.now();
    for (const item of timeline) {
      const due = item.t * 1000 - (performance.now() - t0);
      if (due > 0) await wait(due);
      emit(tag(item.ev));
    }
    const left = r.duration * 1000 - (performance.now() - t0);
    if (left > 0) await wait(left);
    emit(tag({ type: 'end', max_score: r.max_score, max_stage: r.max_stage, exit_code: r.exit_code,
               duration: r.duration, policy_path: r.policy_path.replace(rec.result.run_id, id) }));
    const copy = { ...structuredClone(rec), result: r, summary: { ...rec.summary, run_id: id, started_at: r.started_at } };
    session.set(id, copy);
    return copy;
  }

  const simulated = {
    samples: async () => D.samples,
    runs: async () => [...[...session.values()].map((r) => r.summary).reverse(),
                       ...Object.values(D.runs).map((r) => r.summary)],
    run: async (id) => { const r = session.get(id) || D.runs[id]; if (!r) { const e = new Error('no such run'); e.status = 404; throw e; } return r; },
    benchmark: async () => benchmark,
    start: async (sample) => {
      if (busy) { const e = new Error('busy: ' + busy); e.status = 409; throw e; }
      if (!D.bySample[sample]) { const e = new Error('unknown sample'); e.status = 400; throw e; }
      setBusy('run:' + sample);
      replay(sample).finally(() => setBusy(null));
      return { run_id: null };
    },
    startCode: async () => {
      // Recordings cannot run new code; this needs the engine on Kali.
      const e = new Error('Testing your own code needs the live engine. Start it on Kali with "sudo python3 -m adaptbox.server".');
      e.status = 503; throw e;
    },
    startBenchmark: async () => {
      if (busy) { const e = new Error('busy: ' + busy); e.status = 409; throw e; }
      setBusy('benchmark');
      (async () => {
        emit({ type: 'bench_start', samples: D.samples.map((s) => s.id) });
        const rows = [];
        for (const s of D.samples) {
          const rec = await replay(s.id);
          const base = D.benchmark.rows.find((x) => x.sample === s.name);
          const row = { ...base, run_id: rec.result.run_id };
          rows.push(row);
          emit({ type: 'bench_row', row });
          await wait(500);
        }
        benchmark = { rows, summary: D.benchmark.summary, finished_at: Date.now() / 1000 };
        emit({ type: 'bench_end', summary: D.benchmark.summary });
      })().finally(() => setBusy(null));
      return { started: true };
    },
  };

  // ------------------------------------------------------------------ connect

  async function connect() {
    const want = params.get('engine');
    base = want && want !== 'demo' ? want.replace(/\/$/, '') : (location.protocol === 'file:' ? 'http://localhost:8765' : '');
    if (want !== 'demo') {
      try {
        info = await getJSON('/api/info', { timeout: 2500 });
        mode = 'live'; busy = info.busy;
        openStream();
        return { mode, info };
      } catch (e) { /* fall through to the recordings */ }
    }
    if (!D) throw new Error('engine unreachable and no recordings bundled');
    mode = 'simulated';
    info = { ...D.info };
    setTimeout(() => emit({ type: 'conn', state: 'simulated' }), 0);
    return { mode, info };
  }

  const api = () => (mode === 'live' ? live : simulated);
  return {
    connect,
    on: (fn) => { listeners.add(fn); return () => listeners.delete(fn); },
    get mode() { return mode; },
    get info() { return info; },
    get busy() { return busy; },
    get address() { return base || location.origin; },
    samples: () => api().samples(),
    runs: () => api().runs(),
    run: (id) => api().run(id),
    benchmark: () => api().benchmark(),
    start: (sample) => api().start(sample),
    startCode: (filename, code) => api().startCode(filename, code),
    startBenchmark: () => api().startBenchmark(),
  };
})();
