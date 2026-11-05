// chart.js — the risk score over time, with the ratchet beside it.
// The ratchet is AdaptBox's signature: one rung per containment stage, each placed at
// the height of its threshold on the same scale as the plot, so the score line visibly
// reaches a rung and locks it. Rungs only lock, never unlock (in replay, scrubbing back
// shows the state at that moment).
//
//   const c = new ScoreChart(el, { thresholds: [.35, .55, .75, .9] })
//   c.load(timeline, stageLog, { end })   full data (replay or catch-up)
//   c.addWindow(w)                        live: append and draw the new segment in
//   c.addStage(rec)                       live: a stage was applied
//   c.setEnd({ t, killed })               live: the run ended
//   c.setCursor(t)                        replay: show the run up to t
//   c.onCursor = (t, score, stage) => {}  called whenever the visible moment changes

const STAGE_NAMES = ['Network cut', 'Writes blocked', 'CPU & memory capped', 'Killed'];
const STAGE_SHORT = ['Network', 'Writes', 'CPU, mem', 'Killed'];   // phone width

class ScoreChart {
  constructor(root, { thresholds }) {
    this.root = root;
    this.th = thresholds;
    this.band = 22;          // marker labels above the plot
    this.plotH = 280;
    this.axisH = 26;
    this.left = 40;
    this.H = this.band + this.plotH + this.axisH;
    this.reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.onCursor = null;
    this._clear();
    this._build();
    // stop when the screen that owned this chart is gone, or a late resize would
    // try to update numbers that no longer exist
    const ro = new ResizeObserver(() => {
      if (!this.root.isConnected) { ro.disconnect(); cancelAnimationFrame(this._raf); return; }
      this._layout();
    });
    ro.observe(this.plotEl);
  }

  _clear() {
    this.points = [];         // { t, s, w }
    this.stages = [];         // stage records
    this.end = null;
    this.cursor = 0;
    this.domain = 10;
    this.locked = new Set();
    cancelAnimationFrame(this._raf);
  }

  // ---------------------------------------------------------------- dom

  _build() {
    const NS = 'http://www.w3.org/2000/svg';
    const el = (tag, attrs = {}, parent) => {
      const n = document.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
      if (parent) parent.appendChild(n);
      return n;
    };
    this.el = el;
    this.root.innerHTML = '';
    this.root.classList.add('score-wrap');

    this.plotEl = document.createElement('div');
    this.plotEl.className = 'score-plot';
    const svg = this.svg = el('svg', { height: this.H, role: 'img', 'aria-label': 'Risk score over time' });
    const id = 'clip' + Math.random().toString(36).slice(2, 8);
    const defs = el('defs', {}, svg);
    const clip = el('clipPath', { id }, defs);
    this.clipRect = el('rect', { x: 0, y: 0, height: this.H, width: 0 }, clip);

    this.gGrid = el('g', { class: 'axis' }, svg);
    this.gTh = el('g', {}, svg);
    this.gMarkers = el('g', {}, svg);
    const gData = el('g', { 'clip-path': `url(#${id})` }, svg);
    this.area = el('path', { class: 'score-area' }, gData);
    this.line = el('path', { class: 'score-line' }, gData);
    this.endTick = el('line', { class: 'baseline', visibility: 'hidden' }, svg);
    this.hoverLine = el('line', { class: 'cursor-line', visibility: 'hidden' }, svg);
    this.ring = el('circle', { class: 'score-dot-ring', r: 5 }, svg);
    this.dot = el('circle', { class: 'score-dot', r: 3.5, visibility: 'hidden' }, svg);

    this.thLines = this.th.map((v, i) => el('line', { class: 'threshold', 'data-stage': i + 1 }, this.gTh));

    this.empty = document.createElement('div');
    this.empty.className = 'empty-msg';
    this.empty.textContent = 'Run a sample to see its risk score here.';

    this.tip = document.createElement('div');
    this.tip.className = 'chart-tip';
    Object.assign(this.tip.style, {
      position: 'absolute', pointerEvents: 'none', opacity: 0, background: 'var(--raised)',
      border: '1px solid var(--control)', borderRadius: '4px', padding: '6px 10px',
      fontSize: '12px', boxShadow: 'var(--shadow)', maxWidth: '280px', zIndex: 5,
      transition: 'opacity 120ms linear',
    });

    this.plotEl.append(svg, this.empty, this.tip);

    this.ratchet = document.createElement('div');
    this.ratchet.className = 'ratchet';
    this.ratchet.style.height = this.H + 'px';
    this.rungs = this.th.map((v, i) => {
      const r = document.createElement('div');
      r.className = 'rung';
      r.dataset.kind = i === 3 ? 'kill' : 'warn';
      r.innerHTML = `
        <svg class="lock" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
          <path class="shackle" d="M5 7V5a3 3 0 0 1 6 0v2"/><rect x="3.5" y="7" width="9" height="7" rx="1.5"/>
        </svg>
        <span class="rname"><span class="full">${STAGE_NAMES[i]}</span><span class="short">${STAGE_SHORT[i]}</span><span class="th">≥ ${v.toFixed(2)}</span></span>
        <span class="rtime">—</span>`;
      r.setAttribute('aria-label', `Stage ${i + 1}, ${STAGE_NAMES[i]}, at score ${v.toFixed(2)}: open`);
      this.ratchet.appendChild(r);
      return r;
    });
    this.openNote = document.createElement('div');
    this.openNote.className = 'open-note';
    this.openNote.textContent = `Below ${this.th[0].toFixed(2)} nothing is restricted: full network, writes, CPU and 1 GiB of memory.`;
    this.ratchet.appendChild(this.openNote);

    this.root.append(this.plotEl, this.ratchet);

    svg.addEventListener('pointermove', (e) => this._hover(e));
    svg.addEventListener('pointerleave', () => this._hover(null));
  }

  // ---------------------------------------------------------------- scale

  get W() { return Math.max(200, this.plotEl.clientWidth); }
  x(t) { return this.left + (t / this.domain) * (this.W - this.left - 8); }
  y(s) { return this.band + (1 - s) * this.plotH; }

  _niceDomain(t) {
    const steps = [5, 10, 15, 20, 30, 40, 60, 90, 120];
    return steps.find((s) => s >= t * 1.08) || Math.ceil(t / 30) * 30;
  }

  _layout() {
    const W = this.W, svg = this.svg, el = this.el;
    svg.setAttribute('width', W);
    svg.setAttribute('viewBox', `0 0 ${W} ${this.H}`);

    // y: 0 to 1 in quarters; x: whole seconds on one step
    this.gGrid.innerHTML = '';
    for (const v of [0, 0.25, 0.5, 0.75, 1]) {
      el('line', { class: v === 0 ? 'baseline' : 'gridline', x1: this.left, x2: W - 8, y1: this.y(v), y2: this.y(v) }, this.gGrid);
      el('text', { x: this.left - 8, y: this.y(v) + 4, 'text-anchor': 'end' }, this.gGrid).textContent = v === 0 ? '0' : v.toFixed(2);
    }
    const step = this.domain <= 10 ? 1 : this.domain <= 20 ? 2 : this.domain <= 60 ? 5 : 10;
    const every = Math.max(1, Math.ceil((this.domain / step) / Math.max(4, Math.floor((W - this.left) / 64))));
    for (let t = 0, i = 0; t <= this.domain + 1e-9; t += step, i++) {
      if (i % every) continue;
      const last = t + step * every > this.domain + 1e-9;
      el('text', { x: this.x(t), y: this.band + this.plotH + 18, 'text-anchor': t === 0 ? 'start' : last ? 'end' : 'middle' }, this.gGrid)
        .textContent = last ? `${t} s` : String(t);
    }

    this.thLines.forEach((ln, i) => {
      const y = this.y(this.th[i]);
      ln.setAttribute('x1', this.left); ln.setAttribute('x2', W); ln.setAttribute('y1', y); ln.setAttribute('y2', y);
    });
    this.rungs.forEach((r, i) => { r.style.top = this.y(this.th[i]) + 'px'; });
    this.openNote.style.top = (this.y(this.th[0]) + 22) + 'px';

    const pts = [{ t: 0, s: 0 }, ...this.points];
    const d = pts.map((p, i) => `${i ? 'L' : 'M'}${this.x(p.t).toFixed(1)},${this.y(p.s).toFixed(1)}`).join('');
    this.line.setAttribute('d', d);
    const last = pts[pts.length - 1];
    this.area.setAttribute('d', pts.length > 1 ? `${d}L${this.x(last.t).toFixed(1)},${this.y(0)}L${this.x(0)},${this.y(0)}Z` : '');

    this._drawMarkers();
    if (this.end) {
      const x = this.x(this.end.t);
      Object.entries({ x1: x, x2: x, y1: this.y(0) - 5, y2: this.y(0) + 5 }).forEach(([k, v]) => this.endTick.setAttribute(k, v));
    }
    this._paint(this.cursor, false);
  }

  _drawMarkers() {
    this.gMarkers.innerHTML = '';
    // stages applied in the same window share one marker: "1–4"
    const groups = [];
    for (const s of this.stages) {
      const g = groups.find((x) => Math.abs(x.t - s.t) < 0.05);
      if (g) g.list.push(s.stage); else groups.push({ t: s.t, list: [s.stage] });
    }
    this.markerEls = groups.map((g) => {
      const kind = g.list.includes(4) ? 'kill' : 'warn';
      const x = this.x(g.t);
      const grp = this.el('g', { class: 'stage-marker', 'data-kind': kind, 'data-t': g.t }, this.gMarkers);
      this.el('line', { x1: x, x2: x, y1: this.band - 2, y2: this.y(0) }, grp);
      const label = g.list.length > 1 ? `${g.list[0]}–${g.list[g.list.length - 1]}` : String(g.list[0]);
      this.el('text', { x, y: this.band - 7, 'text-anchor': 'middle' }, grp).textContent = label;
      grp.style.visibility = g.t <= this.cursor + 1e-6 ? 'visible' : 'hidden';
      return { t: g.t, grp };
    });
  }

  // ---------------------------------------------------------------- painting the moment

  scoreAt(t) {
    const pts = [{ t: 0, s: 0 }, ...this.points];
    if (t <= 0) return 0;
    for (let i = 1; i < pts.length; i++) {
      if (t <= pts[i].t) {
        const a = pts[i - 1], b = pts[i];
        return a.s + (b.s - a.s) * ((t - a.t) / (b.t - a.t || 1));
      }
    }
    return pts[pts.length - 1].s;
  }

  stageAt(t) { return this.stages.filter((s) => s.t <= t + 1e-6).reduce((m, s) => Math.max(m, s.stage), 0); }

  _paint(t, animate) {
    this.cursor = t;
    const lastT = this.points.length ? this.points[this.points.length - 1].t : 0;
    const tt = Math.min(t, lastT);
    const x = this.x(tt);
    this.clipRect.setAttribute('width', Math.max(0, x + 2));
    const s = this.scoreAt(tt);
    if (this.points.length) {
      this.dot.setAttribute('visibility', 'visible');
      this.dot.setAttribute('cx', x); this.dot.setAttribute('cy', this.y(s));
      this.ring.setAttribute('cx', x); this.ring.setAttribute('cy', this.y(s));
    } else {
      this.dot.setAttribute('visibility', 'hidden');
    }
    this.empty.hidden = !!(this.points.length || this.end);
    this.endTick.setAttribute('visibility', this.end && t >= this.end.t - 1e-6 ? 'visible' : 'hidden');

    (this.markerEls || []).forEach((m) => {
      const show = m.t <= t + 1e-6;
      if (show && m.grp.style.visibility === 'hidden' && animate && !this.reduced) {
        const ln = m.grp.querySelector('line');
        ln.style.transformOrigin = `0 ${this.y(0)}px`;     // grow up from the baseline
        ln.animate([{ transform: 'scaleY(0)' }, { transform: 'scaleY(1)' }],
                   { duration: 260, easing: 'cubic-bezier(.2,.8,.2,1)' });
      }
      m.grp.style.visibility = show ? 'visible' : 'hidden';
    });

    for (let i = 0; i < 4; i++) {
      const rec = this.stages.find((x) => x.stage === i + 1);
      const on = rec && rec.t <= t + 1e-6;
      const r = this.rungs[i];
      const kind = i === 3 ? 'kill' : 'warn';
      if (on && !this.locked.has(i)) {
        this.locked.add(i);
        if (animate && !this.reduced) this._latch(r);
      } else if (!on) this.locked.delete(i);
      r.toggleAttribute('data-locked', !!on);
      r.toggleAttribute('data-failed', !!(on && rec.ok === false));
      r.querySelector('.rtime').textContent = on ? (rec.ok === false ? 'failed' : `${rec.t.toFixed(2)} s`) : '—';
      r.setAttribute('aria-label', `Stage ${i + 1}, ${STAGE_NAMES[i]}: ${on ? 'locked at ' + rec.t.toFixed(2) + ' s' : 'open'}`);
      if (on) this.thLines[i].dataset.locked = kind; else delete this.thLines[i].dataset.locked;
    }
    if (this.onCursor) this.onCursor(t, s, this.stageAt(t));
  }

  // the rung latches: a small kick sideways as the fill sweeps in, and a ring off the dot
  _latch(rung) {
    rung.animate([{ transform: 'translate(-3px, -50%)' }, { transform: 'translate(0, -50%)' }],
                 { duration: 420, easing: 'cubic-bezier(.3,1.4,.5,1)' });
    this.ring.animate(
      [{ opacity: 0.9, transform: 'scale(1)' }, { opacity: 0, transform: 'scale(3.2)' }],
      { duration: 640, easing: 'cubic-bezier(.2,.8,.2,1)' });
  }

  _tweenTo(t, ms) {
    cancelAnimationFrame(this._raf);
    if (this.reduced || ms <= 0) { this._paint(t, true); return; }
    const from = this.cursor, start = performance.now();
    const ease = (k) => k;               // the line draws at a steady speed, like time
    const frame = (now) => {
      const k = Math.min(1, (now - start) / ms);
      this._paint(from + (t - from) * ease(k), true);
      if (k < 1) this._raf = requestAnimationFrame(frame);
    };
    this._raf = requestAnimationFrame(frame);
  }

  // ---------------------------------------------------------------- public

  reset() {
    this._clear();
    this._layout();
  }

  load(timeline, stageLog, { end = null, cursor = null } = {}) {
    this._clear();
    this.points = timeline.map((w) => ({ t: w.ts, s: w.score, w }));
    this.stages = stageLog.slice();
    this.end = end;
    const lastT = Math.max(end ? end.t : 0, this.points.length ? this.points[this.points.length - 1].t : 0);
    this.domain = this._niceDomain(Math.max(lastT, 4));
    this.cursor = cursor == null ? lastT : cursor;
    this.stages.filter((s) => s.t <= this.cursor).forEach((s) => this.locked.add(s.stage - 1));
    this._layout();
  }

  addWindow(w, windowSeconds = 0.5) {
    this.points.push({ t: w.ts, s: w.score, w });
    if (w.ts > this.domain * 0.92) { this.domain = this._niceDomain(w.ts * 1.3); }
    this._layout();
    this._tweenTo(w.ts, Math.min(360, windowSeconds * 1000 * 0.75));
  }

  addStage(rec) {
    if (this.stages.some((s) => s.stage === rec.stage)) return;
    this.stages.push(rec);
    this._drawMarkers();
    this._paint(this.cursor, true);
  }

  setEnd(end) {
    this.end = end;
    if (end.t > this.domain) this.domain = this._niceDomain(end.t);
    this._layout();
  }

  setCursor(t) { cancelAnimationFrame(this._raf); this._paint(t, true); }

  get lastT() { return Math.max(this.end ? this.end.t : 0, this.points.length ? this.points[this.points.length - 1].t : 0); }

  // ---------------------------------------------------------------- hover

  _hover(e) {
    if (!e || !this.points.length) {
      this.tip.style.opacity = 0; this.hoverLine.setAttribute('visibility', 'hidden'); return;
    }
    const rect = this.svg.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const visible = this.points.filter((p) => p.t <= this.cursor + 1e-6);
    if (!visible.length) return;
    const p = visible.reduce((a, b) => (Math.abs(this.x(b.t) - px) < Math.abs(this.x(a.t) - px) ? b : a));
    const x = this.x(p.t);
    Object.entries({ x1: x, x2: x, y1: this.band, y2: this.y(0) }).forEach(([k, v]) => this.hoverLine.setAttribute(k, v));
    this.hoverLine.setAttribute('visibility', 'visible');
    const hits = (p.w.hits || []).map((h) => `<div><span class="mono">+${h.weight.toFixed(2)}</span> ${esc(h.reason)}</div>`).join('');
    this.tip.innerHTML = `<div class="mono">${p.t.toFixed(2)} s · score ${p.s.toFixed(2)}</div>${hits || '<div class="muted">no rule fired in this window</div>'}`;
    const left = Math.min(x + 12, this.W - 290);
    this.tip.style.left = Math.max(0, left) + 'px';
    this.tip.style.top = Math.max(0, this.y(p.s) - 20) + 'px';
    this.tip.style.opacity = 1;
  }
}

function esc(v) {
  return String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
