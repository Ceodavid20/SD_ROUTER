/* Actual TX and independently measured RTT jitter. Inspect without stopping live updates. */
(() => {
  'use strict';
  const root = document.querySelector('[data-live-tx]');
  if (!root) return;
  const ns = 'http://www.w3.org/2000/svg';
  const colors = ['#215ec3', '#16866e', '#995cc0', '#b6731e'];
  const chart = root.querySelector('[data-tx-chart]');
  const legend = root.querySelector('[data-tx-series]');
  const range = root.querySelector('[data-tx-range]');
  const jitterToggle = root.querySelector('[data-jitter-toggle]');
  const readingValues = root.querySelector('[data-tx-reading-values]');
  const connection = root.querySelector('[data-live-connection]');
  let data = JSON.parse(root.querySelector('[data-tx-payload]').textContent);
  let selected = null;
  let visiblePoints = [];
  let legendKey = '';
  let changesKey = '';
  let fetching = false;
  let samplesFetching = false;
  let sampleCursor = null;
  let controlSaving = false;
  let controlRevision = 0;
  const controlForm = document.querySelector('[data-optimization-control]');
  const toggle = document.querySelector('[data-optimization-toggle]');
  const hidden = new Set();
  const legendNodes = new Map();
  const format = value => {
    if (!Number.isFinite(value)) return '—';
    return value !== 0 && Math.abs(value) < .001
      ? value.toLocaleString(undefined, {maximumSignificantDigits: 4})
      : value.toLocaleString(undefined, {minimumFractionDigits: 3, maximumFractionDigits: 3});
  };
  const date = at => new Date(at).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'});
  const text = (tag, value, className) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  };
  const svgNode = (tag, attributes = {}, value) => {
    const node = document.createElementNS(ns, tag);
    Object.entries(attributes).forEach(([key, v]) => node.setAttribute(key, v));
    if (value !== undefined) node.textContent = value;
    return node;
  };
  const validPoint = p => Number.isFinite(p.mbps) && Number.isFinite(Date.parse(p.at));
  const quality = series => series.quality || {state: 'disabled', points: [], interval_seconds: data.sample_interval_seconds};
  const jitterVisible = () => jitterToggle?.checked ?? false;
  const jitterPoints = series => quality(series).points || [];
  const validJitter = p => Number.isFinite(p.jitter_ms) && Number.isFinite(Date.parse(p.at));
  const unit = p => p.metric === 'jitter' ? 'ms' : 'Mbps';
  const valueOf = p => p.metric === 'jitter' ? p.jitter_ms : p.mbps;
  const nearest = (points, time) => points.reduce((best, p) => !best || Math.abs(Date.parse(p.at) - time) < Math.abs(Date.parse(best.at) - time) ? p : best, null);

  function renderLegend() {
    const key = JSON.stringify(data.series.map(s => [s.id, s.name, s.source]));
    if (key !== legendKey) {
      legendKey = key;
      legend.replaceChildren();
      legendNodes.clear();
      data.series.forEach((series, index) => {
        const button = text('button', undefined, 'tx-series-item tx-series-toggle');
        button.type = 'button';
        button.title = series.source;
        const label = text('span', series.name, 'tx-series-name');
        const swatch = text('span', undefined, 'tx-swatch');
        swatch.style.backgroundColor = colors[index % colors.length];
        label.prepend(swatch);
        const value = text('strong');
        const jitter = text('span', undefined, 'tx-jitter-value');
        const state = text('small', undefined, 'tx-series-state');
        button.append(label, value, jitter, state);
        button.addEventListener('click', () => {
          if (hidden.has(series.id)) hidden.delete(series.id); else hidden.add(series.id);
          if (selected && hidden.has(selected.id)) selected = null;
          render();
        });
        legend.append(button);
        legendNodes.set(series.id, {button, value, jitter, state});
      });
    }
    data.series.forEach(series => {
      const item = legendNodes.get(series.id);
      item.value.textContent = `${format(series.current_mbps)} Mbps`;
      const q = quality(series);
      item.jitter.hidden = !jitterVisible();
      item.jitter.textContent = `${format(q.current_jitter_ms)} ms · ${(q.state || 'disabled').replaceAll('_', ' ')}`;
      item.state.textContent = series.state === 'measured' ? 'Receiving' : series.state.replaceAll('_', ' ');
      item.button.setAttribute('aria-pressed', String(!hidden.has(series.id)));
      item.button.classList.toggle('is-hidden', hidden.has(series.id));
    });
  }

  function showReading() {
    root.querySelector('[data-tx-reading-label]').textContent = selected ? 'Selected reading' : 'Latest reading';
    const selectedTime = selected ? Date.parse(selected.at) : null;
    const lastTimes = data.series.filter(s => !hidden.has(s.id)).flatMap(s => [
      ...s.points.filter(validPoint).slice(-1), ...(jitterVisible() ? jitterPoints(s).slice(-1) : [])].map(p => Date.parse(p.at)).filter(Number.isFinite));
    const time = selectedTime ?? (lastTimes.length ? Math.max(...lastTimes) : null);
    const stamp = root.querySelector('[data-tx-reading-time]');
    stamp.textContent = time === null ? '—' : date(time);
    if (time !== null) stamp.dateTime = new Date(time).toISOString(); else stamp.removeAttribute('datetime');
    readingValues.replaceChildren();
    data.series.filter(s => !hidden.has(s.id)).forEach(series => {
      let point = time === null ? null : nearest(series.points.filter(validPoint), time);
      if (point && selected && Math.abs(Date.parse(point.at) - time) > Math.max(.75, (series.sample_interval_seconds || data.sample_interval_seconds) / 2) * 1000) point = null;
      const item = text('div', undefined, 'tx-reading-item');
      item.append(text('span', series.name));
      item.append(text('strong', `${format(point ? point.mbps : null)} Mbps`));
      item.append(text('small', point ? `${date(point.at)} · ${series.interface}` : 'No sample at this time'));
      if (jitterVisible()) {
        const q = quality(series);
        const samples = jitterPoints(series).filter(p => Number.isFinite(Date.parse(p.at)));
        let jitter = selected ? nearest(samples, time) : samples.at(-1);
        if (jitter && selected && Math.abs(Date.parse(jitter.at) - time) > Math.max(.75, (q.interval_seconds || 60) / 2) * 1000) jitter = null;
        item.append(text('strong', `RTT jitter ${format(jitter?.jitter_ms)} ms`));
        item.append(text('small', jitter ? `${date(jitter.at)} · ${jitter.target} · ${jitter.replies}/${jitter.probes_requested} replies${!selected && q.state === 'stale' ? ' · Stale' : ''}` : selected ? 'No jitter sample at this time' : `Jitter ${(q.state || 'disabled').replaceAll('_', ' ')}`));
      }
      readingValues.append(item);
    });
  }

  function renderChart() {
    const enabled = data.series.filter(s => !hidden.has(s.id));
    const now = Date.parse(data.updated_at);
    const cutoff = range.value === 'all' ? -Infinity : now - Number(range.value) * 60000;
    visiblePoints = enabled.flatMap(series => [
      ...series.points.filter(p => validPoint(p) && Date.parse(p.at) >= cutoff).map(p => ({...p, metric: 'tx'})),
      ...(jitterVisible() ? jitterPoints(series).filter(p => validJitter(p) && Date.parse(p.at) >= cutoff).map(p => ({...p, metric: 'jitter'})) : [])
    ].map(p => ({...p, id: series.id, name: series.name, color: colors[data.series.indexOf(series) % colors.length]})))
      .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
    if (!visiblePoints.length) {
      chart.replaceChildren(text('p', data.series.length ? 'No samples in this range' : 'Waiting for readings', 'tx-empty'));
      return;
    }
    const W = Math.max(320, chart.clientWidth || 920), H = W < 600 ? 260 : 350;
    const left = W < 600 ? 65 : 82, right = jitterVisible() ? 72 : 22, top = 24, bottom = 48, ticks = W < 600 ? 2 : 4;
    const last = Math.max(...visiblePoints.map(p => Date.parse(p.at)));
    const hi = Math.max(last + 1000, now);
    const lo = range.value === 'all' ? Math.min(...visiblePoints.map(p => Date.parse(p.at))) : cutoff;
    const maximum = Math.max(0, ...visiblePoints.filter(p => p.metric === 'tx').map(p => p.mbps));
    const max = maximum > 0 ? maximum * 1.15 : 1;
    const jitterMaximum = Math.max(0, ...visiblePoints.filter(p => p.metric === 'jitter').map(p => p.jitter_ms));
    const jitterMax = jitterMaximum > 0 ? jitterMaximum * 1.15 : 1;
    const x = t => left + (t - lo) / Math.max(1000, hi - lo) * (W - left - right);
    const y = p => H - bottom - valueOf(p) / (p.metric === 'jitter' ? jitterMax : max) * (H - top - bottom);
    const svg = svgNode('svg', {viewBox: `0 0 ${W} ${H}`, 'aria-label': 'Outbound TX in Mbps and RTT jitter in milliseconds', role: 'group'});
    for (let i = 0; i <= 4; i++) {
      const value = max * i / 4;
      const height = y({metric: 'tx', mbps: value});
      svg.append(svgNode('line', {x1: left, x2: W - right, y1: height, y2: height, stroke: '#e5ebf3'}));
      svg.append(svgNode('text', {x: left - 10, y: height + 4, 'text-anchor': 'end', 'font-size': 12}, format(value)));
      if (jitterVisible()) svg.append(svgNode('text', {x: W - right + 10, y: height + 4, 'text-anchor': 'start', 'font-size': 12, 'data-jitter-axis': ''}, format(jitterMax * i / 4)));
    }
    for (let i = 0; i <= ticks; i++) {
      const time = lo + (hi - lo) * i / ticks;
      svg.append(svgNode('text', {x: x(time), y: H - 17, 'text-anchor': 'middle', 'font-size': 12, 'data-tx-time-tick': ''}, new Date(time).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', ...(hi - lo <= 15 * 60000 ? {second: '2-digit'} : {})})));
    }
    svg.append(svgNode('text', {x: 8, y: 15, 'font-size': 12}, 'Mbps'));
    if (jitterVisible()) svg.append(svgNode('text', {x: W - 4, y: 15, 'text-anchor': 'end', 'font-size': 12}, 'Jitter (ms)'));
    enabled.forEach(series => {
      for (const metric of jitterVisible() ? ['tx', 'jitter'] : ['tx']) {
      const points = visiblePoints.filter(p => p.id === series.id && p.metric === metric);
      let previous = null;
      points.forEach(p => {
        const time = Date.parse(p.at), px = x(time), py = y(p);
        const maxGap = metric === 'jitter' ? (quality(series).interval_seconds || 60) * 3 : data.max_gap_seconds;
        if (previous && p.series_id && previous.series_id === p.series_id && time > previous.time && time - previous.time <= maxGap * 1000) {
          svg.append(svgNode('line', {x1: previous.x, y1: previous.y, x2: px, y2: py, stroke: p.color, 'stroke-width': 2.5, 'stroke-linecap': 'round',
            ...(metric === 'jitter' ? {'stroke-dasharray': '5 4', 'data-jitter-line': ''} : {})}));
        }
        const circle = svgNode(metric === 'jitter' ? 'rect' : 'circle', {
          ...(metric === 'jitter' ? {x: px - 3.5, y: py - 3.5, width: 7, height: 7, 'data-jitter-point': p.id + ':' + p.at} : {cx: px, cy: py, r: 3.5, 'data-tx-point': p.id + ':' + p.at}),
          fill: metric === 'jitter' ? 'white' : p.color, stroke: p.color, 'stroke-width': 1.5, role: 'button',
          'aria-label': `${p.name}${metric === 'jitter' ? ' RTT jitter' : ''}, ${format(valueOf(p))} ${unit(p)}, ${date(time)}`});
        circle.append(svgNode('title', {}, `${p.name}${metric === 'jitter' ? ' RTT jitter' : ''} · ${format(valueOf(p))} ${unit(p)} · ${date(time)}`));
        circle.addEventListener('click', event => {
          event.stopPropagation();
          selected = {id: p.id, at: p.at, metric};
          chart.focus({preventScroll: true});
          renderChart(); showReading();
        });
        svg.append(circle);
        previous = {...p, time, x: px, y: py};
      });
      }
    });
    if (selected && Date.parse(selected.at) >= lo && Date.parse(selected.at) <= hi) {
      svg.append(svgNode('line', {x1: x(Date.parse(selected.at)), x2: x(Date.parse(selected.at)), y1: top, y2: H - bottom, stroke: '#61738b', 'stroke-dasharray': '4 4', 'pointer-events': 'none'}));
      const point = visiblePoints.find(p => p.id === selected.id && p.at === selected.at && p.metric === (selected.metric || 'tx'));
      if (point) svg.append(svgNode('circle', {cx: x(Date.parse(point.at)), cy: y(point), r: 7, fill: 'white', stroke: point.color, 'stroke-width': 3, 'pointer-events': 'none'}));
    }
    svg.addEventListener('click', event => {
      const box = svg.getBoundingClientRect();
      const px = (event.clientX - box.left) / box.width * W;
      const py = (event.clientY - box.top) / box.height * H;
      if (px < left || px > W - right || py < top || py > H - bottom) return;
      const time = Math.round((lo + (px - left) / (W - left - right) * (hi - lo)) / 1000) * 1000;
      selected = {id: enabled[0].id, at: new Date(time).toISOString(), metric: 'timeline'};
      chart.focus({preventScroll: true}); renderChart(); showReading();
    });
    chart.replaceChildren(svg);
  }

  function renderOperations() {
    const summary = data.summary;
    const enabled = summary.optimization_enabled ?? true;
    if (toggle) {
      toggle.disabled = controlSaving;
      toggle.setAttribute('aria-busy', String(controlSaving));
      if (!controlSaving) {
        toggle.setAttribute('aria-checked', String(enabled));
        controlForm.querySelector('[data-optimization-next]').value = enabled ? 'false' : 'true';
        controlForm.querySelector('[data-optimization-state]').textContent = enabled ? 'On' : 'Off';
      }
    }
    document.querySelectorAll('[data-save-calculation]').forEach(button => { button.disabled = !enabled || controlSaving; });
    document.querySelectorAll('[data-live-total]').forEach(node => { node.textContent = format(summary.total_mbps); });
    document.querySelectorAll('[data-live-reporting]').forEach(node => { node.textContent = `${summary.reporting} / ${summary.links}`; });
    document.querySelectorAll('[data-live-status]').forEach(node => { node.textContent = summary.optimization_status.replaceAll('_', ' '); });
    const table = document.querySelector('[data-live-recommendations]');
    if (table) {
      const fragment = document.createDocumentFragment();
      data.recommendations.forEach(row => {
        const tr = text('tr');
        [row.name, format(row.actual_mbps), format(row.target_mbps), format(row.change_mbps), row.cost ?? '—',
          row.weight === null ? '—' : `${(row.weight * 100).toFixed(2)}%`].forEach((v, i) => tr.append(text(i === 0 ? 'th' : 'td', v)));
        fragment.append(tr);
      });
      if (!data.recommendations.length) {
        const row = text('tr'), cell = text('td', enabled ? 'No current recommendation' : 'Optimization off', 'table-empty');
        cell.colSpan = 6; row.append(cell); fragment.append(row);
      }
      table.replaceChildren(fragment);
    }
    const routers = document.querySelector('[data-live-routers]');
    if (routers && data.routers) {
      const fragment = document.createDocumentFragment();
      data.routers.forEach(router => {
        const row = text('tr'), label = text('th', router.name);
        label.append(text('small', router.id, 'table-secondary-line'));
        row.append(label, text('td', router.state.replaceAll('_', ' ')), text('td', router.sampled_at || '—'));
        fragment.append(row);
      });
      if (!data.routers.length) { const row = text('tr'), cell = text('td', 'No routers', 'table-empty'); cell.colSpan = 3; row.append(cell); fragment.append(row); }
      routers.replaceChildren(fragment);
    }
    const changes = document.querySelector('[data-live-changes]');
    const key = JSON.stringify(data.changes);
    if (changes && key !== changesKey) {
      changesKey = key;
      const fragment = document.createDocumentFragment();
      data.changes.forEach(change => {
        const li = text('li'), heading = text('div', undefined, 'change-heading');
        const badge = text('span', change.status, 'change-state');
        badge.dataset.state = change.status.toLowerCase().replaceAll(' ', '-');
        heading.append(text('strong', change.title), badge); li.append(heading);
        if (change.detail) li.append(text('p', change.detail));
        const time = text('time', date(change.at)); time.dateTime = change.at; li.append(time);
        fragment.append(li);
      });
      if (!data.changes.length) fragment.append(text('li', 'No changes recorded', 'change-empty'));
      changes.replaceChildren(fragment);
    }
  }

  function render() {
    if (selected && !data.series.some(s => s.id === selected.id)) selected = null;
    renderLegend(); renderChart(); showReading(); renderOperations();
    root.querySelector('[data-tx-updated]').textContent = `Updated ${new Date(data.updated_at).toLocaleTimeString()}`;
    const txIntervals = [...new Set(data.series.map(s => s.sample_interval_seconds || data.sample_interval_seconds))].sort((a,b) => a-b);
    const jitterIntervals = [...new Set(data.series.filter(s => quality(s).enabled).map(s => quality(s).interval_seconds))].sort((a,b) => a-b);
    root.querySelector('[data-tx-sampling]').textContent = `TX every ${txIntervals.join(' / ') || data.sample_interval_seconds}s${jitterIntervals.length ? ' · Jitter every ' + jitterIntervals.join(' / ') + 's' : ''}`;
    const live = data.summary.reporting > 0 || data.series.some(s => Number.isFinite(quality(s).current_jitter_ms));
    connection.textContent = live ? 'Live' : 'Awaiting readings';
    connection.dataset.state = live ? 'live' : 'waiting';
    root.querySelector('[data-tx-follow]').classList.toggle('is-selected', selected === null);
  }
  chart.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End', 'Escape'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Escape') { selected = null; render(); return; }
    const times = [...new Set(visiblePoints.map(p => p.at))];
    if (!times.length) return;
    let index = selected ? times.findIndex(at => Date.parse(at) >= Date.parse(selected.at)) : times.length - 1;
    if (index < 0) index = times.length - 1;
    if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = times.length - 1;
    else index = Math.max(0, Math.min(times.length - 1, index + (event.key === 'ArrowLeft' ? -1 : 1)));
    const point = visiblePoints.find(p => p.at === times[index]);
    selected = {id: point.id, at: point.at, metric: point.metric}; renderChart(); showReading();
  });
  range.addEventListener('change', () => { selected = null; render(); });
  jitterToggle?.addEventListener('change', () => { if (!jitterVisible() && selected?.metric === 'jitter') selected = null; render(); });
  root.querySelector('[data-tx-follow]').addEventListener('click', () => { selected = null; render(); });
  render();
  if (typeof ResizeObserver !== 'undefined') {
    let width = chart.clientWidth;
    new ResizeObserver(() => {
      if (Math.abs(width - chart.clientWidth) > 1) { width = chart.clientWidth; renderChart(); }
    }).observe(chart);
  }

  async function update() {
    if (fetching || document.hidden || controlSaving) return;
    fetching = true;
    const revision = controlRevision;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(root.dataset.requestTimeoutSeconds || 10) * 1000);
    try {
      const response = await fetch(root.dataset.endpoint, {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal});
      if (!response.ok) throw new Error(response.status === 401 ? 'session' : 'connection');
      const next = await response.json();
      if (!Array.isArray(next.series) || !next.summary || !Array.isArray(next.changes)) throw new Error('data');
      if (revision === controlRevision) { data = next; render(); }
    } catch (error) {
      if (revision === controlRevision) {
        connection.textContent = error.message === 'session' ? 'Session expired' : 'Reconnecting';
        connection.dataset.state = 'waiting';
      }
    } finally { clearTimeout(timeout); fetching = false; }
  }
  if (controlForm) controlForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (controlSaving) return;
    controlSaving = true;
    controlRevision += 1;
    const message = document.querySelector('[data-optimization-error]');
    message.textContent = '';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(root.dataset.requestTimeoutSeconds || 10) * 1000);
    renderOperations();
    try {
      const response = await fetch(controlForm.action, {method: 'POST', credentials: 'same-origin', redirect: 'error',
        headers: {'Accept': 'application/json'}, body: new FormData(controlForm), signal: controller.signal});
      if (!response.ok) throw new Error('control');
      const state = await response.json();
      if (typeof state.optimization_enabled !== 'boolean') throw new Error('control');
      data.summary.optimization_enabled = state.optimization_enabled;
      data.summary.optimization_status = state.optimization_enabled ? 'starting' : 'off';
      data.recommendations = [];
    } catch (error) { message.textContent = 'Could not confirm the setting.'; }
    finally {
      clearTimeout(timeout);
      controlSaving = false;
      render();
      update();
    }
  });
  setInterval(update, Math.max(2000, data.refresh_seconds * 1000));
  const mergePoints = (existing, incoming, retention) => {
    const points = new Map(existing.map(p => [p.at + ':' + (p.source || 'signed'), p]));
    incoming.forEach(p => points.set(p.at + ':' + (p.source || 'signed'), p));
    const ordered = [...points.values()].sort((a,b) => Date.parse(a.at) - Date.parse(b.at));
    const fast = ordered.filter(p => p.source === 'api_ssl_live').slice(-retention);
    const first = fast.length ? Date.parse(fast[0].at) : Infinity;
    return [...ordered.filter(p => p.source !== 'api_ssl_live' && Date.parse(p.at) < first), ...fast];
  };
  async function updateSamples() {
    if (samplesFetching || document.hidden || !root.dataset.samplesEndpoint) return;
    samplesFetching = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Number(root.dataset.requestTimeoutSeconds || 10) * 1000);
    try {
      const url = new URL(root.dataset.samplesEndpoint, location.origin);
      if (sampleCursor) url.searchParams.set('after', sampleCursor);
      const response = await fetch(url, {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal});
      if (!response.ok) throw new Error('samples');
      const next = await response.json();
      if (!Array.isArray(next.series) || !Number.isFinite(Date.parse(next.updated_at))) throw new Error('samples');
      next.series.forEach(sampled => {
        const series = data.series.find(s => s.id === sampled.id);
        if (!series) return;
        // Full snapshots and delta requests may complete in either order.
        if (series.sampled_at && sampled.sampled_at && Date.parse(sampled.sampled_at) < Date.parse(series.sampled_at)) return;
        const points = mergePoints(series.points, sampled.points, next.retention_points);
        const qPoints = mergePoints(jitterPoints(series), sampled.quality.points, next.retention_points);
        Object.assign(series, sampled, {points, quality: {...sampled.quality, points: qPoints}});
      });
      sampleCursor = next.updated_at;
      if (next.series.length) { data.updated_at = next.updated_at; render(); }
    } catch (error) {
      if (data.series.some(s => s.sample_interval_seconds === 1)) {
        connection.textContent = 'Reconnecting'; connection.dataset.state = 'waiting';
      }
    } finally { clearTimeout(timeout); samplesFetching = false; }
  }
  setInterval(updateSamples, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { update(); updateSamples(); } });
})();
