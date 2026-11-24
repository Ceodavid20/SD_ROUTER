/* Actual main-router TX only. Inspect real samples without interrupting live updates. */
(() => {
  'use strict';
  const root = document.querySelector('[data-live-tx]');
  if (!root) return;
  const ns = 'http://www.w3.org/2000/svg';
  const colors = ['#215ec3', '#16866e', '#995cc0', '#b6731e'];
  const chart = root.querySelector('[data-tx-chart]');
  const legend = root.querySelector('[data-tx-series]');
  const range = root.querySelector('[data-tx-range]');
  const readingValues = root.querySelector('[data-tx-reading-values]');
  const connection = root.querySelector('[data-live-connection]');
  let data = JSON.parse(root.querySelector('[data-tx-payload]').textContent);
  let selected = null;
  let visiblePoints = [];
  let legendKey = '';
  let changesKey = '';
  let fetching = false;
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
        const state = text('small', undefined, 'tx-series-state');
        button.append(label, value, state);
        button.addEventListener('click', () => {
          if (hidden.has(series.id)) hidden.delete(series.id); else hidden.add(series.id);
          if (selected && hidden.has(selected.id)) selected = null;
          render();
        });
        legend.append(button);
        legendNodes.set(series.id, {button, value, state});
      });
    }
    data.series.forEach(series => {
      const item = legendNodes.get(series.id);
      item.value.textContent = `${format(series.current_mbps)} Mbps`;
      item.state.textContent = series.state === 'measured' ? 'Receiving' : series.state.replaceAll('_', ' ');
      item.button.setAttribute('aria-pressed', String(!hidden.has(series.id)));
      item.button.classList.toggle('is-hidden', hidden.has(series.id));
    });
  }

  function showReading() {
    root.querySelector('[data-tx-reading-label]').textContent = selected ? 'Selected reading' : 'Latest reading';
    const selectedTime = selected ? Date.parse(selected.at) : null;
    const lastTimes = data.series.filter(s => !hidden.has(s.id)).flatMap(s => s.points.filter(validPoint).slice(-1).map(p => Date.parse(p.at)));
    const time = selectedTime ?? (lastTimes.length ? Math.max(...lastTimes) : null);
    const stamp = root.querySelector('[data-tx-reading-time]');
    stamp.textContent = time === null ? '—' : date(time);
    if (time !== null) stamp.dateTime = new Date(time).toISOString(); else stamp.removeAttribute('datetime');
    readingValues.replaceChildren();
    data.series.filter(s => !hidden.has(s.id)).forEach(series => {
      let point = time === null ? null : nearest(series.points.filter(validPoint), time);
      if (point && selected && Math.abs(Date.parse(point.at) - time) > Math.max(2, data.sample_interval_seconds / 2) * 1000) point = null;
      const item = text('div', undefined, 'tx-reading-item');
      item.append(text('span', series.name));
      item.append(text('strong', `${format(point ? point.mbps : null)} Mbps`));
      item.append(text('small', point ? `${date(point.at)} · ${series.interface}` : 'No sample at this time'));
      readingValues.append(item);
    });
  }

  function renderChart() {
    const enabled = data.series.filter(s => !hidden.has(s.id));
    const now = Date.parse(data.updated_at);
    const cutoff = range.value === 'all' ? -Infinity : now - Number(range.value) * 60000;
    visiblePoints = enabled.flatMap((series, index) => series.points.filter(p => validPoint(p) && Date.parse(p.at) >= cutoff)
      .map(p => ({...p, id: series.id, name: series.name, color: colors[data.series.indexOf(series) % colors.length]})))
      .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
    if (!visiblePoints.length) {
      chart.replaceChildren(text('p', data.series.length ? 'No TX samples in this range' : 'Waiting for TX readings', 'tx-empty'));
      return;
    }
    const W = Math.max(320, chart.clientWidth || 920), H = W < 600 ? 260 : 350;
    const left = 82, right = 22, top = 20, bottom = 48, ticks = W < 600 ? 2 : 4;
    const last = Math.max(...visiblePoints.map(p => Date.parse(p.at)));
    const hi = Math.max(last + 1000, now);
    const lo = range.value === 'all' ? Math.min(...visiblePoints.map(p => Date.parse(p.at))) : cutoff;
    const maximum = Math.max(...visiblePoints.map(p => p.mbps));
    const max = maximum > 0 ? maximum * 1.15 : 1;
    const x = t => left + (t - lo) / Math.max(1000, hi - lo) * (W - left - right);
    const y = value => H - bottom - value / max * (H - top - bottom);
    const svg = svgNode('svg', {viewBox: `0 0 ${W} ${H}`, 'aria-label': 'Outbound TX samples in Mbps', role: 'group'});
    for (let i = 0; i <= 4; i++) {
      const value = max * i / 4;
      svg.append(svgNode('line', {x1: left, x2: W - right, y1: y(value), y2: y(value), stroke: '#e5ebf3'}));
      svg.append(svgNode('text', {x: left - 10, y: y(value) + 4, 'text-anchor': 'end', 'font-size': 12}, format(value)));
    }
    for (let i = 0; i <= ticks; i++) {
      const time = lo + (hi - lo) * i / ticks;
      svg.append(svgNode('text', {x: x(time), y: H - 17, 'text-anchor': 'middle', 'font-size': 12}, new Date(time).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})));
    }
    svg.append(svgNode('text', {x: 8, y: 15, 'font-size': 12}, 'Mbps'));
    enabled.forEach(series => {
      const points = visiblePoints.filter(p => p.id === series.id);
      let previous = null;
      points.forEach(p => {
        const time = Date.parse(p.at), px = x(time), py = y(p.mbps);
        if (previous && p.series_id && previous.series_id === p.series_id && time > previous.time && time - previous.time <= data.max_gap_seconds * 1000) {
          svg.append(svgNode('line', {x1: previous.x, y1: previous.y, x2: px, y2: py, stroke: p.color, 'stroke-width': 2.5, 'stroke-linecap': 'round'}));
        }
        const circle = svgNode('circle', {cx: px, cy: py, r: 3.5, fill: p.color, role: 'button',
          'aria-label': `${p.name}, ${format(p.mbps)} Mbps, ${date(time)}`, 'data-tx-point': p.id + ':' + p.at});
        circle.append(svgNode('title', {}, `${p.name} · ${format(p.mbps)} Mbps · ${date(time)}`));
        circle.addEventListener('click', event => {
          event.stopPropagation();
          selected = {id: p.id, at: p.at};
          chart.focus({preventScroll: true});
          renderChart(); showReading();
        });
        svg.append(circle);
        previous = {...p, time, x: px, y: py};
      });
    });
    if (selected && Date.parse(selected.at) >= lo && Date.parse(selected.at) <= hi) {
      svg.append(svgNode('line', {x1: x(Date.parse(selected.at)), x2: x(Date.parse(selected.at)), y1: top, y2: H - bottom, stroke: '#61738b', 'stroke-dasharray': '4 4', 'pointer-events': 'none'}));
      const point = visiblePoints.find(p => p.id === selected.id && p.at === selected.at);
      if (point) svg.append(svgNode('circle', {cx: x(Date.parse(point.at)), cy: y(point.mbps), r: 7, fill: 'white', stroke: point.color, 'stroke-width': 3, 'pointer-events': 'none'}));
    }
    svg.addEventListener('click', event => {
      const box = svg.getBoundingClientRect();
      const px = (event.clientX - box.left) / box.width * W;
      const py = (event.clientY - box.top) / box.height * H;
      if (px < left || px > W - right || py < top || py > H - bottom) return;
      const candidate = visiblePoints.reduce((best, p) => {
        const distance = (x(Date.parse(p.at)) - px) ** 2 + (y(p.mbps) - py) ** 2;
        return !best || distance < best.distance ? {p, distance} : best;
      }, null);
      if (candidate) {
        selected = {id: candidate.p.id, at: candidate.p.at};
        chart.focus({preventScroll: true}); renderChart(); showReading();
      }
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
    if (selected && !data.series.some(s => s.id === selected.id && s.points.some(p => p.at === selected.at))) selected = null;
    renderLegend(); renderChart(); showReading(); renderOperations();
    root.querySelector('[data-tx-updated]').textContent = `Updated ${new Date(data.updated_at).toLocaleTimeString()}`;
    const live = data.summary.reporting > 0;
    connection.textContent = live ? 'Live' : 'Awaiting TX';
    connection.dataset.state = live ? 'live' : 'waiting';
    root.querySelector('[data-tx-follow]').classList.toggle('is-selected', selected === null);
  }
  chart.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End', 'Escape'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Escape') { selected = null; render(); return; }
    const times = [...new Set(visiblePoints.map(p => p.at))];
    if (!times.length) return;
    let index = selected ? times.indexOf(selected.at) : times.length - 1;
    if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = times.length - 1;
    else index = Math.max(0, Math.min(times.length - 1, index + (event.key === 'ArrowLeft' ? -1 : 1)));
    const point = visiblePoints.find(p => p.at === times[index]);
    selected = {id: point.id, at: point.at}; renderChart(); showReading();
  });
  range.addEventListener('change', () => { selected = null; render(); });
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
    const timeout = setTimeout(() => controller.abort(), 8000);
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
    const timeout = setTimeout(() => controller.abort(), 10000);
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
  document.addEventListener('visibilitychange', () => { if (!document.hidden) update(); });
})();
