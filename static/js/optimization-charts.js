/* Independent live TX and RTT jitter plots share one measured data feed. */
(() => {
  'use strict';
  const root = document.querySelector('[data-live-tx]');
  if (!root) return;
  const ns = 'http://www.w3.org/2000/svg';
  const colors = ['#215ec3', '#16866e', '#995cc0', '#b6731e'];
  let data = JSON.parse(root.querySelector('[data-tx-payload]').textContent);
  let changesKey = '';
  let fetching = false;
  let samplesFetching = false;
  let sampleCursor = null;
  let controlSaving = false;
  let controlRevision = 0;
  const controlForm = document.querySelector('[data-optimization-control]');
  const toggle = document.querySelector('[data-optimization-toggle]');
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
  const quality = series => series.quality || {state: 'disabled', points: [], interval_seconds: data.sample_interval_seconds};
  const jitterPoints = series => quality(series).points || [];
  const nearest = (points, time) => points.reduce((best, p) => !best || Math.abs(Date.parse(p.at) - time) < Math.abs(Date.parse(best.at) - time) ? p : best, null);

  function makePlot(panel) {
    const metric = panel.dataset.metricPanel;
    const isJitter = metric === 'jitter';
    const unit = isJitter ? 'ms' : 'Mbps';
    const title = isJitter ? 'RTT jitter' : 'Outbound TX';
    const chart = panel.querySelector('[data-plot-chart]');
    const legend = panel.querySelector('[data-plot-series]');
    const range = panel.querySelector('[data-plot-range]');
    const values = panel.querySelector('[data-plot-reading-values]');
    const hidden = new Set();
    const legendNodes = new Map();
    let selected = null;
    let visiblePoints = [];
    let legendKey = '';
    const metadata = series => isJitter ? quality(series) : series;
    const pointsOf = series => isJitter ? jitterPoints(series) : series.points;
    const valueOf = point => isJitter ? point.jitter_ms : point.mbps;
    const currentOf = series => isJitter ? quality(series).current_jitter_ms : series.current_mbps;
    const intervalOf = series => (isJitter ? quality(series).interval_seconds : series.sample_interval_seconds) || data.sample_interval_seconds;
    const enabledSeries = () => data.series.filter(series => !hidden.has(series.id));

    function selectAt(id, at) {
      const time = Date.parse(at);
      const points = new Map(data.series.map(series => {
        let point = nearest(pointsOf(series).filter(p => Number.isFinite(Date.parse(p.at))), time);
        if (point && Math.abs(Date.parse(point.at) - time) > Math.max(.75, intervalOf(series) / 2) * 1000) point = null;
        return [series.id, point ? {...point} : null];
      }));
      selected = {id, at, points};
    }

    function renderLegend() {
      const key = JSON.stringify(data.series.map(s => [s.id, s.name, s.source]));
      if (key !== legendKey) {
        legendKey = key; legend.replaceChildren(); legendNodes.clear();
        data.series.forEach((series, index) => {
          const button = text('button', undefined, 'tx-series-item tx-series-toggle');
          button.type = 'button';
          const label = text('span', series.name, 'tx-series-name');
          const swatch = text('span', undefined, 'tx-swatch');
          swatch.style.backgroundColor = colors[index % colors.length]; label.prepend(swatch);
          const value = text('strong'), state = text('small', undefined, 'tx-series-state');
          button.append(label, value, state);
          button.addEventListener('click', () => {
            if (hidden.has(series.id)) hidden.delete(series.id); else hidden.add(series.id);
            if (selected && hidden.has(selected.id)) selected = null;
            renderPanel();
          });
          legend.append(button); legendNodes.set(series.id, {button, value, state});
        });
      }
      data.series.forEach(series => {
        const item = legendNodes.get(series.id), state = metadata(series).state || 'awaiting';
        item.button.title = isJitter ? `${series.source} → ${quality(series).target || 'No probe target'}` : series.source;
        item.value.textContent = `${format(currentOf(series))} ${unit}`;
        item.state.textContent = !isJitter && state === 'measured' ? 'Receiving' : state.replaceAll('_', ' ');
        item.button.setAttribute('aria-pressed', String(!hidden.has(series.id)));
        item.button.classList.toggle('is-hidden', hidden.has(series.id));
      });
    }

    function showReading() {
      panel.querySelector('[data-plot-reading-label]').textContent = selected ? 'Selected reading' : 'Latest reading';
      const series = enabledSeries();
      const latest = series.flatMap(s => pointsOf(s).slice(-1).map(p => Date.parse(p.at))).filter(Number.isFinite);
      const time = selected ? Date.parse(selected.at) : latest.length ? Math.max(...latest) : null;
      const stamp = panel.querySelector('[data-plot-reading-time]');
      stamp.textContent = time === null ? '—' : date(time);
      if (time !== null) stamp.dateTime = new Date(time).toISOString(); else stamp.removeAttribute('datetime');
      values.replaceChildren();
      series.forEach(s => {
        const candidates = pointsOf(s).filter(p => Number.isFinite(Date.parse(p.at)));
        const point = selected ? selected.points.get(s.id) : candidates.at(-1);
        const value = selected ? point ? valueOf(point) : null : currentOf(s);
        const item = text('div', undefined, 'tx-reading-item');
        item.append(text('span', s.name), text('strong', `${format(value)} ${unit}`));
        const at = selected ? point?.at : metadata(s).sampled_at;
        if (point && at && (selected || Number.isFinite(value))) {
          item.append(text('small', isJitter
            ? `${date(at)} · ${point.target} · ${point.replies}/${point.probes_requested} replies`
            : `${date(at)} · ${s.interface}`));
        } else {
          item.append(text('small', selected ? 'No sample at this time' : `${(metadata(s).state || 'awaiting').replaceAll('_', ' ')}${at ? ' · ' + date(at) : ''}`));
        }
        values.append(item);
      });
    }

    function renderChart() {
      let bridges = 0;
      const gaps = panel.querySelector('[data-plot-gaps]');
      if (gaps) gaps.hidden = true;
      const enabled = enabledSeries(), now = Date.parse(data.updated_at);
      const cutoff = range.value === 'all' ? -Infinity : now - Number(range.value) * 60000;
      visiblePoints = enabled.flatMap(series => pointsOf(series)
        .filter(p => Number.isFinite(valueOf(p)) && Number.isFinite(Date.parse(p.at)) && Date.parse(p.at) >= cutoff)
        .map(p => ({...p, id: series.id, color: colors[data.series.indexOf(series) % colors.length], name: series.name, interval: intervalOf(series)})))
        .sort((a,b) => Date.parse(a.at) - Date.parse(b.at));
      if (!visiblePoints.length) {
        chart.replaceChildren(text('p', data.series.length ? 'No samples in this range' : 'Waiting for readings', 'tx-empty')); return;
      }
      const W = Math.max(320, chart.clientWidth || 920), H = W < 600 ? 260 : 310;
      const left = W < 600 ? 65 : 82, right = 22, top = 24, bottom = 48, ticks = W < 600 ? 2 : 4;
      const hi = Math.max(...visiblePoints.map(p => Date.parse(p.at) + 1000), now);
      const lo = range.value === 'all' ? Math.min(...visiblePoints.map(p => Date.parse(p.at))) : cutoff;
      const maximum = Math.max(0, ...visiblePoints.map(valueOf)), max = maximum > 0 ? maximum * 1.15 : 1;
      const x = t => left + (t - lo) / Math.max(1000, hi - lo) * (W - left - right);
      const y = value => H - bottom - value / max * (H - top - bottom);
      const svg = svgNode('svg', {viewBox: `0 0 ${W} ${H}`, 'aria-label': `${title} in ${unit}`, role: 'group', 'data-plot-metric': metric});
      for (let i = 0; i <= 4; i++) {
        const value = max * i / 4, height = y(value);
        svg.append(svgNode('line', {x1:left, x2:W-right, y1:height, y2:height, stroke:'#e5ebf3'}));
        svg.append(svgNode('text', {x:left-10, y:height+4, 'text-anchor':'end', 'font-size':12}, format(value)));
      }
      for (let i = 0; i <= ticks; i++) {
        const time = lo + (hi-lo) * i / ticks;
        svg.append(svgNode('text', {x:x(time), y:H-17, 'text-anchor':i===0?'start':i===ticks?'end':'middle', 'font-size':12, 'data-plot-time-tick':''},
          new Date(time).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', ...(enabled.some(s=>intervalOf(s)<60)&&hi-lo<=15*60000 ? {second:'2-digit'} : {})})));
      }
      svg.append(svgNode('text', {x:8,y:15,'font-size':12}, unit));
      enabled.forEach(series => {
        let previous = null;
        visiblePoints.filter(p => p.id === series.id).forEach(p => {
          const time = Date.parse(p.at), px = x(time), py = y(valueOf(p));
          const maxGap = isJitter ? p.interval * 3 : data.max_gap_seconds;
          if (previous && time > previous.time) {
            const measured = p.series_id && previous.series_id === p.series_id && time-previous.time<=maxGap*1000;
            const line = svgNode('line', {x1:previous.x,y1:previous.y,x2:px,y2:py,stroke:p.color,'stroke-width':2.5,'stroke-linecap':'round',
              'data-metric-line':metric, ...(isJitter ? {'data-jitter-line':''} : {}),
              ...(!measured ? {'stroke-dasharray':'2 4','stroke-opacity':.55,'data-unmeasured-bridge':''} : {})});
            if (!measured) {
              bridges += 1;
              line.append(svgNode('title', {}, `Visual connector only · no continuous measurements between ${date(previous.time)} and ${date(time)}`));
            }
            svg.append(line);
          }
          const marker = svgNode(isJitter ? 'rect' : 'circle', {
            ...(isJitter ? {x:px-3.5,y:py-3.5,width:7,height:7,'data-jitter-point':p.id+':'+p.at} : {cx:px,cy:py,r:3.5,'data-tx-point':p.id+':'+p.at}),
            fill:isJitter?'white':p.color,stroke:p.color,'stroke-width':1.5,role:'button','data-plot-point':p.id+':'+p.at,
            'aria-label':`${p.name}, ${format(valueOf(p))} ${unit}, ${date(time)}`});
          marker.append(svgNode('title',{},`${p.name} · ${format(valueOf(p))} ${unit} · ${date(time)}`));
          marker.addEventListener('click',event=>{
            event.stopPropagation(); selectAt(p.id,p.at); chart.focus({preventScroll:true}); renderChart(); showReading();
          });
          svg.append(marker); previous={...p,time,x:px,y:py};
        });
      });
      if (selected && Date.parse(selected.at)>=lo && Date.parse(selected.at)<=hi) {
        svg.append(svgNode('line',{x1:x(Date.parse(selected.at)),x2:x(Date.parse(selected.at)),y1:top,y2:H-bottom,stroke:'#61738b','stroke-dasharray':'4 4','pointer-events':'none'}));
        const p=visiblePoints.find(p=>p.id===selected.id&&p.at===selected.at);
        if(p)svg.append(svgNode('circle',{cx:x(Date.parse(p.at)),cy:y(valueOf(p)),r:7,fill:'white',stroke:p.color,'stroke-width':3,'pointer-events':'none'}));
      }
      svg.addEventListener('click',event=>{
        const box=svg.getBoundingClientRect(),px=(event.clientX-box.left)/box.width*W,py=(event.clientY-box.top)/box.height*H;
        if(px<left||px>W-right||py<top||py>H-bottom)return;
        const time=Math.round((lo+(px-left)/(W-left-right)*(hi-lo))/1000)*1000;
        selectAt(enabled[0].id,new Date(time).toISOString()); chart.focus({preventScroll:true}); renderChart(); showReading();
      });
      if (gaps) gaps.hidden = bridges === 0;
      chart.replaceChildren(svg);
    }

    function renderPanel() {
      if(selected&&!data.series.some(s=>s.id===selected.id))selected=null;
      renderLegend(); renderChart(); showReading();
      panel.querySelector('[data-plot-updated]').textContent=`Updated ${new Date(data.updated_at).toLocaleTimeString()}`;
      const intervals=[...new Set(data.series.filter(s=>!isJitter||quality(s).enabled).map(intervalOf))].sort((a,b)=>a-b);
      panel.querySelector('[data-plot-sampling]').textContent=intervals.length?`Samples every ${intervals.join(' / ')}s`:'Monitoring disabled';
      const connection=panel.querySelector('[data-live-connection]'),live=data.series.some(s=>Number.isFinite(currentOf(s)));
      connection.textContent=live?'Live':'Awaiting readings';connection.dataset.state=live?'live':'waiting';
      panel.querySelector('[data-plot-follow]').classList.toggle('is-selected',selected===null);
    }
    chart.addEventListener('keydown',event=>{
      if(!['ArrowLeft','ArrowRight','Home','End','Escape'].includes(event.key))return;
      event.preventDefault();if(event.key==='Escape'){selected=null;renderPanel();return;}
      const times=[...new Set(visiblePoints.map(p=>p.at))];if(!times.length)return;
      let index=selected?times.findIndex(at=>Date.parse(at)>=Date.parse(selected.at)):times.length-1;
      if(index<0)index=times.length-1;
      if(event.key==='Home')index=0;else if(event.key==='End')index=times.length-1;
      else index=Math.max(0,Math.min(times.length-1,index+(event.key==='ArrowLeft'?-1:1)));
      const p=visiblePoints.find(p=>p.at===times[index]);selectAt(p.id,p.at);renderChart();showReading();
    });
    range.addEventListener('change',()=>{selected=null;renderPanel();});
    panel.querySelector('[data-plot-follow]').addEventListener('click',()=>{selected=null;renderPanel();});
    if(typeof ResizeObserver!=='undefined'){
      let width=chart.clientWidth;
      new ResizeObserver(()=>{if(Math.abs(width-chart.clientWidth)>1){width=chart.clientWidth;renderChart();}}).observe(chart);
    }
    return {render:renderPanel};
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

  const plots = [...root.querySelectorAll('[data-metric-panel]')].map(makePlot);
  function render() { plots.forEach(plot => plot.render()); renderOperations(); }
  function setConnections(message, state) {
    root.querySelectorAll('[data-live-connection]').forEach(node => {
      node.textContent = message; node.dataset.state = state;
    });
  }
  render();

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
        setConnections(error.message === 'session' ? 'Session expired' : 'Reconnecting', 'waiting');
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
        setConnections('Reconnecting', 'waiting');
      }
    } finally { clearTimeout(timeout); samplesFetching = false; }
  }
  setInterval(updateSamples, Math.max(1000, Number(root.dataset.sampleRefreshSeconds || data.sample_interval_seconds || 1) * 1000));
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { update(); updateSamples(); } });
})();
