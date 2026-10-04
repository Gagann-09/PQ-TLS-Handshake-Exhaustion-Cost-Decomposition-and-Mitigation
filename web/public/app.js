/* ============================================================================
   PQ-TLS Handshake Exhaustion — Chart Rendering
   ============================================================================ */

// Global chart defaults
const Chart = window.Chart;
Chart.defaults.font.family = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
Chart.defaults.font.size = 12;
Chart.defaults.color = '#3c4043';

const COLORS = {
  C0: '#1a73e8',      // Blue
  C1: '#e65100',      // Orange
  C2: '#2e7d32',      // Green
  C3: '#6a1b9a',      // Purple
  C4: '#c62828',      // Red
  primary: '#1a73e8',
  success: '#2e7d32',
  warning: '#e65100',
  danger: '#c62828'
};

async function loadJSON(path) {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`Failed to load ${path}`);
  return resp.json();
}

// Figure A: CPU/attempt by configuration and workload
async function renderFigureA() {
  const data = await loadJSON('data/figures_phase5.json');
  const figA = data.figure_a;

  const workloads = ['normal_completion', 'controlled_abort'];
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  const labels = ['C0 (X25519+ECDSA)', 'C1 (ML-KEM+ECDSA)', 'C2 (X25519+ML-DSA)', 'C3 (Hybrid+ECDSA)', 'C4 (ML-KEM+ML-DSA)'];

  const datasets = workloads.map((w, wi) => ({
    label: w === 'normal_completion' ? 'W0 (Completed)' : 'W1 (Controlled Abort)',
    data: configs.map(c => figA[w][c].mean * 1000), // convert to ms
    backgroundColor: configs.map(c => COLORS[c] + (wi === 0 ? 'CC' : '80')),
    borderColor: configs.map(c => COLORS[c]),
    borderWidth: 2,
    borderRadius: 4
  }));

  new Chart(document.getElementById('chartFigureA'), {
    type: 'bar',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top' },
        title: { display: true, text: 'Figure A: Server CPU-seconds per Attempted Handshake (ms)', font: { size: 14 } },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.dataset.label}: ${ctx.raw.toFixed(3)} ms`
          }
        }
      },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: 'CPU / attempt (ms)' } }
      }
    }
  });
}

// Figure B: Incremental cost relative to C0
async function renderFigureB() {
  const data = await loadJSON('data/figures_phase5.json');
  const figB = data.figure_b;

  const workloads = ['normal_completion', 'controlled_abort'];
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  const labels = ['C0', 'C1', 'C2', 'C3', 'C4'];

  const datasets = workloads.map((w, wi) => ({
    label: w === 'normal_completion' ? 'W0 Δ vs C0 (ms)' : 'W1 Δ vs C0 (ms)',
    data: configs.map(c => {
      const delta = figB[w][c].delta_vs_C0;
      return delta === 0 ? 0 : delta * 1000;
    }),
    backgroundColor: configs.map(c => {
      const delta = figB[w][c].delta_vs_C0;
      if (delta === 0) return '#9e9e9e';
      return delta > 0 ? COLORS.danger + 'CC' : COLORS.success + 'CC';
    }),
    borderColor: configs.map(c => {
      const delta = figB[w][c].delta_vs_C0;
      if (delta === 0) return '#9e9e9e';
      return delta > 0 ? COLORS.danger : COLORS.success;
    }),
    borderWidth: 2,
    borderRadius: 4
  }));

  new Chart(document.getElementById('chartFigureB'), {
    type: 'bar',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top' },
        title: { display: true, text: 'Figure B: Incremental CPU Cost vs C0 (ms)', font: { size: 14 } },
        tooltip: {
          callbacks: {
            label: ctx => {
              const cfg = configs[ctx.dataIndex];
              const ratio = figB[workloads[ctx.datasetIndex]][cfg].ratio_vs_C0;
              return `${ctx.dataset.label}: ${ctx.raw.toFixed(3)} ms (ratio: ${ratio.toFixed(2)}×)`;
            }
          }
        }
      },
      scales: {
        y: { title: { display: true, text: 'Delta CPU / attempt vs C0 (ms)' } }
      }
    }
  });
}

// Figure C: Key-establishment vs Authentication
async function renderFigureC() {
  const data = await loadJSON('data/figures_phase5.json');
  const figC = data.figure_c;

  const workloads = ['normal_completion', 'controlled_abort'];
  const configs = ['C0', 'C1', 'C2', 'C4'];
  const labels = ['C0 (Classical)', 'C1 (PQ KEM)', 'C2 (PQ Auth)', 'C4 (Both PQ)'];

  const datasets = workloads.map((w, wi) => ({
    label: w === 'normal_completion' ? 'W0 (Completed)' : 'W1 (Controlled Abort)',
    data: configs.map(c => figC[w][c].mean * 1000),
    backgroundColor: configs.map(c => COLORS[c] + 'CC'),
    borderColor: configs.map(c => COLORS[c]),
    borderWidth: 2,
    borderRadius: 4
  }));

  new Chart(document.getElementById('chartFigureC'), {
    type: 'bar',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top' },
        title: { display: true, text: 'Figure C: PQ Key-Establishment vs Authentication Contribution', font: { size: 14 } },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.dataset.label}: ${ctx.raw.toFixed(3)} ms`
          }
        }
      },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: 'CPU / attempt (ms)' } }
      }
    }
  });
}

// Figure D: Key Reuse
async function renderFigureD() {
  const data = await loadJSON('data/figures_phase5.json');
  const figD = data.figure_d;

  new Chart(document.getElementById('chartFigureD'), {
    type: 'bar',
    data: {
      labels: ['Fresh Keypair', 'Reused Keypair (fresh ciphertext)', 'Paired Δ (Reused−Fresh)'],
      datasets: [{
        label: 'CPU / attempt (ms)',
        data: [
          figD.fresh_keypair.mean * 1000,
          figD.reused_client_keypair.mean * 1000,
          figD.paired_delta_reused_minus_fresh.mean * 1000
        ],
        backgroundColor: ['#1a73e8CC', '#e65100CC', '#6a1b9aCC'],
        borderColor: ['#1a73e8', '#e65100', '#6a1b9a'],
        borderWidth: 2,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: { 
          display: true, 
          text: 'Figure D: Fresh vs Reused ML-KEM Keypair (C1×W1) — NULL RESULT (true reuse not implemented)',
          font: { size: 13 }
        },
        tooltip: {
          callbacks: {
            label: ctx => `${ctx.label}: ${ctx.raw.toFixed(4)} ms`
          }
        }
      },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: 'CPU / attempt (ms)' } }
      }
    }
  });
}

// Figure E: Defense Effectiveness
async function renderFigureE() {
  const data = await loadJSON('data/figures_phase7.json');
  const defenses = data.defenses;

  const order = ['D0', 'D1', 'D2', 'D3'];
  const labels = ['D0\nBaseline', 'D1\nHRR (no cookie)', 'D2\nSource Budget (5/s)', 'D3\nD2 + D1'];

  new Chart(document.getElementById('chartFigureE'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Server CPU / attempt (ms)',
        data: order.map(d => defenses[d].cpu_mean_ms),
        backgroundColor: ['#9e9e9eCC', '#e65100CC', '#2e7d32CC', '#6a1b9aCC'],
        borderColor: ['#9e9e9e', '#e65100', '#2e7d32', '#6a1b9a'],
        borderWidth: 2,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        title: { display: true, text: 'Figure E: Defense Effectiveness — CPU Reduction (C1×W1, Phase 7)', font: { size: 14 } },
        tooltip: {
          callbacks: {
            label: ctx => {
              const d = order[ctx.dataIndex];
              const red = d === 'D0' ? '—' : ((defenses[d].cpu_mean_ms - defenses.D0.cpu_mean_ms) / defenses.D0.cpu_mean_ms * 100).toFixed(1) + '%';
              return `CPU/attempt: ${ctx.raw.toFixed(2)} ms (${red} vs D0)`;
            }
          }
        }
      },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: 'CPU / attempt (ms)' } }
      }
    }
  });
}

// Figure F: Legitimate-Client Trade-off
async function renderFigureF() {
  const data = await loadJSON('data/figures_phase7.json');
  const defenses = data.defenses;

  const order = ['D0', 'D1', 'D2', 'D3'];
  const labels = ['D0\nBaseline', 'D1\nHRR (no cookie)', 'D2\nSource Budget (5/s)', 'D3\nD2 + D1'];

  const datasets = [
    {
      label: 'Legitimate Success Rate (%)',
      data: order.map(d => defenses[d].legitimate_success_rate * 100),
      yAxisID: 'y',
      type: 'bar',
      backgroundColor: ['#9e9e9eCC', '#e65100CC', '#2e7d32CC', '#6a1b9aCC'],
      borderColor: ['#9e9e9e', '#e65100', '#2e7d32', '#6a1b9a'],
      borderWidth: 2,
      borderRadius: 4
    },
    {
      label: 'Legitimate p50 Latency (ms)',
      data: order.map(d => defenses[d].legitimate_p50_mean_ms),
      yAxisID: 'y1',
      type: 'line',
      borderColor: '#1a73e8',
      backgroundColor: '#1a73e8',
      borderWidth: 3,
      pointRadius: 6,
      pointBackgroundColor: '#1a73e8',
      tension: 0.2,
      fill: false
    }
  ];

  new Chart(document.getElementById('chartFigureF'), {
    type: 'bar',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top' },
        title: { display: true, text: 'Figure F: Legitimate-Client Trade-off (C1×W1, Phase 7)', font: { size: 14 } },
        tooltip: {
          callbacks: {
            label: ctx => {
              const d = order[ctx.dataIndex];
              if (ctx.dataset.type === 'line') {
                return `p50 Latency: ${ctx.raw.toFixed(1)} ms`;
              }
              return `Success Rate: ${ctx.raw.toFixed(1)}%`;
            }
          }
        }
      },
      scales: {
        y: { 
          type: 'linear', 
          position: 'left', 
          min: 90, 
          max: 105,
          title: { display: true, text: 'Success Rate (%)' }
        },
        y1: { 
          type: 'linear', 
          position: 'right', 
          min: 170, 
          max: 220,
          title: { display: true, text: 'p50 Latency (ms)' },
          grid: { drawOnChartArea: false }
        }
      }
    }
  });
}

// Initialize all charts
async function initCharts() {
  try {
    await Promise.all([
      renderFigureA(),
      renderFigureB(),
      renderFigureC(),
      renderFigureD(),
      renderFigureE(),
      renderFigureF()
    ]);
    console.log('All charts rendered successfully');
  } catch (err) {
    console.error('Chart rendering failed:', err);
    document.querySelectorAll('.chart-container').forEach(el => {
      el.innerHTML = `<div class="alert danger">Failed to load chart data: ${err.message}</div>`;
    });
  }
}

// Smooth scroll for TOC links
document.querySelectorAll('.toc a').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// Active TOC highlighting on scroll
const sections = document.querySelectorAll('main section[id]');
const tocLinks = document.querySelectorAll('.toc a');

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      tocLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === '#' + entry.target.id);
      });
    }
  });
}, { rootMargin: '-100px 0px -60% 0px' });

sections.forEach(section => observer.observe(section));

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', initCharts);

// ============================================================================
// C0–C4 Interactive Explorer
// ============================================================================

import { getExplorerData, getWorkloadLabels } from './data/loader.js';

let explorerData = null;
let currentConfig = 'C0';
let currentWorkload = 'W0';

const CONFIG_LABELS = {
  'C0': 'C0 — X25519 + ECDSA-P256',
  'C1': 'C1 — ML-KEM-768 + ECDSA-P256',
  'C2': 'C2 — X25519 + ML-DSA-65',
  'C3': 'C3 — X25519+ML-KEM-768 (hybrid) + ECDSA-P256',
  'C4': 'C4 — ML-KEM-768 + ML-DSA-65'
};

const WORKLOAD_LABELS = {
  'W0': 'W0 (Completed Handshake)',
  'W1': 'W1 (Controlled Pre-Finished Abort)'
};

function createSegmentedControl(containerId, items, getCurrent, setCurrent, onChange, attr = 'aria-pressed') {
  const container = document.getElementById(containerId);
  if (!container) return;
  
  const render = () => {
    container.innerHTML = items.map(([key, label]) => 
      `<button role="tab" ${attr}="${getCurrent() === key}" data-key="${key}" tabindex="${getCurrent() === key ? '0' : '-1'}">${label}</button>`
    ).join('');
    
    container.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', () => {
        setCurrent(btn.dataset.key);
        onChange();
        render();
      });
      btn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setCurrent(btn.dataset.key);
          onChange();
          render();
        }
      });
    });
  };
  render();
  return render;
}

function renderBars(containerId, configs, workload, valueIndex, unit) {
  const container = document.getElementById(containerId);
  if (!container || !explorerData) return;
  
  const values = configs.map(c => explorerData[c][workload][valueIndex]);
  const maxVal = Math.max(...values);
  
  const configMeta = {
    'C0': { ke: 'X25519', au: 'ECDSA-P256' },
    'C1': { ke: 'ML-KEM-768', au: 'ECDSA-P256' },
    'C2': { ke: 'X25519', au: 'ML-DSA-65' },
    'C3': { ke: 'X25519+ML-KEM-768', au: 'ECDSA-P256' },
    'C4': { ke: 'ML-KEM-768', au: 'ML-DSA-65' }
  };
  
  container.innerHTML = configs.map(cfg => {
    const val = explorerData[cfg][workload][valueIndex];
    const pct = maxVal > 0 ? (val / maxVal * 100) : 0;
    const isSel = cfg === currentConfig;
    const label = `${cfg} (${configMeta[cfg].ke} + ${configMeta[cfg].au})`;
    const displayVal = unit === 's' ? val.toFixed(5) : val.toLocaleString();
    const unitLabel = unit === 's' ? ' s' : ' B';
    
    return `<div class="bar-row${isSel ? ' selected' : ''}" data-config="${cfg}">
      <button class="bar-label" data-config="${cfg}" ${isSel ? 'aria-pressed="true"' : ''} tabindex="${isSel ? '0' : '-1'}">${label}</button>
      <div class="bar-track" role="img" aria-label="${label}: ${displayVal}${unitLabel}">
        <div class="bar-fill" style="width:${Math.max(pct, 0.4)}%"></div>
      </div>
      <span class="bar-value">${displayVal}${unitLabel}</span>
    </div>`;
  }).join('');
  
  // Add click handlers for keyboard accessibility
  container.querySelectorAll('.bar-label').forEach(btn => {
    btn.addEventListener('click', () => {
      currentConfig = btn.dataset.config;
      updateExplorer();
    });
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        currentConfig = btn.dataset.config;
        updateExplorer();
      }
    });
  });
}

function renderTable() {
  const tbody = document.querySelector('#explorer-table tbody');
  if (!tbody || !explorerData) return;
  
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  const workloads = ['W0', 'W1'];
  
  tbody.innerHTML = configs.flatMap(cfg => 
    workloads.map(w => {
      const d = explorerData[cfg][w];
      const isSel = cfg === currentConfig && w === currentWorkload;
      return `<tr class="${isSel ? 'selected' : ''}">
        <td>${cfg}</td>
        <td>${w}</td>
        <td>${d[0].toFixed(5)}</td>
        <td>${d[1].toLocaleString()}</td>
        <td>${d[2].toLocaleString()}</td>
      </tr>`;
    })
  ).join('');
}

function updateExplorer() {
  if (!explorerData) return;
  
  const d = explorerData[currentConfig][currentWorkload];
  const meta = explorerData[currentConfig];
  
  document.getElementById('explorer-config-title').textContent = CONFIG_LABELS[currentConfig];
  document.getElementById('explorer-config-desc').textContent = meta.note;
  document.getElementById('explorer-cpu').textContent = d[0].toFixed(5) + ' s';
  document.getElementById('explorer-rx').textContent = d[1].toLocaleString() + ' B';
  document.getElementById('explorer-tx').textContent = d[2].toLocaleString() + ' B';
  document.getElementById('explorer-ke').textContent = meta.ke;
  document.getElementById('explorer-au').textContent = meta.au;
  document.getElementById('explorer-workload-label').textContent = `(${WORKLOAD_LABELS[currentWorkload]})`;
  
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  renderBars('explorer-cpu-bars', configs, currentWorkload, 0, 's');
  renderBars('explorer-rx-bars', configs, currentWorkload, 1, 'B');
  renderBars('explorer-tx-bars', configs, currentWorkload, 2, 'B');
  renderTable();
}

async function initExplorer() {
  try {
    explorerData = await getExplorerData();
    
    createSegmentedControl('config-segmented', 
      Object.entries(CONFIG_LABELS),
      () => currentConfig,
      (v) => { currentConfig = v; },
      updateExplorer
    );
    
    createSegmentedControl('workload-segmented',
      Object.entries(WORKLOAD_LABELS),
      () => currentWorkload,
      (v) => { currentWorkload = v; },
      updateExplorer
    );
    
    updateExplorer();
  } catch (err) {
    console.error('Explorer initialization failed:', err);
    document.getElementById('explorer').innerHTML += `<div class="alert danger">Failed to load explorer data: ${err.message}</div>`;
  }
}

// Initialize explorer after DOM ready
document.addEventListener('DOMContentLoaded', initExplorer);

// ============================================================================
// D1 HRR Interactive Stepper
// ============================================================================

import { getDefenseSummary } from './data/loader.js';

const D1_STEPS = [
  {
    id: 0,
    title: 'ClientHello 1',
    subtitle: 'Initial client hello',
    details: [
      'Client offers supported_groups: X25519, MLKEM768',
      'Client provides key_share: X25519',
      'No cookie extension (first flight)'
    ],
    direction: 'Client → Server',
    cookieStatus: { text: 'Cookie extension: not applicable (first flight)', type: 'neutral' }
  },
  {
    id: 1,
    title: 'HelloRetryRequest',
    subtitle: 'Server requests different key share',
    details: [
      'RFC 8446 special random observed (HRR indicator)',
      'Server requests key_share: MLKEM768',
      'Stateless cookie extension: ABSENT'
    ],
    direction: 'Server → Client',
    cookieStatus: { text: 'Cookie extension: ABSENT (cookie_observed = false)', type: 'missing' }
  },
  {
    id: 2,
    title: 'ClientHello 2',
    subtitle: 'Client retries with requested key share',
    details: [
      'Client provides key_share: MLKEM768',
      'Cookie extension: ABSENT (server did not provide one)',
      'Handshake validation: 3/3 trials succeeded'
    ],
    direction: 'Client → Server',
    cookieStatus: { text: 'Cookie extension: ABSENT', type: 'missing' }
  },
  {
    id: 3,
    title: 'ServerHello',
    subtitle: 'Handshake completes',
    details: [
      'Negotiated group: MLKEM768',
      'Handshake completed successfully',
      'No stateless cookie mitigation demonstrated'
    ],
    direction: 'Server → Client',
    cookieStatus: { text: 'Handshake complete — no cookie mitigation', type: 'missing' }
  }
];

let currentD1Step = 0;
let d1Metrics = null;

function renderD1Step(stepIndex) {
  const step = D1_STEPS[stepIndex];
  const panel = document.getElementById('step-panel');
  if (!panel) return;
  
  const cookieClass = step.cookieStatus.type === 'missing' ? 'missing' : 
                      step.cookieStatus.type === 'present' ? 'present' : 'neutral';
  
  panel.innerHTML = `
    <div class="step-detail">
      <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem;">
        <span style="display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:50%;background:${currentD1Step === stepIndex ? 'var(--color-primary)' : 'var(--color-border)'};color:${currentD1Step === stepIndex ? 'white' : 'var(--color-text-secondary)'};font-weight:600;">${step.id + 1}</span>
        <div>
          <h4>${step.title}</h4>
          <p style="margin:0;color:var(--color-text-secondary);font-size:0.9rem;">${step.subtitle}</p>
        </div>
      </div>
      <p style="margin-bottom:1rem;"><strong>Direction:</strong> <code>${step.direction}</code></p>
      <ul style="margin-left:1.5rem;margin-bottom:1rem;color:var(--color-text-secondary);">
        ${step.details.map(d => `<li>${d}</li>`).join('')}
      </ul>
      <div class="cookie-status ${cookieClass}">
        <span>●</span>
        <span>${step.cookieStatus.text}</span>
      </div>
    </div>
  `;
  
  // Update step buttons
  document.querySelectorAll('.step-btn').forEach(btn => {
    const stepNum = parseInt(btn.dataset.step, 10);
    const isSelected = stepNum === stepIndex;
    btn.setAttribute('aria-selected', isSelected);
    if (isSelected) {
      btn.querySelector('.step-num').style.background = 'var(--color-primary)';
      btn.querySelector('.step-num').style.color = 'white';
      btn.querySelector('.step-title').style.color = 'var(--color-primary)';
      btn.querySelector('.step-title').style.fontWeight = '600';
    } else {
      btn.querySelector('.step-num').style.background = 'var(--color-border)';
      btn.querySelector('.step-num').style.color = 'var(--color-text-secondary)';
      btn.querySelector('.step-title').style.color = 'var(--color-text-secondary)';
      btn.querySelector('.step-title').style.fontWeight = '500';
    }
  });
}

function renderD1Metrics() {
  const container = document.getElementById('d1-metrics');
  if (!container || !d1Metrics) return;
  
  const d1 = d1Metrics.D1;
  const d0 = d1Metrics.D0;
  
  container.innerHTML = `
    <div class="d1-metric">
      <dt>CPU / attempt</dt>
      <dd>${d1.cpu.toFixed(6)} s</dd>
    </div>
    <div class="d1-metric">
      <dt>CPU vs D0 (ratio)</dt>
      <dd class="warning">${d1.ratio.toFixed(3)}×</dd>
    </div>
    <div class="d1-metric">
      <dt>CPU increase vs D0</dt>
      <dd class="critical">+${((d1.ratio - 1) * 100).toFixed(1)}%</dd>
    </div>
    <div class="d1-metric">
      <dt>Legitimate success rate</dt>
      <dd>${d1.ok.toFixed(1)}%</dd>
    </div>
    <div class="d1-metric">
      <dt>Legitimate p50 latency</dt>
      <dd>~${d1.p50.toFixed(0)} ms</dd>
    </div>
    <div class="d1-metric">
      <dt>Cookie observed</dt>
      <dd class="critical" style="font-size:0.9rem;">false</dd>
    </div>
  `;
}

function initD1Stepper() {
  const stepButtons = document.querySelectorAll('.step-btn');
  if (!stepButtons.length) return;
  
  stepButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      currentD1Step = parseInt(btn.dataset.step, 10);
      renderD1Step(currentD1Step);
    });
    
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        const steps = Array.from(stepButtons);
        const currentIndex = steps.findIndex(b => b === btn);
        let nextIndex;
        if (e.key === 'ArrowRight') {
          nextIndex = (currentIndex + 1) % steps.length;
        } else {
          nextIndex = (currentIndex - 1 + steps.length) % steps.length;
        }
        steps[nextIndex].focus();
        currentD1Step = parseInt(steps[nextIndex].dataset.step, 10);
        renderD1Step(currentD1Step);
      } else if (e.key === 'Home') {
        e.preventDefault();
        stepButtons[0].focus();
        currentD1Step = 0;
        renderD1Step(0);
      } else if (e.key === 'End') {
        e.preventDefault();
        stepButtons[stepButtons.length - 1].focus();
        currentD1Step = stepButtons.length - 1;
        renderD1Step(currentD1Step);
      }
    });
  });
  
  // Initial render
  renderD1Step(0);
  
  // Load D1 metrics
  getDefenseSummary().then(summary => {
    d1Metrics = summary;
    renderD1Metrics();
  }).catch(err => {
    console.error('Failed to load D1 metrics:', err);
  });
}

// Initialize D1 stepper after DOM ready
document.addEventListener('DOMContentLoaded', initD1Stepper);

// ============================================================================
// D0–D3 Defense Explorer
// ============================================================================

import { getDefenseSummary } from './data/loader.js';

const DEFENSE_LABELS = {
  'D0': { id: 'D0', name: 'Baseline', description: 'No admission control' },
  'D1': { id: 'D1', name: 'HRR (no cookie)', description: 'Stateless HRR via openssl s_server -stateless; cookie_observed=false' },
  'D2': { id: 'D2', name: 'Source Budget', description: 'Userspace proxy with token bucket (5 tokens, 5/sec refill)' },
  'D3': { id: 'D3', name: 'Combined', description: 'Proxy (D2) → stateless server (D1)' }
};

let currentDefense = 'D0';
let defenseData = null;

function renderDefenseDetail(defenseId) {
  const container = document.getElementById('defense-detail');
  if (!container || !defenseData) return;
  
  const d = defenseData[defenseId];
  const label = DEFENSE_LABELS[defenseId];
  const isD0 = defenseId === 'D0';
  
  // Format CPU ratio
  let ratioHtml = '';
  if (isD0) {
    ratioHtml = '<dd>— (reference)</dd>';
  } else {
    const ratioClass = d.ratio < 1 ? 'reduction' : 'increase';
    const pct = ((1 - d.ratio) * 100).toFixed(1);
    ratioHtml = `<dd class="${ratioClass}">${d.ratio.toFixed(3)}× (${pct}% ${d.ratio < 1 ? 'reduction' : 'increase'})</dd>`;
  }
  
  // Format CPU per attempt
  const cpuHtml = `<dd>${d.cpu.toFixed(6)} s (${d.cpu_ms.toFixed(1)} ms)</dd>`;
  
  // Format legitimate success
  const successHtml = `<dd>${d.ok.toFixed(1)}%</dd>`;
  
  // Format p50 latency
  const latencyHtml = d.p50 ? `<dd>${d.p50.toFixed(0)} ms</dd>` : `<dd class="unavailable">TBD / not measured</dd>`;
  
  // Format accepted/rejected
  let accRejHtml = '';
  if (d.acc !== null && d.rej !== null) {
    accRejHtml = `
      <dt>Accepted at TLS</dt><dd>${d.acc.toLocaleString()}</dd>
      <dt>Rejected at proxy</dt><dd>${d.rej.toLocaleString()}</dd>
    `;
  } else if (defenseId === 'D1') {
    accRejHtml = `<dt>Accepted/Rejected</dt><dd class="unavailable">Not applicable (HRR behavior only; no ingress proxy)</dd>`;
  } else {
    accRejHtml = `<dt>Accepted/Rejected</dt><dd class="unavailable">— (baseline)</dd>`;
  }
  
  // Cookie status
  const cookieHtml = defenseId === 'D1' 
    ? `<dd class="cookie-false">false</dd>`
    : defenseId === 'D0'
      ? `<dd class="unavailable">N/A (no admission control)</dd>`
      : `<dd class="unavailable">N/A (proxy-level admission control)</dd>`;
  
  container.innerHTML = `
    <div class="defense-metric">
      <dt>Defense</dt><dd>${label.id} — ${label.name}</dd>
    </div>
    <div class="defense-metric">
      <dt>Mechanism</dt><dd>${label.description}</dd>
    </div>
    <div class="defense-metric">
      <dt>CPU / attempt</dt>${cpuHtml}
    </div>
    <div class="defense-metric">
      <dt>CPU ratio vs D0</dt>${ratioHtml}
    </div>
    <div class="defense-metric">
      <dt>Legitimate success rate</dt>${successHtml}
    </div>
    <div class="defense-metric">
      <dt>Legitimate p50 latency</dt>${latencyHtml}
    </div>
    <div class="defense-metric">
      ${accRejHtml}
    </div>
    <div class="defense-metric">
      <dt>Cookie observed</dt>${cookieHtml}
    </div>
  `;
}

function renderComparisonBars(defenseId) {
  const container = document.getElementById('comparison-bars');
  if (!container || !defenseData) return;
  
  const defenses = ['D0', 'D1', 'D2', 'D3'];
  const d0Cpu = defenseData.D0.cpu;
  
  container.innerHTML = defenses.map(d => {
    if (d === 'D0') return ''; // Skip D0 in comparison
    const data = defenseData[d];
    const ratio = data.ratio;
    const pct = Math.abs((1 - ratio) * 100);
    const isReduction = ratio < 1;
    const fillClass = isReduction ? 'reduction' : 'increase';
    const label = `${d} vs D0`;
    const valueText = `${ratio.toFixed(3)}× (${isReduction ? '−' : '+'}${pct.toFixed(1)}%)`;
    // Bar width: for D0=1.0, D1=1.034, D2=0.121, D3=0.128
    // We want to show the ratio visually, capped at reasonable width
    const barWidth = Math.min(ratio, 1.5) * 66.66; // Scale so 1.0 = ~67%, 1.5 = 100%
    
    return `
      <div class="comparison-bar">
        <span class="comparison-bar-label">${label}</span>
        <div class="comparison-bar-track" role="img" aria-label="${label}: ${valueText}">
          <div class="comparison-bar-fill ${fillClass}" style="width:${barWidth}%"></div>
        </div>
        <span class="comparison-bar-value ${isReduction ? 'reduction' : 'increase'}">${valueText}</span>
      </div>
    `;
  }).join('');
}

function renderDefenseBadges(defenseId) {
  const container = document.getElementById('defense-badges');
  if (!container || !defenseData) return;
  
  const d = defenseData[defenseId];
  const badges = [];
  
  if (defenseId === 'D0') {
    badges.push('<span class="badge" style="background:var(--color-primary-light);color:var(--color-primary);border-color:var(--color-primary)">Baseline</span>');
  }
  
  if (defenseId === 'D1') {
    badges.push('<span class="badge badge-warning">HRR Observed</span>');
    badges.push('<span class="badge" style="background:var(--color-danger-light);color:var(--color-danger);border-color:var(--color-danger)">Cookie NOT Observed</span>');
    badges.push('<span class="badge" style="background:var(--color-danger-light);color:var(--color-danger);border-color:var(--color-danger)">No CPU Reduction</span>');
  }
  
  if (defenseId === 'D2') {
    badges.push('<span class="badge badge-ok">~88% CPU Reduction</span>');
    badges.push('<span class="badge badge-ok">100% Legitimate Success</span>');
    badges.push('<span class="badge" style="background:var(--color-primary-light);color:var(--color-primary);border-color:var(--color-primary)">Proxy Admission Control</span>');
  }
  
  if (defenseId === 'D3') {
    badges.push('<span class="badge badge-ok">~87% CPU Reduction</span>');
    badges.push('<span class="badge badge-ok">100% Legitimate Success</span>');
    badges.push('<span class="badge" style="background:var(--color-warning-light);color:var(--color-warning);border-color:var(--color-warning)">No Added Benefit vs D2</span>');
  }
  
  container.innerHTML = badges.join('');
}

function updateDefenseExplorer(defenseId) {
  currentDefense = defenseId;
  renderDefenseDetail(defenseId);
  renderComparisonBars(defenseId);
  renderDefenseBadges(defenseId);
  
  // Update button states
  document.querySelectorAll('.defense-btn').forEach(btn => {
    const isSelected = btn.dataset.defense === defenseId;
    btn.setAttribute('aria-selected', isSelected);
  });
}

function initDefenseExplorer() {
  const buttons = document.querySelectorAll('.defense-btn');
  if (!buttons.length) return;
  
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      updateDefenseExplorer(btn.dataset.defense);
    });
    
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        const btns = Array.from(buttons);
        const currentIndex = btns.findIndex(b => b === btn);
        let nextIndex;
        if (e.key === 'ArrowRight') {
          nextIndex = (currentIndex + 1) % btns.length;
        } else {
          nextIndex = (currentIndex - 1 + btns.length) % btns.length;
        }
        btns[nextIndex].focus();
        updateDefenseExplorer(btns[nextIndex].dataset.defense);
      } else if (e.key === 'Home') {
        e.preventDefault();
        buttons[0].focus();
        updateDefenseExplorer('D0');
      } else if (e.key === 'End') {
        e.preventDefault();
        buttons[buttons.length - 1].focus();
        updateDefenseExplorer('D3');
      }
    });
  });
  
  // Load defense data
  getDefenseSummary().then(summary => {
    defenseData = summary;
    renderDefenseDetail(currentDefense);
    renderComparisonBars(currentDefense);
    renderDefenseBadges(currentDefense);
  }).catch(err => {
    console.error('Failed to load defense data:', err);
    document.getElementById('defense-explorer').innerHTML += `<div class="alert danger">Failed to load defense data: ${err.message}</div>`;
  });
}

// Initialize defense explorer after DOM ready
document.addEventListener('DOMContentLoaded', initDefenseExplorer);

// ============================================================================
// Architecture Node Inspector
// ============================================================================

const ARCH_NODES = [
  {
    id: 'controller',
    label: 'Experiment Controller',
    icon: '🎮',
    description: 'Orchestrates the experiment matrix, enforces safety limits, manages trial repetitions, and coordinates logging.',
    role: 'Coordinates all experimental runs; enforces hard ceilings (1000 attempts, 30 s, concurrency 1); generates experiment matrix from config YAML.',
    inputs: 'Configuration YAML (config/*.yaml), safety limits (config/safety_limits.yaml)',
    outputs: 'Experiment matrix, trial parameters, run manifests, aggregated results',
    evidence: 'Safety boundary enforcement (test_preflight.py), matrix execution (scripts/run_phase*.py), result aggregation (scripts/run_analysis.py)',
    methodology: 'Central authority — ensures bounded, reproducible execution; no network-facing attack logic.'
  },
  {
    id: 'workload',
    label: 'Controlled TLS Workload',
    icon: '⚡',
    description: 'Executes bounded handshake attempts against the TLS server under test. Two workload modes.',
    role: 'Generates the controlled handshake-exhaustion load; runs only W0 (normal_completion) or W1 (controlled_abort).',
    inputs: 'Experiment controller trial parameters (config, workload mode, attempt count, duration)',
    outputs: 'Handshake attempts, ClientHello/Finished transcripts, connection outcomes (success/abort/error)',
    evidence: 'Handshake outcomes per run (attempt count, duration, negotiated cipher suite); workload behavior validated (test_f02_controlled_abort.py)',
    methodology: 'Bounded by design — 1000 attempts max, 30 s max, concurrency 1; pre-Finished abort for W1 (not a completion variant).'
  },
  {
    id: 'legitimate',
    label: 'Legitimate TLS Client',
    icon: '✅',
    description: 'Independent client path measuring legitimate-client availability under each defense mode.',
    role: 'Measures legitimate-client success rate and latency (RQ5) by running steady background traffic (≈1 req/s) through the same admission layer.',
    inputs: 'Same admission layer as workload (D0–D3); steady 1 req/s rate',
    outputs: 'Legitimate success rate, p50/p95 latency, connection establishment confirmation',
    evidence: 'Legitimate-client success rate and latency recorded per defense trial (Phase 7: D0–D3 × 3 trials); independent of workload intensity',
    methodology: 'Availability baseline — not part of the exhaustion load; measures defense impact on legitimate traffic (RQ5).'
  },
  {
    id: 'network',
    label: 'Laboratory Network',
    icon: '🔗',
    description: 'Docker bridge network isolating the testbed. localhost-only, no public routing.',
    role: 'Provides the isolated network path between clients and server; enforces localhost-only connectivity.',
    inputs: 'Docker Compose network configuration (lab/network/docker-compose*.yml)',
    outputs: 'Network-level isolation; all traffic confined to Docker bridge; no external routing',
    evidence: 'Target allowlist enforced (localhost, 127.0.0.1, ::1, Docker service names only); Docker Desktop bridge on host',
    methodology: 'Bounded environment — single-source IP, localhost/Docker only; no NAT, no middleboxes, no Internet path.'
  },
  {
    id: 'tls-server',
    label: 'TLS 1.3 Server',
    icon: '🔐',
    description: 'OpenSSL 3.5+ TLS server handling all handshakes. Configurations C0–C4, defense modes D0–D3.',
    role: 'The system under test — processes handshakes from both workload and legitimate clients; CPU cost measured here.',
    inputs: 'ClientHello from workload/legitimate clients; defense layer admission decisions; configuration (C0–C4) and defense mode (D0–D3)',
    outputs: 'ServerHello, HelloRetryRequest (D1), handshake completion or termination; TLS transcripts (negotiated group, signature, outcome)',
    evidence: 'pidstat CPU per server process; TLS event logs; handshake validation (3/3 trials per campaign run); D1 cookie_observed=false',
    methodology: 'Single OpenSSL 3.5.x build per campaign; native ML-KEM-768/ML-DSA-65 support via default provider; no oqs-provider.'
  },
  {
    id: 'instrumentation',
    label: 'Instrumentation',
    icon: '📊',
    description: 'Three independent evidence streams converging on measurement results.',
    role: 'Collects and correlates the three evidence streams — no single stream proxies another.',
    inputs: 'TLS server process (pidstat), wire capture (tcpdump), TLS handshake events (transcripts)',
    outputs: 'CPU-seconds per attempt (pidstat), RX/TX bytes per attempt (tcpdump), negotiated parameters and outcomes (TLS events)',
    evidence: 'Measurement Triangle: (1) TLS events — negotiated group, signature, outcome; (2) CPU process cost — pidstat per server PID; (3) Wire bytes — tcpdump capture',
    methodology: 'Triangulation — each stream independently validates; convergent evidence required for reported results; no stream is a proxy for another.'
  }
];

let currentArchNode = 'controller';

function renderArchNodes() {
  const container = document.getElementById('arch-nodes');
  if (!container) return;
  
  container.innerHTML = ARCH_NODES.map(node => `
    <button class="arch-node${node.id === currentArchNode ? ' selected' : ''}" 
            role="tab" 
            aria-selected="${node.id === currentArchNode}" 
            data-node="${node.id}"
            aria-controls="arch-detail"
            tabindex="${node.id === currentArchNode ? '0' : '-1'}">
      <span class="arch-node-icon" aria-hidden="true">${node.icon}</span>
      <span class="arch-node-label">${node.label}</span>
    </button>
  `).join('');
  
  container.querySelectorAll('.arch-node').forEach(btn => {
    btn.addEventListener('click', () => {
      currentArchNode = btn.dataset.node;
      renderArchNodes();
      renderArchDetail(currentArchNode);
    });
    
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        currentArchNode = btn.dataset.node;
        renderArchNodes();
        renderArchDetail(currentArchNode);
      } else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        const nodes = Array.from(container.querySelectorAll('.arch-node'));
        const currentIndex = nodes.findIndex(b => b === btn);
        let nextIndex;
        if (e.key === 'ArrowRight') {
          nextIndex = (currentIndex + 1) % nodes.length;
        } else {
          nextIndex = (currentIndex - 1 + nodes.length) % nodes.length;
        }
        nodes[nextIndex].focus();
        currentArchNode = nodes[nextIndex].dataset.node;
        renderArchNodes();
        renderArchDetail(currentArchNode);
      } else if (e.key === 'Home') {
        e.preventDefault();
        const first = container.querySelector('.arch-node');
        if (first) {
          first.focus();
          currentArchNode = first.dataset.node;
          renderArchNodes();
          renderArchDetail(currentArchNode);
        }
      } else if (e.key === 'End') {
        e.preventDefault();
        const nodes = container.querySelectorAll('.arch-node');
        const last = nodes[nodes.length - 1];
        if (last) {
          last.focus();
          currentArchNode = last.dataset.node;
          renderArchNodes();
          renderArchDetail(currentArchNode);
        }
      }
    });
  });
}

function renderArchDetail(nodeId) {
  const container = document.getElementById('arch-detail');
  if (!container) return;
  
  const node = ARCH_NODES.find(n => n.id === nodeId);
  if (!node) return;
  
  container.innerHTML = `
    <h4>${node.icon} ${node.label}</h4>
    <p style="margin-bottom:1rem;color:var(--color-text-secondary);">${node.description}</p>
    
    <div class="arch-detail-field">
      <dt>Role in Experiment</dt>
      <dd>${node.role}</dd>
    </div>
    
    <div class="arch-detail-field">
      <dt>Inputs</dt>
      <dd>${node.inputs}</dd>
    </div>
    
    <div class="arch-detail-field">
      <dt>Outputs</dt>
      <dd>${node.outputs}</dd>
    </div>
    
    <div class="arch-detail-field">
      <dt>Evidence Collected</dt>
      <dd>${node.evidence}</dd>
    </div>
    
    <div class="arch-detail-field">
      <dt>Methodology Note</dt>
      <dd>${node.methodology}</dd>
    </div>
    
    <div class="arch-evidence-flow">
      <dt>Evidence Stream(s) Involved</dt>
      <dd>${getEvidenceStreams(nodeId)}</dd>
    </div>
  `;
}

function getEvidenceStreams(nodeId) {
  const streams = {
    controller: 'TLS events (configuration), CPU process cost (controller overhead), Wire bytes (controller logs)',
    workload: 'TLS events (handshake outcomes), CPU process cost (workload client), Wire bytes (workload traffic)',
    legitimate: 'TLS events (legitimate handshakes), CPU process cost (negligible), Wire bytes (legitimate traffic)',
    network: 'TLS events (network-level), CPU process cost (N/A), Wire bytes (network capture)',
    'tls-server': 'TLS events (negotiated params), CPU process cost (pidstat — primary), Wire bytes (server TX/RX)',
    instrumentation: 'TLS events (stream 1), CPU process cost (stream 2), Wire bytes (stream 3) — all three'
  };
  return streams[nodeId] || '—';
}

function initArchInspector() {
  const container = document.getElementById('arch-nodes');
  if (!container) return;
  
  renderArchNodes();
  renderArchDetail(currentArchNode);
}

// Initialize architecture inspector after DOM ready
document.addEventListener('DOMContentLoaded', initArchInspector);

// ============================================================================
// Engineering Failures & Remediation Accordion
// ============================================================================

const ENGINEERING_FAILURES = [
  {
    id: 'F-01',
    title: 'Configuration values were being inferred instead of observed',
    problem: 'TLS negotiation values were initially inferred from configuration rather than parsed from actual handshake transcripts. The system assumed that configured values (e.g., C1 = ML-KEM-768) would match negotiated values.',
    whyItMattered: 'In TLS 1.3, the negotiated cipher suite and key exchange group depend on both client and server capabilities. A configuration may specify ML-KEM-768, but if the peer does not support it, the handshake will negotiate a different group. Measurements must reflect what actually occurred on the wire, not what was configured.',
    remediation: 'Introduced NegotiationObservation parsing from OpenSSL transcripts. All negotiated parameters (cipher suite, key exchange group, signature algorithm) are now extracted from the observed handshake. Unobserved fields are left null rather than inferred from configuration. Validation tests (test_f01_tls_provenance.py) ensure configuration ≠ observation is enforced.',
    result: 'All reported configurations now reflect actual negotiated values. Any mismatch between configuration and observation is flagged. This was a measurement validity correction, not a TLS vulnerability.'
  },
  {
    id: 'F-02',
    title: 'W1 workload was completing the handshake',
    problem: 'The workload mode labeled "controlled_abort" (W1) was initially implemented such that the TLS handshake could complete. The client sent ClientHello and then continued through to Finished instead of aborting pre-Finished.',
    whyItMattered: 'W1 is defined as a pre-Finished abort workload to measure server-side cost before expensive cryptographic verification. If the handshake completes, the measurement includes signature verification cost, conflating W1 with W0 and invalidating the pre-completion cost decomposition (RQ2).',
    remediation: 'Modified the client workload (src/workload/client.py) to use do_handshake_on_connect=False with non-blocking sockets. The client now sends ClientHello and closes the connection before the server can send ServerHello/Finished. Validated by test_f02_controlled_abort.py which confirms W1 aborts pre-Finished.',
    result: 'W1 now correctly represents pre-completion server cost. Measurements show C2 and C3 have lower pre-completion cost than C0 (server aborts before ML-DSA verification), while C4 remains high (both ML-KEM encapsulation and ML-DSA verification occur pre-Finished). This was a workload behavior correction, not a TLS vulnerability.'
  },
  {
    id: 'F-03',
    title: 'Packet capture termination was not properly bounded',
    problem: 'tcpdump lifecycle and termination were not reliably managed. The capture could continue beyond the experiment window or fail to stop cleanly, making packet totals unreliable.',
    whyItMattered: 'RX/TX bytes per attempt must correspond exactly to the bounded experiment window (1000 attempts, 30 seconds). Unbounded capture could include extraneous traffic or miss tail packets, invalidating wire-byte measurements.',
    remediation: 'Implemented bounded background capture with explicit lifecycle: (1) start tcpdump before workload, (2) confirm process alive, (3) run workload within timeout, (4) explicit stop/join, (5) copy pcap, (6) parse, (7) cleanup. If any step fails, measurements are marked unavailable (null) rather than fabricated as zero. Validated by test_f03_packet_capture.py.',
    result: 'Wire-byte measurements now correspond strictly to the experiment window. Measurement failures are reported as "TBD / not measured" in the data layer, not as zero values. This was a measurement integrity correction, not a TLS vulnerability.'
  },
  {
    id: 'F-04',
    title: 'Controller/instrumentation integration could fabricate zero values',
    problem: 'Instrumentation (CPU sampling, packet capture, TLS event logging) was not initially correctly wired into the controller lifecycle. Missing measurements could result in zero-valued results being recorded instead of being flagged as unavailable.',
    whyItMattered: 'A zero CPU measurement or zero byte count is scientifically different from "measurement failed" or "not available." Fabricated zeros would invalidate cost decomposition and defense effectiveness calculations.',
    remediation: 'Restructured the controller to explicitly start/stop all instrumentation around the workload execution window. CPU sampling (pidstat), packet capture (tcpdump), and TLS event logging are now lifecycle-coupled to the trial. Any measurement failure results in null/unavailable in the data layer, with explicit "unavailable" rendering in the UI. Validated by test_f04_controller_integration.py and test_f05_cpu_sampling.py.',
    result: 'All reported measurements are either valid observations or explicitly unavailable. No fabricated zeros appear in campaign data. This was a measurement pipeline integrity correction, not a TLS vulnerability.'
  }
];

function renderEngineeringAccordion() {
  const container = document.querySelector('.accordion-list');
  if (!container) return;
  
  container.innerHTML = ENGINEERING_FAILURES.map((failure, index) => `
    <div class="accordion-item">
      <button class="accordion-header" 
              aria-expanded="false" 
              aria-controls="accordion-content-${failure.id}"
              data-failure="${failure.id}"
              id="accordion-header-${failure.id}">
        <span class="accordion-id">${failure.id}</span>
        <span class="accordion-title">${failure.title}</span>
        <svg class="accordion-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M6 9l6 6 6-6"/>
        </svg>
      </button>
      <div class="accordion-content" 
           id="accordion-content-${failure.id}" 
           role="region" 
           aria-labelledby="accordion-header-${failure.id}"
           aria-hidden="true">
        <div class="accordion-section">
          <div class="accordion-section-title">Problem</div>
          <p>${failure.problem}</p>
        </div>
        <div class="accordion-section">
          <div class="accordion-section-title">Why It Invalidated the Measurement</div>
          <p>${failure.whyItMattered}</p>
        </div>
        <div class="accordion-section">
          <div class="accordion-section-title">Remediation</div>
          <p>${failure.remediation}</p>
        </div>
        <div class="accordion-result">
          <div class="accordion-result-title">Result</div>
          <p>${failure.result}</p>
        </div>
      </div>
    </div>
  `).join('');
  
  // Add click/keyboard handlers
  container.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
      toggleAccordion(header);
    });
    
    header.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleAccordion(header);
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        const headers = Array.from(container.querySelectorAll('.accordion-header'));
        const currentIndex = headers.findIndex(h => h === header);
        if (currentIndex < headers.length - 1) {
          headers[currentIndex + 1].focus();
        }
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        const headers = Array.from(container.querySelectorAll('.accordion-header'));
        const currentIndex = headers.findIndex(h => h === header);
        if (currentIndex > 0) {
          headers[currentIndex - 1].focus();
        }
      } else if (e.key === 'Home') {
        e.preventDefault();
        const first = container.querySelector('.accordion-header');
        if (first) first.focus();
      } else if (e.key === 'End') {
        e.preventDefault();
        const headers = container.querySelectorAll('.accordion-header');
        if (headers.length > 0) headers[headers.length - 1].focus();
      }
    });
  });
}

function toggleAccordion(header) {
  const isExpanded = header.getAttribute('aria-expanded') === 'true';
  const contentId = header.getAttribute('aria-controls');
  const content = document.getElementById(contentId);
  
  header.setAttribute('aria-expanded', !isExpanded);
  if (content) {
    content.setAttribute('aria-hidden', isExpanded);
  }
}

function initEngineeringAccordion() {
  const container = document.querySelector('.accordion-list');
  if (!container) return;
  
  renderEngineeringAccordion();
}

// Initialize engineering accordion after DOM ready
document.addEventListener('DOMContentLoaded', initEngineeringAccordion);

// ============================================================================
// Mobile Navigation
// ============================================================================

function initMobileNav() {
  const menuBtn = document.getElementById('toc-menu-btn');
  const tocList = document.getElementById('toc-list');
  
  if (!menuBtn || !tocList) return;
  
  function closeMenu() {
    tocList.classList.remove('open');
    menuBtn.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }
  
  function openMenu() {
    tocList.classList.add('open');
    menuBtn.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
    // Focus first menu item
    const firstLink = tocList.querySelector('a');
    if (firstLink) firstLink.focus();
  }
  
  function toggleMenu() {
    const isOpen = tocList.classList.contains('open');
    if (isOpen) {
      closeMenu();
    } else {
      openMenu();
    }
  }
  
  menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleMenu();
  });
  
  // Close menu when clicking a link
  tocList.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      closeMenu();
    });
  });
  
  // Close menu on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && tocList.classList.contains('open')) {
      closeMenu();
      menuBtn.focus();
    }
  });
  
  // Close menu when clicking outside
  document.addEventListener('click', (e) => {
    if (tocList.classList.contains('open') && 
        !tocList.contains(e.target) && 
        !menuBtn.contains(e.target)) {
      closeMenu();
    }
  });
  
  // Handle resize - close menu if window grows
  window.addEventListener('resize', () => {
    if (window.innerWidth > 768 && tocList.classList.contains('open')) {
      closeMenu();
    }
  });
}

// Initialize mobile nav after DOM ready
document.addEventListener('DOMContentLoaded', initMobileNav);