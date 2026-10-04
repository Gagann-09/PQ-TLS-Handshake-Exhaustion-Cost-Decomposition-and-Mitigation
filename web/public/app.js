/* ============================================================================
   PQ-TLS Handshake Exhaustion — Chart Rendering
   ============================================================================ */

// Global chart defaults
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