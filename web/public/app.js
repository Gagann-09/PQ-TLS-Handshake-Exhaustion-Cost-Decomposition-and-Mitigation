import { getExplorerData, getDecompositionData, getDefenseSummary } from './data/loader.js';

// Global state
const state = {
  config: 'C0',
  workload: 'W0',
  decompScope: 'baseline',
  decompWorkload: 'W0',
  d2Mode: 'D0'
};

let explorerData = null;
let decompData = null;
let defenseData = null;
let challengesData = null;

async function init() {
  try {
    // Load data
    explorerData = await getExplorerData();
    decompData = await getDecompositionData();
    defenseData = await getDefenseSummary();
    
    const chalResp = await fetch('data/challenges.json');
    challengesData = await chalResp.json();

    // Bind Navigation
    bindNavigation();
    
    // Bind Controls
    bindControls();

    // Setup Global Toggle
    setupGlobalToggle();

    // Initial Renders
    updateAllViews();
    renderAudit();
  } catch (err) {
    console.error('Failed to initialize dashboard:', err);
  }
}

function setupGlobalToggle() {
  document.body.classList.add('mode-evidence');
  const toggle = document.getElementById('global-mode-toggle');
  if (toggle) {
    toggle.addEventListener('change', (e) => {
      if (e.target.checked) {
        document.body.classList.add('mode-hypothetical');
        document.body.classList.remove('mode-evidence');
        document.getElementById('sidebar-mode-badge').textContent = 'HYPOTHETICAL MODE';
        document.getElementById('sidebar-mode-badge').className = 'badge badge-warning';
        document.getElementById('label-ev').classList.remove('active');
        document.getElementById('label-hy').classList.add('active');
        // Activate simulator tab
        document.querySelector('.nav-link-hypo').click();
        initSimulator();
      } else {
        document.body.classList.add('mode-evidence');
        document.body.classList.remove('mode-hypothetical');
        document.getElementById('sidebar-mode-badge').textContent = 'EVIDENCE MODE';
        document.getElementById('sidebar-mode-badge').className = 'badge badge-evidence';
        document.getElementById('label-ev').classList.add('active');
        document.getElementById('label-hy').classList.remove('active');
        // Activate Overview tab
        document.querySelector('.nav-link[data-target="overview"]').click();
      }
    });
  }
}

function bindNavigation() {
  const links = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('.dashboard-section');
  const title = document.getElementById('top-bar-title');

  links.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      
      // Update active link
      links.forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      // Update active section
      const targetId = link.getAttribute('data-target');
      sections.forEach(s => {
        if (s.id === targetId) {
          s.classList.add('active');
          title.textContent = link.textContent;
        } else {
          s.classList.remove('active');
        }
      });
    });
  });
}

function bindControls() {
  // Handshake Lab Controls
  document.querySelectorAll('#config-selector .segmented-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#config-selector .segmented-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.config = btn.getAttribute('data-cfg');
      updateAllViews();
    });
  });

  document.querySelectorAll('#workload-selector .segmented-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#workload-selector .segmented-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.workload = btn.getAttribute('data-wl');
      updateAllViews();
    });
  });

  // Cost Analysis Controls
  document.querySelectorAll('#decomp-selector .segmented-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#decomp-selector .segmented-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.decompScope = btn.getAttribute('data-decomp');
      renderDecompChart();
    });
  });

  document.querySelectorAll('#decomp-wl-selector .segmented-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#decomp-wl-selector .segmented-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.decompWorkload = btn.getAttribute('data-wl');
      renderDecompChart();
    });
  });

  // Defense Lab Controls
  document.querySelectorAll('#d2-toggle .segmented-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#d2-toggle .segmented-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.d2Mode = btn.getAttribute('data-mode');
      renderD2Simulation();
    });
  });
}

function updateAllViews() {
  renderLabMetrics();
  renderTimeline();
  renderDecompChart();
  renderD2Simulation();
}

function renderLabMetrics() {
  if (!explorerData) return;
  const data = explorerData[state.config];
  if (!data) return;

  const wlData = data[state.workload];
  
  document.getElementById('lab-cpu-val').textContent = (wlData[0] * 1000).toFixed(3) + ' ms';
  document.getElementById('lab-rx-val').textContent = wlData[1].toLocaleString() + ' B';
  document.getElementById('lab-tx-val').textContent = wlData[2].toLocaleString() + ' B';
  
  document.getElementById('lab-outcome-val').textContent = 
    state.workload === 'W0' ? 'COMPLETED' : 'ABORTED (Pre-Finished)';
}

function renderTimeline() {
  const container = document.getElementById('lab-timeline');
  if (!container) return;

  const isW0 = state.workload === 'W0';
  
  let html = '';
  
  if (isW0) {
    html = `
      <div class="timeline-step completed">
        <div class="step-dot">1</div>
        <div class="step-label">ClientHello</div>
      </div>
      <div class="timeline-step completed">
        <div class="step-dot">2</div>
        <div class="step-label">Server Processing</div>
        <div class="step-sub">KE + Auth</div>
      </div>
      <div class="timeline-step completed">
        <div class="step-dot">3</div>
        <div class="step-label">Server Response</div>
        <div class="step-sub">Finished</div>
      </div>
      <div class="timeline-step completed">
        <div class="step-dot">4</div>
        <div class="step-label text-ok">COMPLETED</div>
      </div>
    `;
  } else {
    html = `
      <div class="timeline-step completed">
        <div class="step-dot">1</div>
        <div class="step-label">ClientHello</div>
      </div>
      <div class="timeline-step completed">
        <div class="step-dot">2</div>
        <div class="step-label">Server Processing</div>
        <div class="step-sub">Pre-completion only</div>
      </div>
      <div class="timeline-step aborted">
        <div class="step-dot">3</div>
        <div class="step-label text-error">ABORTED</div>
        <div class="step-sub">Client disconnects</div>
      </div>
    `;
  }

  container.innerHTML = html;
}

function renderDecompChart() {
  const container = document.getElementById('decomp-chart');
  if (!container || !decompData) return;

  const wlData = decompData;
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  
  let highlighted = [];
  let additiveRef = null;

  switch (state.decompScope) {
    case 'baseline':
      highlighted = configs;
      break;
    case 'ke':
      highlighted = ['C0', 'C1'];
      break;
    case 'auth':
      highlighted = ['C0', 'C2'];
      break;
    case 'combined':
      highlighted = ['C0', 'C1', 'C2', 'C4'];
      const c0 = wlData['C0'][state.decompWorkload];
      const c1 = wlData['C1'][state.decompWorkload];
      const c2 = wlData['C2'][state.decompWorkload];
      additiveRef = c1 + c2 - c0;
      break;
  }

  // Find max for scaling
  let maxVal = Math.max(...configs.map(c => wlData[c][state.decompWorkload]));
  if (additiveRef && additiveRef > maxVal) maxVal = additiveRef;

  let html = '';
  configs.forEach(c => {
    if (state.decompScope !== 'baseline' && !highlighted.includes(c)) return;
    
    const val = wlData[c][state.decompWorkload];
    const pct = (val / maxVal) * 100;
    const hClass = highlighted.includes(c) ? 'highlighted' : '';
    const isSelectedConfig = c === state.config;

    html += `
      <div class="bar-wrapper" style="opacity: ${isSelectedConfig ? '1' : '0.6'}">
        <div class="bar ${hClass}" style="height: ${pct}%;"></div>
        <div class="bar-val">${(val * 1000).toFixed(3)}</div>
        <div class="bar-label" style="color: ${isSelectedConfig ? 'var(--accent-primary)' : ''}">${c}</div>
      </div>
    `;
  });

  if (state.decompScope === 'combined' && additiveRef) {
    const pct = (additiveRef / maxVal) * 100;
    html += `
      <div class="bar-wrapper" style="opacity: 0.8">
        <div class="bar" style="height: ${pct}%; background: repeating-linear-gradient(45deg, var(--border-strong), var(--border-strong) 10px, var(--bg-base) 10px, var(--bg-base) 20px);"></div>
        <div class="bar-val" style="color: var(--text-secondary)">${(additiveRef * 1000).toFixed(3)}</div>
        <div class="bar-label">Ref</div>
      </div>
    `;
    document.getElementById('decomp-note').textContent = "The simple additive reference (C1 + C2 − C0) is shown for comparison only — not as a proven decomposition model.";
  } else {
    document.getElementById('decomp-note').textContent = "Displaying campaign means from Phase 5 data.";
  }

  container.innerHTML = html;
}

function renderD2Simulation() {
  const flowContainer = document.getElementById('d2-sim-flow');
  const statsContainer = document.getElementById('d2-stats');
  if (!flowContainer || !statsContainer || !defenseData) return;

  const data = defenseData[state.d2Mode];
  if (!data) return;

  if (state.d2Mode === 'D0') {
    flowContainer.innerHTML = `
      <div class="sim-node">
        <div class="sim-node-title">Total Attempts</div>
        <div class="sim-node-val">1000</div>
      </div>
      <div class="sim-arrow">→</div>
      <div class="sim-node" style="border-color: var(--status-error)">
        <div class="sim-node-title">Reached TLS</div>
        <div class="sim-node-val sim-reject">1000</div>
      </div>
      <div class="sim-arrow">→</div>
      <div class="sim-node" style="border-color: var(--status-error)">
        <div class="sim-node-title">CPU Impact</div>
        <div class="sim-node-val sim-reject">High</div>
      </div>
    `;
  } else {
    flowContainer.innerHTML = `
      <div class="sim-node">
        <div class="sim-node-title">Total Attempts</div>
        <div class="sim-node-val">1000</div>
      </div>
      <div class="sim-arrow">→</div>
      <div class="sim-node" style="border-color: var(--accent-primary)">
        <div class="sim-node-title">Rejected by Proxy</div>
        <div class="sim-node-val">${data.rej}</div>
      </div>
      <div class="sim-arrow">→</div>
      <div class="sim-node" style="border-color: var(--status-ok)">
        <div class="sim-node-title">Reached TLS</div>
        <div class="sim-node-val sim-accept">${data.acc}</div>
      </div>
    `;
  }

  statsContainer.innerHTML = `
    <div class="data-item">
      <div class="data-label">CPU / Attempt</div>
      <div class="data-val">${data.cpu_ms.toFixed(3)} ms</div>
    </div>
    <div class="data-item">
      <div class="data-label">CPU Reduction</div>
      <div class="data-val" style="color: var(--status-ok)">${state.d2Mode === 'D0' ? '0%' : '~88%'}</div>
    </div>
    <div class="data-item">
      <div class="data-label">Legitimate Success</div>
      <div class="data-val">${data.ok}%</div>
    </div>
    <div class="data-item">
      <div class="data-label">Method</div>
      <div class="data-val" style="font-size: 13px; color: var(--text-primary)">${data.description}</div>
    </div>
  `;
}

function renderAudit() {
  const container = document.getElementById('audit-list');
  if (!container || !challengesData) return;

  const items = challengesData.challenges.slice(0, 4); // F-01 to F-04
  
  let html = '';
  items.forEach(c => {
    html += `
      <div class="audit-item">
        <button class="audit-header">
          <span class="audit-id">${c.id}</span>
          <span class="audit-title">${c.title}</span>
        </button>
        <div class="audit-content">
          <div class="audit-section">
            <h4>Problem</h4>
            <p>${c.problem}</p>
          </div>
          <div class="audit-section">
            <h4>Investigation</h4>
            <p>${c.investigation}</p>
          </div>
          <div class="audit-section">
            <h4>Remediation</h4>
            <p>${c.resolution}</p>
          </div>
          <div class="audit-section">
            <h4>Status</h4>
            <p class="text-ok">${c.status}</p>
          </div>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  container.querySelectorAll('.audit-header').forEach(btn => {
    btn.addEventListener('click', () => {
      const content = btn.nextElementSibling;
      content.classList.toggle('open');
    });
  });
}

// --- HYPOTHETICAL SIMULATOR LOGIC ---
let simulatorInitialized = false;

function initSimulator() {
  if (simulatorInitialized) return;
  simulatorInitialized = true;

  // Sync defaults from evidence mode
  document.getElementById('sim-cfg').value = state.config;
  document.getElementById('sim-wl').value = state.workload;
  
  const updateSim = () => {
    // Read values
    const attempts = parseInt(document.getElementById('sim-attempts').value);
    const cpuAssumed = parseFloat(document.getElementById('sim-cpu').value);
    const admRate = parseFloat(document.getElementById('sim-adm').value) / 100;
    const def = document.getElementById('sim-def').value;
    const wl = document.getElementById('sim-wl').value;
    const cfg = document.getElementById('sim-cfg').value;

    // Display readouts
    document.getElementById('sim-attempts-val').textContent = attempts;
    document.getElementById('sim-cpu-val').textContent = cpuAssumed.toFixed(3) + ' ms';
    document.getElementById('sim-adm-val').textContent = (admRate * 100).toFixed(1) + '%';
    
    // Disable adm rate slider if D0
    if (def === 'D0') {
       document.getElementById('sim-adm').disabled = true;
       document.getElementById('sim-admission-group').style.opacity = '0.5';
    } else {
       document.getElementById('sim-adm').disabled = false;
       document.getElementById('sim-admission-group').style.opacity = '1';
    }

    // Calculate outcomes
    const accepted = def === 'D2' ? Math.round(attempts * admRate) : attempts;
    const rejected = attempts - accepted;
    
    const cpuCost = (accepted * cpuAssumed) / 1000; // in seconds
    const baselineCpuCost = (attempts * cpuAssumed) / 1000;
    const saved = baselineCpuCost - cpuCost;
    const pctSaved = baselineCpuCost > 0 ? (saved / baselineCpuCost) * 100 : 0;

    // Render Outputs
    document.getElementById('sim-out-cpu').textContent = cpuCost.toFixed(3) + ' s';
    document.getElementById('sim-out-saved').textContent = saved.toFixed(3) + ' s';
    document.getElementById('sim-out-pct').textContent = pctSaved.toFixed(1) + '%';
    document.getElementById('sim-out-acc').textContent = accepted;

    // Render Flow
    const flowContainer = document.getElementById('sim-flow-chart');
    if (def === 'D0') {
        flowContainer.innerHTML = `
            <div class="sim-node">
              <div class="sim-node-title text-warning">INPUT ATTEMPTS</div>
              <div class="sim-node-val text-warning">${attempts}</div>
            </div>
            <div class="sim-arrow text-warning">→</div>
            <div class="sim-node">
              <div class="sim-node-title text-warning">REACHED TLS</div>
              <div class="sim-node-val text-warning">${accepted}</div>
            </div>
        `;
    } else {
        flowContainer.innerHTML = `
            <div class="sim-node">
              <div class="sim-node-title text-warning">INPUT ATTEMPTS</div>
              <div class="sim-node-val text-warning">${attempts}</div>
            </div>
            <div class="sim-arrow text-warning">→</div>
            <div class="sim-node" style="border-color: var(--status-warning)">
              <div class="sim-node-title text-warning">REJECTED</div>
              <div class="sim-node-val text-warning">${rejected}</div>
            </div>
            <div class="sim-arrow text-warning">→</div>
            <div class="sim-node">
              <div class="sim-node-title text-warning">REACHED TLS</div>
              <div class="sim-node-val text-warning">${accepted}</div>
            </div>
        `;
    }

    // Render Validation Table (compare against Phase 7)
    const refData = defenseData ? defenseData[def] : null;
    const refCpuPerAttempt = refData ? refData.cpu_ms : 0;
    const refReduction = def === 'D0' ? '0%' : '~88%';
    
    let deltaCpu = cpuAssumed - refCpuPerAttempt;
    let deltaCpuStr = (deltaCpu > 0 ? '+' : '') + deltaCpu.toFixed(3);
    let deltaColor = deltaCpu > 0 ? 'delta-negative' : 'delta-positive';
    if (Math.abs(deltaCpu) < 0.001) deltaColor = 'delta-neutral';

    const tBody = document.getElementById('sim-comparison-table').querySelector('tbody');
    tBody.innerHTML = `
       <tr>
         <td>Assumed CPU / Attempt</td>
         <td class="text-warning">${cpuAssumed.toFixed(3)} ms</td>
         <td>${refCpuPerAttempt.toFixed(3)} ms</td>
         <td class="${deltaColor}">${deltaCpuStr}</td>
       </tr>
       <tr>
         <td>CPU Reduction</td>
         <td class="text-warning">${pctSaved.toFixed(1)}%</td>
         <td>${refReduction}</td>
         <td class="delta-neutral">-</td>
       </tr>
    `;
  };

  // Bind inputs
  ['sim-cfg', 'sim-wl', 'sim-def', 'sim-attempts', 'sim-cpu', 'sim-adm'].forEach(id => {
     document.getElementById(id).addEventListener('input', () => {
         // remove preset active state
         document.querySelectorAll('#sim-presets .segmented-btn').forEach(b => b.classList.remove('active'));
         updateSim();
     });
  });

  // Bind Presets
  document.querySelectorAll('#sim-presets .segmented-btn').forEach(btn => {
     btn.addEventListener('click', (e) => {
         document.querySelectorAll('#sim-presets .segmented-btn').forEach(b => b.classList.remove('active'));
         btn.classList.add('active');
         
         const p = btn.getAttribute('data-preset');
         if (p === 'measured_d0') {
             document.getElementById('sim-def').value = 'D0';
             document.getElementById('sim-attempts').value = 1000;
             if (defenseData && defenseData['D0']) {
                 document.getElementById('sim-cpu').value = defenseData['D0'].cpu_ms.toFixed(3);
             }
         } else if (p === 'measured_d2') {
             document.getElementById('sim-def').value = 'D2';
             document.getElementById('sim-attempts').value = 1000;
             if (defenseData && defenseData['D2']) {
                 document.getElementById('sim-cpu').value = defenseData['D2'].cpu_ms.toFixed(3);
             }
             document.getElementById('sim-adm').value = 12.8;
         } else if (p === 'stress') {
             document.getElementById('sim-def').value = 'D2';
             document.getElementById('sim-attempts').value = 100000;
             document.getElementById('sim-cpu').value = 3.0; // hypothetical worse case
             document.getElementById('sim-adm').value = 5.0; // tighter admission
         }
         updateSim();
     });
  });

  document.getElementById('sim-reset').addEventListener('click', () => {
     document.querySelector('[data-preset="measured_d0"]').click();
  });

  // Initial Update
  updateSim();
}

document.addEventListener('DOMContentLoaded', init);