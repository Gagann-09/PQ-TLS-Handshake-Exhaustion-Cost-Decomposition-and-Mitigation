/**
 * Data Loader — Canonical Public JSON Data Layer
 * 
 * Single source of truth for all interactive components.
 * Loads from external JSON files (configurations.json, figures_phase5.json, figures_phase7.json).
 * Provides normalized accessors for the C0–C4 explorer and other interactive components.
 */

const DATA_PATHS = {
  configurations: 'data/configurations.json',
  phase5: 'data/figures_phase5.json',
  phase7: 'data/figures_phase7.json',
  challenges: 'data/challenges.json'
};

let _cache = {};
let _loadPromise = null;

/**
 * Load a JSON file with caching
 */
async function loadJSON(path) {
  if (_cache[path]) return _cache[path];
  
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`Failed to load ${path}: ${resp.status}`);
  const data = await resp.json();
  _cache[path] = data;
  return data;
}

/**
 * Load all canonical data sources
 * Returns a promise that resolves when all data is loaded
 */
export async function loadAllData() {
  if (_loadPromise) return _loadPromise;
  
  _loadPromise = Promise.all([
    loadJSON(DATA_PATHS.configurations),
    loadJSON(DATA_PATHS.phase5),
    loadJSON(DATA_PATHS.phase7)
  ]).then(([configs, phase5, phase7]) => ({
    configs,
    phase5,
    phase7
  }));
  
  return _loadPromise;
}

/**
 * Get C0–C4 configuration metadata
 */
export async function getConfigurations() {
  const { configs } = await loadAllData();
  return configs.configurations;
}

/**
 * Get workload mode metadata
 */
export async function getWorkloadModes() {
  const { configs } = await loadAllData();
  return configs.workload_modes;
}

/**
 * Get defense mode metadata
 */
export async function getDefenseModes() {
  const { configs } = await loadAllData();
  return configs.defense_modes;
}

/**
 * Get canonical C0–C4 × W0/W1 measurement data for the explorer
 * Returns normalized data matching the canonical values from the spec
 */
export async function getExplorerData() {
  const { phase5 } = await loadAllData();
  const figA = phase5.figure_a;
  
  // Build explorer data from canonical Phase 5 figure_a data
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  const workloads = ['normal_completion', 'controlled_abort'];
  
  const explorerData = {};
  
  configs.forEach(cfg => {
    explorerData[cfg] = {
      W0: [
        figA.normal_completion[cfg].mean,  // CPU s/attempt
        getRxBytes(cfg, 'W0'),             // RX bytes
        getTxBytes(cfg, 'W0')              // TX bytes
      ],
      W1: [
        figA.controlled_abort[cfg].mean,   // CPU s/attempt
        getRxBytes(cfg, 'W1'),             // RX bytes
        getTxBytes(cfg, 'W1')              // TX bytes
      ],
      ke: getKeyEstablishment(cfg),
      au: getAuthentication(cfg),
      note: getConfigNote(cfg)
    };
  });
  
  return explorerData;
}

/**
 * Get CPU/attempt data for all configs × workload (for decomposition bars)
 */
export async function getDecompositionData() {
  const { phase5 } = await loadAllData();
  const figA = phase5.figure_a;
  
  const configs = ['C0', 'C1', 'C2', 'C3', 'C4'];
  const result = {};
  
  configs.forEach(cfg => {
    result[cfg] = {
      W0: figA.normal_completion[cfg].mean,
      W1: figA.controlled_abort[cfg].mean,
      ke: getKeyEstablishment(cfg),
      au: getAuthentication(cfg)
    };
  });
  
  return result;
}

/**
 * Get Phase 7 defense data for D0–D3
 */
export async function getDefenseData() {
  const { phase7 } = await loadAllData();
  return phase7.defenses;
}

/**
 * Get key establishment label for config
 */
function getKeyEstablishment(cfg) {
  const map = {
    'C0': 'X25519',
    'C1': 'ML-KEM-768',
    'C2': 'X25519',
    'C3': 'X25519+ML-KEM-768 (hybrid)',
    'C4': 'ML-KEM-768'
  };
  return map[cfg] || cfg;
}

/**
 * Get authentication label for config
 */
function getAuthentication(cfg) {
  const map = {
    'C0': 'ECDSA-P256',
    'C1': 'ECDSA-P256',
    'C2': 'ML-DSA-65',
    'C3': 'ECDSA-P256',
    'C4': 'ML-DSA-65'
  };
  return map[cfg] || cfg;
}

/**
 * Get config note
 */
function getConfigNote(cfg) {
  const notes = {
    'C0': 'Classical baseline.',
    'C1': 'PQ key establishment alone: W0 CPU ≈ 0.95× C0, i.e. not higher in this testbed. Wire bytes roughly double.',
    'C2': 'ML-DSA authentication: W0 CPU ≈ 1.93× C0. TX bytes are large because of the ML-DSA material.',
    'C3': 'Hybrid key establishment: modest CPU increment over C0 in W0.',
    'C4': 'Both PQ components: W0 CPU ≈ 1.95× C0; the largest CPU and TX in the matrix.'
  };
  return notes[cfg] || '';
}

/**
 * RX/TX bytes from landing-page data.js (canonical values per spec)
 * These are the wire byte measurements from the experiment
 */
function getRxBytes(cfg, workload) {
  const data = {
    'C0': { 'W0': 1005, 'W1': 876 },
    'C1': { 'W0': 1854, 'W1': 1896 },
    'C2': { 'W0': 844, 'W1': 826 },
    'C3': { 'W0': 1880, 'W1': 826 },
    'C4': { 'W0': 1978, 'W1': 1977 }
  };
  return data[cfg]?.[workload] ?? 0;
}

function getTxBytes(cfg, workload) {
  const data = {
    'C0': { 'W0': 1587, 'W1': 982 },
    'C1': { 'W0': 2602, 'W1': 2661 },
    'C2': { 'W0': 9929, 'W1': 220 },
    'C3': { 'W0': 2626, 'W1': 220 },
    'C4': { 'W0': 11031, 'W1': 11032 }
  };
  return data[cfg]?.[workload] ?? 0;
}

/**
 * Get workload labels
 */
export function getWorkloadLabels() {
  return {
    'W0': 'Normal completed TLS handshake',
    'W1': 'Controlled pre-Finished abort'
  };
}

/**
 * Get defense labels and summary data
 */
export async function getDefenseSummary() {
  const defenses = await getDefenseData();
  const summary = {};
  
  ['D0', 'D1', 'D2', 'D3'].forEach(d => {
    const o = defenses[d];
    summary[d] = {
      label: o.label || d,
      cpu: o.cpu_mean_ms / 1000, // convert to seconds
      cpu_ms: o.cpu_mean_ms,
      ratio: d === 'D0' ? 1.0 : (o.cpu_mean_ms / defenses.D0.cpu_mean_ms),
      ok: o.legitimate_success_rate * 100,
      p50: o.legitimate_p50_mean_ms,
      acc: o.accepted_at_tls ? Math.round(o.accepted_at_tls.reduce((a,b)=>a+b)/o.accepted_at_tls.length) : null,
      rej: o.rejected_at_proxy ? Math.round(o.rejected_at_proxy.reduce((a,b)=>a+b)/o.rejected_at_proxy.length) : null,
      description: o.description
    };
  });
  
  return summary;
}