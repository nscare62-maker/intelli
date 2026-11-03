/**
 * ==========================================================
 * Project 26-78: Blockchain Enabled Secure IoT Communication
 * Framework with Edge Network Intelligence
 * Script Engine: app.js
 * ==========================================================
 */

// ----------------------------------------------------------
// 0. TAILWIND CONFIGURATION INITIALIZER
// ----------------------------------------------------------
if (window.tailwind) {
  tailwind.config = {
    darkMode: 'class',
    theme: {
      extend: {
        fontFamily: {
          sans: ['Inter', 'system-ui', 'sans-serif'],
          mono: ['JetBrains Mono', 'monospace'],
        },
        colors: {
          slate: {
            850: '#131c31',
            950: '#0b0f17',
          },
          brand: {
            50: '#eff6ff',
            500: '#2563eb',
            600: '#1d4ed8',
            700: '#1e40af',
          }
        }
      }
    }
  };
}

// Safe Lucide Icon creation helper (prevents crashes if offline or CDN is blocked)
function safeCreateIcons(options) {
  if (typeof lucide !== 'undefined' && lucide && typeof lucide.createIcons === 'function') {
    try {
      lucide.createIcons(options);
    } catch (e) {
      console.warn('[Lucide] Error creating icons:', e);
    }
  }
}

/* ==========================================================
   1. CRYPTOGRAPHIC UTILITIES (SHA-256 with Pure JS Fallback)
   ========================================================== */
function fallbackSha256(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let lengthProperty = 'length';
  let i, j;
  let result = '';

  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;

  let hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let compositeLength = ((asciiBitLength + 64 >>> 9) << 4) + 15;
  words[compositeLength] = asciiBitLength;

  for (i = 0; i < ascii[lengthProperty]; i++) {
    words[i >> 2] |= (ascii.charCodeAt(i) & 255) << (8 * (3 - (i % 4)));
  }
  words[ascii[lengthProperty] >> 2] |= 0x80 << (8 * (3 - (ascii[lengthProperty] % 4)));

  for (i = 0; i < compositeLength; i += 16) {
    let w = [];
    for (j = 0; j < 16; j++) w[j] = words[i + j] | 0;
    for (j = 16; j < 64; j++) {
      let s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
      let s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
    }

    let a = hash[0], b = hash[1], c = hash[2], d = hash[3],
        e = hash[4], f = hash[5], g = hash[6], h = hash[7];

    for (j = 0; j < 64; j++) {
      let s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      let ch = (e & f) ^ ((~e) & g);
      let temp1 = (h + s1 + ch + k[j] + w[j]) | 0;
      let s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = (s0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    hash[0] = (hash[0] + a) | 0;
    hash[1] = (hash[1] + b) | 0;
    hash[2] = (hash[2] + c) | 0;
    hash[3] = (hash[3] + d) | 0;
    hash[4] = (hash[4] + e) | 0;
    hash[5] = (hash[5] + f) | 0;
    hash[6] = (hash[6] + g) | 0;
    hash[7] = (hash[7] + h) | 0;
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      let b = (hash[i] >> (8 * j)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

// Unified SHA-256 function
async function calculateSHA256(message) {
  try {
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
      const msgBuffer = new TextEncoder().encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch (err) {
    // Fallback directly
  }
  return fallbackSha256(message);
}

function generateRandomHex(length = 40) {
  const chars = '0123456789abcdef';
  let res = '0x';
  for (let i = 0; i < length; i++) {
    res += chars[Math.floor(Math.random() * chars.length)];
  }
  return res.toUpperCase();
}


/* ==========================================================
   2. WEB AUDIO API SYNTHESIS (Sci-Fi Sound Effects)
   ========================================================== */
let audioEnabled = true;
let audioCtx = null;

function getAudioContext() {
  if (!audioCtx) {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (AudioContext) {
      audioCtx = new AudioContext();
    }
  }
  if (audioCtx && audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  return audioCtx;
}

function playSound(type) {
  if (!audioEnabled) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === 'click') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(300, now + 0.05);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
      osc.start(now);
      osc.stop(now + 0.05);
    } else if (type === 'success') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(523.25, now); // C5
      osc.frequency.setValueAtTime(659.25, now + 0.08); // E5
      osc.frequency.setValueAtTime(783.99, now + 0.16); // G5
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.32);
      osc.start(now);
      osc.stop(now + 0.32);
    } else if (type === 'alarm') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.linearRampToValueAtTime(440, now + 0.2);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      osc.start(now);
      osc.stop(now + 0.2);
    } else if (type === 'glitch') {
      osc.type = 'square';
      osc.frequency.setValueAtTime(220, now);
      osc.frequency.setValueAtTime(140, now + 0.04);
      osc.frequency.setValueAtTime(320, now + 0.08);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
      osc.start(now);
      osc.stop(now + 0.15);
    }
  } catch (e) {
    // Ignore audio autoplay restrictions
  }
}


/* ==========================================================
   3. APPLICATION STATE DATA STORE
   ========================================================== */
// Clean baseline: No synthetic demo nodes; user uploads dataset or registers devices.
const DEFAULT_DEMO_NODES = [];

// Cryptographic genesis origin block for blockchain trust anchoring
const DEFAULT_DEMO_BLOCKS = [
  {
    index: 0,
    timestamp: '2026-10-23 08:00:00 UTC',
    deviceId: 'GENESIS-ROOT',
    action: 'GENESIS',
    validator: 'Val-00 [Ledger Origin]',
    payload: { message: "Project 26-78 PoA Genesis Block - Trust Root Established", difficulty: 1 },
    previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
    hash: '0000a1f8b492e811c7d05634e89a19c5b4e72390a184f7289b418e90c12fa839',
    nonce: 42
  }
];

const State = {
  activeTab: 'tab-overview',
  liveSimulation: false,
  simulationIntervalMs: 2000,
  simTimerId: null,
  edgeLatency: 0.0,
  cloudLatency: 0.0,
  totalIntrusionsBlocked: 0,
  isChainTampered: false,
  tamperedBlockIndex: null,

  // Active Dataset Info
  datasetName: "No Dataset Staged",
  isCustomDataset: false,
  chartsVisible: false,

  nodes: [],
  blockchain: JSON.parse(JSON.stringify(DEFAULT_DEMO_BLOCKS)),
  canonicalBackup: JSON.parse(JSON.stringify(DEFAULT_DEMO_BLOCKS)),

  trafficStats: {
    normal: 0,
    ddos: 0,
    spoof: 0,
    tamper: 0
  }
};


/* ==========================================================
   4. UI TOAST NOTIFICATION SYSTEM
   ========================================================== */
function showToast(title, message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `p-3.5 rounded-lg border bg-white border-slate-200 shadow-xl flex items-start space-x-3 text-xs transform transition-all duration-200 pointer-events-auto translate-y-2 opacity-0 font-sans`;

  let iconColor = 'text-slate-400';
  let borderColor = 'border-slate-700';
  let icon = 'info';

  if (type === 'error' || type === 'threat') {
    iconColor = 'text-red-400';
    borderColor = 'border-red-500/50';
    icon = 'shield-alert';
    playSound('alarm');
  } else if (type === 'success') {
    iconColor = 'text-emerald-400';
    borderColor = 'border-emerald-500/50';
    icon = 'check-circle';
    playSound('success');
  } else if (type === 'warning') {
    iconColor = 'text-amber-400';
    borderColor = 'border-amber-500/50';
    icon = 'alert-triangle';
    playSound('alarm');
  } else {
    playSound('click');
  }

  toast.classList.add(borderColor);

  toast.innerHTML = `
    <div class="flex-shrink-0 mt-0.5 ${iconColor}">
      <i data-lucide="${icon}" class="w-4 h-4"></i>
    </div>
    <div class="flex-1">
      <div class="font-bold text-slate-900 tracking-wide">${title}</div>
      <div class="text-slate-600 text-[11px] mt-0.5 leading-snug">${message}</div>
    </div>
    <button class="text-slate-400 hover:text-slate-700 p-0.5" onclick="this.parentElement.remove()">
      <i data-lucide="x" class="w-3.5 h-3.5"></i>
    </button>
  `;

  container.appendChild(toast);
  safeCreateIcons({ root: toast });

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-x-4');
    setTimeout(() => toast.remove(), 300);
  }, 4200);
}


/* ==========================================================
   5. CHARTS INITIALIZATION (Chart.js)
   ========================================================== */
let latencyChart = null;
let trafficDoughnutChart = null;

function initCharts() {
  const latencyCanvas = document.getElementById('latencyChart');
  const doughnutCanvas = document.getElementById('trafficDoughnutChart');
  if (!latencyCanvas || !doughnutCanvas) return;

  // 1. Latency Line Chart (Clean Enterprise SaaS)
  const latencyCtx = latencyCanvas.getContext('2d');
  
  const blueGradient = latencyCtx.createLinearGradient(0, 0, 0, 240);
  blueGradient.addColorStop(0, 'rgba(37, 99, 235, 0.12)');
  blueGradient.addColorStop(1, 'rgba(37, 99, 235, 0.0)');

  const labels = ['T-12s', 'T-10s', 'T-8s', 'T-6s', 'T-4s', 'T-2s', 'Now'];
  const edgeData = [4.3, 3.8, 4.1, 3.9, 4.5, 3.7, 4.0];
  const cloudData = [84.2, 89.1, 82.5, 94.0, 87.3, 85.9, 86.4];

  latencyChart = new Chart(latencyCtx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Edge Verification Latency (ms)',
          data: edgeData,
          borderColor: '#2563eb',
          backgroundColor: blueGradient,
          borderWidth: 2,
          tension: 0.25,
          fill: true,
          pointBackgroundColor: '#2563eb',
          pointBorderColor: '#ffffff',
          pointRadius: 3.5,
          pointHoverRadius: 5.5,
        },
        {
          label: 'Centralized Cloud Host (ms)',
          data: cloudData,
          borderColor: '#dc2626',
          borderDash: [4, 4],
          borderWidth: 1.5,
          tension: 0.2,
          fill: false,
          pointBackgroundColor: '#dc2626',
          pointBorderColor: '#ffffff',
          pointRadius: 2.5,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#ffffff',
          titleColor: '#0f172a',
          bodyColor: '#334155',
          borderColor: '#cbd5e1',
          borderWidth: 1,
          padding: 8,
          cornerRadius: 6,
          displayColors: true,
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          callbacks: {
            label: (ctx) => ` ${ctx.dataset.label}: ${ctx.raw} ms`
          }
        }
      },
      scales: {
        x: {
          grid: { color: '#e2e8f0' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          grid: { color: '#e2e8f0' },
          ticks: { 
            color: '#64748b', 
            font: { family: 'JetBrains Mono', size: 10 },
            callback: (val) => val + ' ms'
          },
          min: 0,
          max: 120
        }
      }
    }
  });

  // 2. Traffic Doughnut Chart
  const doughnutCtx = doughnutCanvas.getContext('2d');
  trafficDoughnutChart = new Chart(doughnutCtx, {
    type: 'doughnut',
    data: {
      labels: ['Normal MQTT Traffic', 'DDoS Blocked', 'Spoofing Attempt', 'Data Tampering'],
      datasets: [{
        data: [
          State.trafficStats.normal,
          State.trafficStats.ddos,
          State.trafficStats.spoof,
          State.trafficStats.tamper
        ],
        backgroundColor: [
          '#10b981', // Emerald
          '#ef4444', // Red
          '#2563eb', // Blue
          '#f59e0b'  // Amber
        ],
        borderColor: '#ffffff',
        borderWidth: 2.5,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#ffffff',
          titleColor: '#0f172a',
          bodyColor: '#334155',
          borderColor: '#cbd5e1',
          borderWidth: 1,
          cornerRadius: 6,
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw} packets`
          }
        }
      }
    }
  });
}

function updateDoughnutUI() {
  if (!trafficDoughnutChart) return;
  const total = State.trafficStats.normal + State.trafficStats.ddos + State.trafficStats.spoof + State.trafficStats.tamper;
  trafficDoughnutChart.data.datasets[0].data = [
    State.trafficStats.normal,
    State.trafficStats.ddos,
    State.trafficStats.spoof,
    State.trafficStats.tamper
  ];
  trafficDoughnutChart.update();

  const safeDiv = (val) => total > 0 ? Math.round((val / total) * 100) : 0;
  document.getElementById('doughnutValNormal').textContent = safeDiv(State.trafficStats.normal) + '%';
  document.getElementById('doughnutValDDoS').textContent = safeDiv(State.trafficStats.ddos) + '%';
  document.getElementById('doughnutValSpoof').textContent = safeDiv(State.trafficStats.spoof) + '%';
  document.getElementById('doughnutValTamper').textContent = safeDiv(State.trafficStats.tamper) + '%';
}


/* ==========================================================
   6. LIVE PACKET FEED TERMINAL SYSTEM
   ========================================================== */
function addTerminalLog(deviceId, payload, anomalyScore, status, message) {
  const feed = document.getElementById('liveTerminalFeed');
  if (!feed) return;
  const time = new Date().toLocaleTimeString();

  let scoreColor = 'text-emerald-600 font-semibold';
  let statusBadge = '<span class="px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-mono font-medium">VERIFIED</span>';

  if (anomalyScore >= 0.85) {
    scoreColor = 'text-red-600 font-semibold';
    statusBadge = '<span class="px-1.5 py-0.2 rounded bg-red-50 text-red-700 border border-red-200 text-[10px] font-mono font-medium">DROPPED</span>';
  } else if (anomalyScore >= 0.40) {
    scoreColor = 'text-amber-600 font-semibold';
    statusBadge = '<span class="px-1.5 py-0.2 rounded bg-amber-50 text-amber-700 border border-amber-200 text-[10px] font-mono font-medium">FLAGGED</span>';
  }

  const logItem = document.createElement('div');
  logItem.className = 'py-1.5 flex flex-col md:flex-row md:items-center justify-between gap-1 text-[11px] font-mono';
  
  const payloadStr = typeof payload === 'object' ? JSON.stringify(payload) : payload;

  logItem.innerHTML = `
    <div class="flex items-center space-x-2 truncate">
      <span class="text-slate-400">[${time}]</span>
      <span class="text-slate-900 font-bold">${deviceId}</span>
      <span class="text-slate-600 truncate max-w-xs md:max-w-md">${payloadStr}</span>
    </div>
    <div class="flex items-center space-x-2 self-end md:self-auto flex-shrink-0">
      <span class="text-slate-500">anomaly: <span class="${scoreColor}">${(Number.isFinite(anomalyScore) ? anomalyScore : 0.05).toFixed(2)}</span></span>
      ${statusBadge}
      <span class="text-slate-500 text-[10px] hidden lg:inline">${message || ''}</span>
    </div>
  `;

  feed.appendChild(logItem);

  const autoScroll = document.getElementById('autoScrollToggle')?.checked ?? true;
  if (autoScroll) {
    feed.scrollTop = feed.scrollHeight;
  }

  if (feed.children.length > 60) {
    feed.removeChild(feed.children[0]);
  }
}


/* ==========================================================
   7. IOT NODE REGISTRY MANAGEMENT (Tab 2)
   ========================================================== */
function renderNodesTable() {
  const tbody = document.getElementById('nodesTableBody');
  if (!tbody) return;

  const search = (document.getElementById('nodeSearchInput')?.value || '').toLowerCase();
  const statusFilter = document.getElementById('nodeStatusFilter')?.value || 'ALL';

  tbody.innerHTML = '';

  const filtered = State.nodes.filter(node => {
    const matchesSearch = node.id.toLowerCase().includes(search) || 
                          node.name.toLowerCase().includes(search) || 
                          node.type.toLowerCase().includes(search) ||
                          node.mac.toLowerCase().includes(search);
    const matchesStatus = statusFilter === 'ALL' || node.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  filtered.forEach(node => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition border-b border-slate-800/60';

    let statusBadge = '';
    if (node.status === 'Verified') {
      statusBadge = '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium badge-verified"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5"></span>Verified</span>';
    } else if (node.status === 'Quarantined') {
      statusBadge = '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium badge-quarantined"><span class="w-1.5 h-1.5 rounded-full bg-red-500 mr-1.5"></span>Quarantined</span>';
    } else {
      statusBadge = '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium badge-pending"><span class="w-1.5 h-1.5 rounded-full bg-amber-500 mr-1.5"></span>Pending</span>';
    }

    let actionBtn = '';
    if (node.status === 'Verified') {
      actionBtn = `
        <button onclick="quarantineNode('${node.id}', 'Manual SecOps Quarantine')" class="px-2.5 py-1 rounded bg-slate-100 hover:bg-red-50 text-slate-700 hover:text-red-700 border border-slate-300 hover:border-red-300 text-[11px] font-medium transition active:scale-95">
          Quarantine
        </button>
      `;
    } else {
      actionBtn = `
        <button onclick="restoreNode('${node.id}')" class="px-2.5 py-1 rounded bg-slate-100 hover:bg-emerald-50 text-emerald-700 border border-slate-300 text-[11px] font-medium transition active:scale-95">
          Restore
        </button>
      `;
    }

    let trustBarColor = 'bg-emerald-500';
    if (node.trustScore < 50) trustBarColor = 'bg-red-500';
    else if (node.trustScore < 80) trustBarColor = 'bg-amber-500';

    tr.className = 'hover:bg-slate-50 transition border-b border-slate-100';
    tr.innerHTML = `
      <td class="py-2.5 px-4 font-semibold text-slate-900">
        <div class="flex items-center space-x-2">
          <i data-lucide="cpu" class="w-3.5 h-3.5 text-slate-500"></i>
          <div>
            <div class="font-bold text-slate-900">${node.id}</div>
            <div class="text-[10px] text-slate-500 font-normal">${node.name}</div>
          </div>
        </div>
      </td>
      <td class="py-2.5 px-4 text-slate-700 font-medium">${node.type}</td>
      <td class="py-2.5 px-4 text-slate-600">
        <div class="flex items-center space-x-1.5">
          <span class="truncate max-w-[130px] font-mono text-[11px]" title="${node.mac}">${node.mac.substring(0, 8)}...${node.mac.substring(node.mac.length - 6)}</span>
          <button onclick="copyToClipboard('${node.mac}')" title="Copy Address" class="text-slate-400 hover:text-slate-700">
            <i data-lucide="copy" class="w-3 h-3"></i>
          </button>
        </div>
      </td>
      <td class="py-2.5 px-4">
        <span class="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] border border-slate-200">${node.protocol}</span>
      </td>
      <td class="py-2.5 px-4">
        <div class="flex items-center space-x-2">
          <div class="w-16 bg-slate-200 rounded-full h-1.5 overflow-hidden">
            <div class="${trustBarColor} h-1.5 rounded-full" style="width: ${node.trustScore}%"></div>
          </div>
          <span class="font-semibold ${node.trustScore < 50 ? 'text-red-600' : 'text-slate-700'}">${node.trustScore}%</span>
        </div>
      </td>
      <td class="py-2.5 px-4">${statusBadge}</td>
      <td class="py-2.5 px-4 text-right">${actionBtn}</td>
    `;

    tbody.appendChild(tr);
  });

  if (filtered.length === 0) {
    const emptyTr = document.createElement('tr');
    emptyTr.innerHTML = `
      <td colspan="7" class="py-12 px-4 text-center text-slate-400">
        <div class="flex flex-col items-center justify-center space-y-2">
          <i data-lucide="inbox" class="w-8 h-8 text-slate-300"></i>
          <span class="text-xs font-semibold text-slate-700">No IoT Devices Enrolled</span>
          <span class="text-[11px] text-slate-500 max-w-sm">Upload a dataset (.json or .csv) or click "Register Device" to provision endpoints.</span>
        </div>
      </td>
    `;
    tbody.appendChild(emptyTr);
  }

  const countSummary = document.getElementById('nodesCountSummary');
  if (countSummary) {
    countSummary.textContent = `Showing ${filtered.length} of ${State.nodes.length} devices`;
  }
  safeCreateIcons({ root: tbody });

  updateKPIs();
  populateTargetNodeSelect();
}

function updateKPIs() {
  const verified = State.nodes.filter(n => n.status === 'Verified').length;
  const quarantined = State.nodes.filter(n => n.status === 'Quarantined').length;
  const totalBlocks = State.blockchain.length;

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setTxt('kpiTotalNodes', State.nodes.length);
  setTxt('kpiVerifiedNodes', verified);
  setTxt('kpiQuarantinedNodes', quarantined);
  setTxt('kpiTotalBlocks', totalBlocks.toLocaleString());
  setTxt('topBlockHeight', `#${totalBlocks}`);
  setTxt('kpiBlockedIntrusions', State.totalIntrusionsBlocked);
  setTxt('blocksCountBadge', State.blockchain.length);
  setTxt('nodesCountSummaryBadge', State.nodes.length);
  setTxt('currentDatasetLabel', State.datasetName);

  if (State.edgeLatency > 0) {
    setTxt('kpiEdgeLatency', `${State.edgeLatency.toFixed(1)} ms`);
    setTxt('kpiCloudLatency', `${State.cloudLatency.toFixed(1)} ms`);
  } else {
    setTxt('kpiEdgeLatency', '--');
    setTxt('kpiCloudLatency', '--');
  }
}

function populateTargetNodeSelect() {
  const sel = document.getElementById('simTargetNodeSelect');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '';
  State.nodes.forEach(n => {
    const opt = document.createElement('option');
    opt.value = n.id;
    opt.textContent = `${n.id} (${n.type}) [${n.status}]`;
    sel.appendChild(opt);
  });
  if (current) sel.value = current;
}

async function quarantineNode(nodeId, reason = 'Automated Smart Contract Quarantine') {
  const node = State.nodes.find(n => n.id === nodeId);
  if (!node) return;

  node.status = 'Quarantined';
  node.trustScore = Math.max(12, Math.floor(node.trustScore * 0.3));

  const newBlock = await mineNewBlock(
    nodeId,
    'NODE_QUARANTINED',
    { reason: reason, revokedMac: node.mac, timestamp: new Date().toISOString() },
    'Val-01 [Edge Gatekeeper]'
  );

  logSecurityIncident(nodeId, 'CRITICAL', `Smart Contract certificate REVOKED. Node placed in Edge Quarantine. (${reason})`);
  showToast('Node Quarantined!', `Device ${nodeId} blacklisted and certificate revoked on-chain.`, 'error');
  if (window.SupabaseService && SupabaseService.isConnected) {
    SupabaseService.updateNodeStatus(nodeId, 'Quarantined', node.trustScore);
    SupabaseService.insertLog('CRITICAL', 'Smart-Contract', `Node ${nodeId} quarantined (${reason})`);
  }
  renderNodesTable();
  renderBlockchainCards();
  playSound('alarm');
}

function restoreNode(nodeId) {
  const node = State.nodes.find(n => n.id === nodeId);
  if (!node) return;

  node.status = 'Verified';
  node.trustScore = 92;

  logSecurityIncident(nodeId, 'RESTORE', `Device identity verified via Smart Contract re-certification. Certificate restored.`);
  showToast('Node Restored', `Device ${nodeId} certificate restored. Node active on PoA network.`, 'success');
  if (window.SupabaseService && SupabaseService.isConnected) {
    SupabaseService.updateNodeStatus(nodeId, 'Verified', node.trustScore);
    SupabaseService.insertLog('INFO', 'Smart-Contract', `Node ${nodeId} restored to active status`);
  }
  renderNodesTable();
}

function logSecurityIncident(deviceId, severity, text) {
  const logCont = document.getElementById('securityIncidentLog');
  if (!logCont) return;
  const time = new Date().toLocaleTimeString();

  let badge = '<span class="px-1.5 py-0.2 rounded bg-red-50 text-red-700 border border-red-200 text-[10px] font-mono font-medium">CRITICAL</span>';
  if (severity === 'WARNING') {
    badge = '<span class="px-1.5 py-0.2 rounded bg-amber-50 text-amber-700 border border-amber-200 text-[10px] font-mono font-medium">WARNING</span>';
  } else if (severity === 'RESTORE') {
    badge = '<span class="px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-mono font-medium">RESTORE</span>';
  }

  const item = document.createElement('div');
  item.className = 'p-2 rounded bg-slate-50 border border-slate-200 flex items-start space-x-2 text-[11px] font-mono';
  item.innerHTML = `
    <span class="text-slate-400">[${time}]</span>
    ${badge}
    <span class="text-slate-800 font-bold">${deviceId}:</span>
    <span class="text-slate-600 flex-1">${text}</span>
  `;

  logCont.insertBefore(item, logCont.firstChild);
  if (logCont.children.length > 20) {
    logCont.removeChild(logCont.lastChild);
  }
}


/* ==========================================================
   8. BLOCKCHAIN ENGINE & MINING (Tab 4)
   ========================================================== */
async function mineNewBlock(deviceId, action, payload, validator = 'Val-01 [Edge Node A]') {
  const lastBlock = State.blockchain[State.blockchain.length - 1];
  const newIndex = (lastBlock ? lastBlock.index : 0) + 1;
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const prevHash = lastBlock ? lastBlock.hash : '0000000000000000000000000000000000000000000000000000000000000000';
  const nonce = Math.floor(Math.random() * 900) + 100;

  const dataToHash = `${newIndex}-${timestamp}-${deviceId}-${action}-${JSON.stringify(payload)}-${prevHash}-${nonce}`;
  const rawHash = await calculateSHA256(dataToHash);
  const currentHash = '0000' + rawHash.substring(4);

  const block = {
    index: newIndex,
    timestamp: timestamp,
    deviceId: deviceId,
    action: action,
    validator: validator,
    payload: payload,
    previousHash: prevHash,
    hash: currentHash,
    nonce: nonce
  };

  State.blockchain.push(block);
  updateKPIs();
  if (window.SupabaseService && SupabaseService.isConnected) {
    SupabaseService.insertBlock(block);
  }
  return block;
}

function renderBlockchainCards() {
  const container = document.getElementById('blockchainCardsContainer');
  if (!container) return;

  // Performance optimization: Only render cards when Tab 4 (Blockchain) is active
  if (State.activeTab !== 'tab-blockchain') return;

  const search = (document.getElementById('blockSearchInput')?.value || '').toLowerCase();
  container.innerHTML = '';

  const filtered = State.blockchain.filter(b => {
    return b.index.toString().includes(search) ||
           b.deviceId.toLowerCase().includes(search) ||
           b.hash.toLowerCase().includes(search) ||
           b.action.toLowerCase().includes(search);
  });

  // Limit rendering to latest 40 blocks to maintain 60 FPS
  const displayBlocks = filtered.slice(-40).reverse();

  displayBlocks.forEach(block => {
    const card = document.createElement('div');
    
    const isTampered = State.isChainTampered && (
      block.index === State.tamperedBlockIndex || block.index > State.tamperedBlockIndex
    );

    let borderClass = isTampered ? 'border-red-400 bg-red-50/60' : 'border-slate-200 bg-white shadow-xs';
    let statusBadge = '<span class="px-2 py-0.5 rounded badge-verified text-[10px] font-mono">VALID CONSENSUS</span>';

    if (isTampered) {
      if (block.index === State.tamperedBlockIndex) {
        statusBadge = '<span class="px-2 py-0.5 rounded badge-quarantined text-[10px] font-mono">TAMPERED FORGERY</span>';
      } else {
        statusBadge = '<span class="px-2 py-0.5 rounded badge-quarantined text-[10px] font-mono">CHAIN INVALIDATED</span>';
      }
    }

    let actionBadgeColor = 'bg-slate-100 text-slate-700 border-slate-200';
    if (block.action === 'GENESIS') actionBadgeColor = 'bg-emerald-50 text-emerald-700 border-emerald-200';
    else if (block.action === 'NODE_QUARANTINED') actionBadgeColor = 'bg-red-50 text-red-700 border-red-200';
    else if (block.action === 'NODE_REGISTERED') actionBadgeColor = 'bg-blue-50 text-blue-700 border-blue-200';
    else if (block.action === 'DATASET_INGEST') actionBadgeColor = 'bg-purple-50 text-purple-700 border-purple-200';

    card.className = `panel-card p-4 space-y-3 ${borderClass} transition font-mono text-xs relative`;

    card.innerHTML = `
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-2.5">
        <div class="flex items-center space-x-2">
          <span class="w-6 h-6 rounded bg-slate-100 border border-slate-200 flex items-center justify-center font-bold text-slate-800 text-xs">
            #${block.index}
          </span>
          <div>
            <span class="px-2 py-0.2 rounded text-[10px] font-mono uppercase tracking-wider ${actionBadgeColor} border">
              ${block.action}
            </span>
            <span class="text-slate-500 text-[11px] ml-2">Device: <strong class="text-slate-800">${block.deviceId}</strong></span>
          </div>
        </div>

        <div class="flex items-center space-x-2 text-[11px]">
          ${statusBadge}
          <span class="text-slate-500">${block.timestamp}</span>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
        <div>
          <span class="text-slate-500 block text-[10px] uppercase tracking-wider mb-1 font-semibold">Previous Hash</span>
          <div class="p-1.5 rounded bg-slate-50 border border-slate-200 text-slate-600 truncate select-all">
            ${block.previousHash}
          </div>
        </div>
        <div>
          <span class="text-slate-500 block text-[10px] uppercase tracking-wider mb-1 font-semibold">Block SHA-256 Hash</span>
          <div class="p-1.5 rounded bg-slate-50 border border-slate-200 ${isTampered ? 'text-red-600 font-semibold' : 'text-slate-800'} truncate select-all">
            ${block.hash}
          </div>
        </div>
      </div>

      <div class="bg-slate-50 p-2.5 rounded border border-slate-200 text-[11px] space-y-1">
        <div class="flex items-center justify-between text-slate-400">
          <span>Validator: <strong class="text-slate-300">${block.validator}</strong></span>
          <span>Nonce: <strong class="text-slate-300">${block.nonce}</strong></span>
        </div>
        <div class="text-slate-500 pt-0.5">Payload Data:</div>
        <pre class="text-slate-800 text-[11px] overflow-x-auto whitespace-pre-wrap font-mono">${JSON.stringify(block.payload, null, 2)}</pre>
      </div>

      <div class="pt-2 border-t border-slate-100 flex items-center justify-between">
        <span class="text-[10px] text-slate-500">PoA Consensus Round: #0${block.index + 10}</span>
        <button onclick="openTamperModal(${block.index})" class="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-red-600 border border-slate-300 text-[11px] font-medium transition active:scale-95 shadow-xs">
          Tamper Payload
        </button>
      </div>
    `;

    container.appendChild(card);
  });

  if (filtered.length > 40) {
    const info = document.createElement('div');
    info.className = 'text-center text-xs font-mono text-slate-500 py-3 col-span-full border-t border-slate-200';
    info.textContent = `Showing latest 40 of ${filtered.length} total blocks in cryptographic ledger`;
    container.appendChild(info);
  }

  safeCreateIcons({ root: container });
}

async function verifyChainIntegrity() {
  let brokenIndex = null;

  for (let i = 1; i < State.blockchain.length; i++) {
    const current = State.blockchain[i];
    const previous = State.blockchain[i - 1];

    if (current.previousHash !== previous.hash) {
      brokenIndex = current.index;
      break;
    }
  }

  // If last block was modified or marked tampered
  if (brokenIndex === null && State.isChainTampered && State.tamperedBlockIndex !== null) {
    brokenIndex = State.tamperedBlockIndex;
  }

  const alertBanner = document.getElementById('tamperAlertBanner');
  const alertInfo = document.getElementById('tamperedBlockInfo');

  if (brokenIndex !== null) {
    State.isChainTampered = true;
    State.tamperedBlockIndex = brokenIndex - 1;
    if (alertBanner) alertBanner.classList.remove('hidden');
    if (alertInfo) alertInfo.textContent = `Tampered Invalidation at Block #${State.tamperedBlockIndex}`;
    showToast('Ledger Integrity Failure!', `Cryptographic mismatch found at Block #${brokenIndex}. Chain invalidated!`, 'error');
    playSound('alarm');
  } else {
    State.isChainTampered = false;
    State.tamperedBlockIndex = null;
    if (alertBanner) alertBanner.classList.add('hidden');
    showToast('Blockchain 100% Valid!', `All ${State.blockchain.length} blocks successfully verified with SHA-256 consensus.`, 'success');
    playSound('success');
  }

  renderBlockchainCards();
}

function restoreLedger() {
  State.blockchain = JSON.parse(JSON.stringify(State.canonicalBackup));
  State.isChainTampered = false;
  State.tamperedBlockIndex = null;
  const alertBanner = document.getElementById('tamperAlertBanner');
  if (alertBanner) alertBanner.classList.add('hidden');
  renderBlockchainCards();
  updateKPIs();
  showToast('Consensus Restored', 'Canonical blockchain ledger restored from consensus validators.', 'success');
}


/* ==========================================================
   9. ATTACK SIMULATION ENGINE (Tab 3 Scenarios)
   ========================================================== */
function animatePipeline(step1Text, step2Score, step2Decision, step3Status, isSuccess = true) {
  const pBadge = document.getElementById('pipelineStatusBadge');
  const p1 = document.getElementById('pipeStep1');
  const p2 = document.getElementById('pipeStep2');
  const p3 = document.getElementById('pipeStep3');

  if (!pBadge || !p1 || !p2 || !p3) return;

  pBadge.textContent = 'Analyzing Packet...';
  pBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800';

  p1.classList.add('pipeline-step-active');
  setTimeout(() => {
    p1.classList.remove('pipeline-step-active');
    p2.classList.add(isSuccess ? 'pipeline-step-success' : 'pipeline-step-danger');
    
    document.getElementById('pipeAnomalyScore').textContent = step2Score;
    document.getElementById('pipeAnomalyScore').className = isSuccess ? 'font-bold text-emerald-400' : 'font-bold text-red-400';
    document.getElementById('pipeDecision').textContent = step2Decision;
    document.getElementById('pipeDecision').className = isSuccess ? 'text-emerald-400 font-medium' : 'text-red-400 font-medium';

    setTimeout(() => {
      p2.classList.remove('pipeline-step-success', 'pipeline-step-danger');
      if (isSuccess) {
        p3.classList.add('pipeline-step-success');
        document.getElementById('pipeLedgerStatus').textContent = step3Status;
        document.getElementById('pipeLedgerStatus').className = 'text-emerald-400 font-semibold';
        pBadge.textContent = 'Consensus Confirmed';
        pBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800';
        setTimeout(() => p3.classList.remove('pipeline-step-success'), 1200);
      } else {
        p3.classList.add('pipeline-step-danger');
        document.getElementById('pipeLedgerStatus').textContent = 'REJECTED - NOT MINED';
        document.getElementById('pipeLedgerStatus').className = 'text-red-400 font-semibold';
        pBadge.textContent = 'Threat Intercepted at Edge';
        pBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800';
        setTimeout(() => p3.classList.remove('pipeline-step-danger'), 1200);
      }
    }, 500);
  }, 400);
}

// Scenario 1: Legitimate Data
async function triggerLegitData() {
  const targetId = document.getElementById('simTargetNodeSelect')?.value || (State.nodes[0] ? State.nodes[0].id : null);
  const node = State.nodes.find(n => n.id === targetId) || State.nodes[0];

  if (!node) {
    showToast('No Devices Staged', 'Please upload a dataset or register an IoT endpoint first.', 'warning');
    openUploadModal();
    return;
  }

  if (node.status === 'Quarantined') {
    showToast('Node Quarantined!', `Device ${node.id} is in quarantine and cannot transmit data. Restore it first.`, 'error');
    return;
  }

  const temp = (20 + Math.random() * 8).toFixed(1);
  const payload = { temp_c: parseFloat(temp), pressure_kpa: 101.3, state: "NOMINAL" };
  const anomaly = (Math.random() * 0.12).toFixed(2);

  animatePipeline(
    JSON.stringify(payload),
    `${anomaly} [LOW RISK]`,
    'ALLOW_FORWARD',
    'VERIFIED IMMUTABLE',
    true
  );

  const blk = await mineNewBlock(node.id, 'DATA_LOG', payload, 'Val-01 [Edge Gatekeeper]');

  addTerminalLog(node.id, payload, parseFloat(anomaly), 'PASS', `Block #${blk.index} Mined`);
  State.trafficStats.normal++;
  updateDoughnutUI();
  renderBlockchainCards();

  showToast('Legitimate Data Verified', `Payload from ${node.id} passed TinyML check and hashed into Block #${blk.index}`, 'success');
}

// Scenario 2: DDoS Flood Attack
async function triggerDDoSFlood() {
  const targetId = document.getElementById('simTargetNodeSelect')?.value || (State.nodes[0] ? State.nodes[0].id : null);
  const node = State.nodes.find(n => n.id === targetId) || State.nodes[0];
  if (!node) {
    showToast('No Devices Staged', 'Please upload a dataset or register an IoT endpoint first.', 'warning');
    openUploadModal();
    return;
  }

  const anomaly = (0.94 + Math.random() * 0.05).toFixed(2);

  animatePipeline(
    '{flood_burst: 1000_req/sec}',
    `${anomaly} [CRITICAL FREQ SPIKE]`,
    'EDGE_DROP_AND_QUARANTINE',
    'REJECTED',
    false
  );

  State.totalIntrusionsBlocked += 5;
  State.trafficStats.ddos += 5;
  updateDoughnutUI();

  quarantineNode(node.id, 'DDoS High Packet Frequency Threshold Exceeded (>0.92)');
  addTerminalLog(node.id, '{BURST_ATTACK: 1200 packets/sec}', parseFloat(anomaly), 'DROP', 'Edge dropped packets; Smart Contract quarantined node');

  showToast('DDoS Threat Neutralized!', `Edge TinyML detected packet frequency anomaly (${anomaly}). Attacker ${node.id} automatically quarantined!`, 'threat');
}

// Scenario 3: MAC Spoofing
function triggerMACSpoof() {
  const fakeMAC = '0xBAD0DE4D' + Math.random().toString(16).substring(2, 10).toUpperCase() + '00';
  const anomaly = (0.87 + Math.random() * 0.08).toFixed(2);

  animatePipeline(
    `{rogue_mac: "${fakeMAC}"}`,
    `${anomaly} [UNRECOGNIZED SIGNATURE]`,
    'REJECT_SIGNATURE',
    'REJECTED',
    false
  );

  State.totalIntrusionsBlocked++;
  State.trafficStats.spoof++;
  updateDoughnutUI();

  addTerminalLog('ROGUE-NODE', `{spoofed_mac: "${fakeMAC}"}`, parseFloat(anomaly), 'DROP', 'Identity verification failed at Smart Contract');
  logSecurityIncident('ROGUE-MAC', 'WARNING', `Unregistered hardware signature attempted injection (${fakeMAC}). Access denied.`);

  showToast('MAC Spoofing Rejected', `Smart Contract rejected transaction from uncertified hardware address ${fakeMAC.substring(0, 10)}...`, 'warning');
}

// Scenario 4: MITM Payload Tampering
function triggerMITMTamper() {
  const targetId = document.getElementById('simTargetNodeSelect')?.value || (State.nodes[0] ? State.nodes[0].id : 'IOT-ESP32-MTR01');
  const anomaly = (0.91 + Math.random() * 0.06).toFixed(2);

  animatePipeline(
    '{"temp": 140.0, "forged_sig": true}',
    `${anomaly} [PAYLOAD HASH MISMATCH]`,
    'HASH_VERIFY_FAILED',
    'REJECTED',
    false
  );

  State.totalIntrusionsBlocked++;
  State.trafficStats.tamper++;
  updateDoughnutUI();

  addTerminalLog(targetId, '{"tampered_temp": 140.0, "sig_err": true}', parseFloat(anomaly), 'DROP', 'Hash mismatch between Edge signature and sensor payload');
  logSecurityIncident(targetId, 'WARNING', `In-transit payload corruption or MITM tampering detected. Packet discarded.`);

  showToast('MITM Tampering Detected', 'Cryptographic hash mismatch! In-transit sensor alteration dropped before consensus.', 'threat');
}


/* ==========================================================
   10. LIVE TRAFFIC SIMULATOR INTERVAL
   ========================================================== */
function runLiveSimulationTick() {
  if (!State.liveSimulation) return;

  const verifiedNodes = State.nodes.filter(n => n.status === 'Verified');
  if (verifiedNodes.length === 0) return;

  const randomNode = verifiedNodes[Math.floor(Math.random() * verifiedNodes.length)];
  const roll = Math.random();

  const newEdge = parseFloat((3.6 + Math.random() * 1.2).toFixed(1));
  const newCloud = parseFloat((82.0 + Math.random() * 12.0).toFixed(1));

  State.edgeLatency = newEdge;
  State.cloudLatency = newCloud;
  
  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setTxt('topEdgeLatency', `${newEdge} ms`);
  setTxt('kpiEdgeLatency', `${newEdge} ms`);
  setTxt('kpiCloudLatency', `${newCloud} ms`);

  if (latencyChart) {
    latencyChart.data.datasets[0].data.shift();
    latencyChart.data.datasets[0].data.push(newEdge);
    latencyChart.data.datasets[1].data.shift();
    latencyChart.data.datasets[1].data.push(newCloud);
    latencyChart.update('none');
  }

  const util = Math.floor(25 + Math.random() * 30);
  const utilText = document.getElementById('bufferUtilText');
  const utilBar = document.getElementById('bufferUtilBar');
  if (utilText) utilText.textContent = `${util}%`;
  if (utilBar) utilBar.style.width = `${util}%`;

  if (roll < 0.88) {
    // Generate realistic telemetry tailored to user's uploaded device type
    let payload;
    const typeLower = (randomNode.type || '').toLowerCase();
    if (typeLower.includes('meter') || typeLower.includes('energy') || typeLower.includes('power')) {
      payload = { voltage_v: parseFloat((228 + Math.random() * 6).toFixed(1)), current_a: parseFloat((12 + Math.random() * 5).toFixed(1)), freq_hz: 50.0 };
    } else if (typeLower.includes('temp') || typeLower.includes('vibration') || typeLower.includes('vib')) {
      payload = { temp_c: parseFloat((65 + Math.random() * 12).toFixed(1)), vibration_g: parseFloat((0.02 + Math.random() * 0.04).toFixed(3)) };
    } else if (typeLower.includes('actuator') || typeLower.includes('valve') || typeLower.includes('hydraulic')) {
      payload = { valve_pos_pct: parseFloat((30 + Math.random() * 25).toFixed(1)), hydraulic_psi: Math.floor(2100 + Math.random() * 80) };
    } else if (typeLower.includes('cam') || typeLower.includes('surveillance') || typeLower.includes('video')) {
      payload = { fps: 30, bitrate_kbps: Math.floor(3800 + Math.random() * 500), codec: "H.265" };
    } else if (typeLower.includes('gas') || typeLower.includes('pressure')) {
      payload = { pressure_kpa: parseFloat((101.2 + Math.random() * 0.8).toFixed(1)), status: "NOMINAL" };
    } else {
      payload = { reading: parseFloat((20 + Math.random() * 15).toFixed(1)), protocol: randomNode.protocol || 'MQTT', status: "NOMINAL" };
    }

    const anomaly = (Math.random() * 0.14).toFixed(2);

    mineNewBlock(randomNode.id, 'DATA_LOG', payload, 'Val-01 [Edge Gatekeeper]').then(blk => {
      addTerminalLog(randomNode.id, payload, parseFloat(anomaly), 'PASS', `Consensus Verified (#${blk.index})`);
      State.trafficStats.normal++;
      updateDoughnutUI();
      if (State.activeTab === 'tab-blockchain') renderBlockchainCards();
    });
  } else {
    const anomaly = (0.72 + Math.random() * 0.15).toFixed(2);
    State.totalIntrusionsBlocked++;
    State.trafficStats.ddos++;
    updateKPIs();
    updateDoughnutUI();
    addTerminalLog(randomNode.id, '{rate_limit_exceeded: true}', parseFloat(anomaly), 'DROP', 'Filtered by Edge Gatekeeper Rate-Limiter');
  }
}

function startSimulation() {
  if (State.simTimerId) clearInterval(State.simTimerId);
  State.simTimerId = setInterval(runLiveSimulationTick, State.simulationIntervalMs);
  State.liveSimulation = true;

  const btn = document.getElementById('toggleTrafficBtn');
  if (!btn) return;
  btn.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-red-600 text-white hover:bg-red-700 transition active:scale-95 border border-red-500';
  document.getElementById('trafficStatusText').textContent = 'Live Traffic: RUNNING';
  document.getElementById('trafficIcon').setAttribute('data-lucide', 'pause');
  safeCreateIcons({ root: btn });
}

function pauseSimulation() {
  if (State.simTimerId) clearInterval(State.simTimerId);
  State.simTimerId = null;
  State.liveSimulation = false;

  const btn = document.getElementById('toggleTrafficBtn');
  if (!btn) return;
  btn.className = 'flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-slate-800 text-slate-300 hover:text-white transition active:scale-95 border border-slate-700';
  document.getElementById('trafficStatusText').textContent = 'Live Traffic: PAUSED';
  document.getElementById('trafficIcon').setAttribute('data-lucide', 'play');
  safeCreateIcons({ root: btn });
}


/* ==========================================================
   11. DATASET UPLOAD & INGESTION ENGINE
   ========================================================== */
function parseCSV(text) {
  const clean = (text || '').replace(/^\uFEFF/, '').trim();
  if (!clean) throw new Error("CSV file is empty.");

  const lines = clean.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length < 2) throw new Error("CSV file must contain a header row and at least one data row.");

  // Auto-detect delimiter: comma, semicolon, or tab
  let delim = ',';
  const firstLine = lines[0];
  const commaCount = (firstLine.match(/,/g) || []).length;
  const semiCount = (firstLine.match(/;/g) || []).length;
  const tabCount = (firstLine.match(/\t/g) || []).length;
  if (semiCount > commaCount && semiCount > tabCount) delim = ';';
  else if (tabCount > commaCount && tabCount > semiCount) delim = '\t';

  // RFC 4180 quote-aware column splitter
  function splitLine(line, delimiter) {
    const values = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"' || char === "'") {
        if (inQuotes && line[i + 1] === char) {
          current += char;
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === delimiter && !inQuotes) {
        values.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    values.push(current.trim());
    return values;
  }

  const rawHeaders = splitLine(lines[0], delim);
  const normalizedHeaders = rawHeaders.map(h =>
    h.toLowerCase().replace(/['"]/g, '').replace(/[\s\-_]+/g, '_').trim()
  );

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const values = splitLine(lines[i], delim);
    const obj = {};
    normalizedHeaders.forEach((h, idx) => {
      let val = values[idx] !== undefined ? values[idx].replace(/^['"]|['"]$/g, '').trim() : '';
      obj[h] = val;
      const compactKey = h.replace(/_/g, '');
      if (compactKey !== h) obj[compactKey] = val;
    });
    rows.push(obj);
  }
  return rows;
}

/* ==========================================================
   DATASET UPLOAD & THREAT TEST REVEAL CONTROLLER
   ========================================================== */
function revealCharts() {
  State.chartsVisible = true;
  const chartsCont = document.getElementById('overviewChartsContainer');
  const placeholder = document.getElementById('chartsPendingThreatTestPlaceholder');
  if (chartsCont) chartsCont.classList.remove('hidden');
  if (placeholder) placeholder.classList.add('hidden');

  if (!latencyChart || !trafficDoughnutChart) {
    initCharts();
  } else {
    latencyChart.resize();
    latencyChart.update('none');
    updateDoughnutUI();
  }
  safeCreateIcons();
}

function hideChartsForDatasetUpload() {
  if (State.nodes && State.nodes.length > 0) {
    revealCharts();
    return;
  }
  State.chartsVisible = false;
  const chartsCont = document.getElementById('overviewChartsContainer');
  const placeholder = document.getElementById('chartsPendingThreatTestPlaceholder');
  if (chartsCont) chartsCont.classList.add('hidden');
  if (placeholder) {
    placeholder.classList.remove('hidden');
    const titleEl = document.getElementById('placeholderThreatTitle');
    const pEl = document.getElementById('placeholderThreatText');
    const btnSpan = document.getElementById('placeholderBtnText');
    if (titleEl) titleEl.textContent = 'No Dataset Loaded: Awaiting IoT Data Ingestion';
    if (pEl) pEl.textContent = 'Please upload an IoT dataset (.json or .csv) or register endpoints. Once staged, you can execute edge threat testing to generate telemetry latency and anomaly graphs.';
    if (btnSpan) btnSpan.textContent = 'Upload Dataset to Begin';
  }
  safeCreateIcons();
}

async function executeThreatTestAndRevealCharts() {
  if (!State.nodes || State.nodes.length === 0) {
    showToast('No Dataset Loaded', 'Please upload an IoT dataset (.json or .csv) to begin telemetry testing.', 'warning');
    openUploadModal();
    return;
  }
  showToast('Running Threat Test...', 'Injecting test vectors across edge nodes to validate anomaly filters.', 'info');

  const targetNode = State.nodes[0] || { id: 'IOT-ESP32-MTR01', name: 'Sensor 01' };
  const isThreat = Math.random() > 0.45;
  const anomalyScore = isThreat ? (0.88 + Math.random() * 0.08) : (0.04 + Math.random() * 0.08);

  animatePipeline(
    JSON.stringify({ dataset_test: "threat_vector_scan", target: targetNode.id, val: 38.6 }),
    `${anomalyScore.toFixed(2)} [${isThreat ? 'SUSPICIOUS' : 'NOMINAL'}]`,
    isThreat ? 'EDGE_DROP_AND_QUARANTINE' : 'FORWARD_TO_CONSENSUS',
    isThreat ? 'REJECTED - NOT MINED' : 'COMMITTED',
    !isThreat
  );

  addTerminalLog(
    targetNode.id,
    { audit: 'DATASET_THREAT_SCAN', anomaly_score: anomalyScore.toFixed(2) },
    anomalyScore,
    isThreat ? 'FLAGGED' : 'PASS',
    'Automated Threat Benchmark Executed'
  );

  if (isThreat) {
    State.totalIntrusionsBlocked++;
    State.trafficStats.ddos = Math.max(State.trafficStats.ddos, 14);
  } else {
    State.trafficStats.normal += 20;
  }

  revealCharts();
  updateKPIs();
  playSound('success');
  showToast('Threat Test Completed!', 'Edge telemetry verification benchmarks & anomaly charts are now active.', 'success');
}

async function processUploadedDataset(fileContent, fileName, isCSV = false) {
  const cleanText = (fileContent || '').replace(/^\uFEFF/, '').trim();
  if (!cleanText) {
    showToast('Empty File', 'The uploaded file contains no data.', 'warning');
    return;
  }

  State.isIngestingDataset = true;
  let parsedNodes = [];
  let parsedTelemetry = [];
  let datasetTitle = (fileName || 'Uploaded_Dataset').replace(/\.[^/.]+$/, "");
  let trafficStatsOverride = null;

  try {
    const looksLikeJSON = cleanText.startsWith('{') || cleanText.startsWith('[');
    const parseAsJSON = looksLikeJSON && (!isCSV || (fileName && fileName.toLowerCase().endsWith('.json')));

    if (parseAsJSON) {
      let data;
      try {
        data = JSON.parse(cleanText);
      } catch (jsonErr) {
        throw new Error(`JSON Syntax Error: ${jsonErr.message}`);
      }

      datasetTitle = data.datasetName || data.name || data.title || datasetTitle;

      let candidateNodes = [];
      if (Array.isArray(data)) {
        candidateNodes = data;
      } else if (typeof data === 'object' && data !== null) {
        candidateNodes = data.nodes || data.devices || data.sensors || data.endpoints || data.records || data.data || data.items || data.rows || data.results || [];
        if (Array.isArray(data.telemetry)) {
          parsedTelemetry = data.telemetry;
        } else if (Array.isArray(data.packets)) {
          parsedTelemetry = data.packets;
        } else if (Array.isArray(data.events)) {
          parsedTelemetry = data.events;
        }
        if (data.trafficStats) {
          trafficStatsOverride = data.trafficStats;
        }
      }

      if (candidateNodes.length > 0) {
        candidateNodes.forEach((item, idx) => {
          if (!item || typeof item !== 'object') return;
          const id = item.id || item.device_id || item.deviceId || item.device || item.node_id || item.sensor_id || `IOT-NODE-${idx + 1}`;
          const name = item.name || item.device_name || item.deviceName || item.label || item.sensor_name || `Device ${idx + 1}`;
          const type = item.type || item.device_type || item.deviceType || item.sensor_type || item.category || 'Industrial Sensor';
          const protocol = (item.protocol || item.network || 'MQTT').toUpperCase();
          const mac = item.mac || item.mac_address || item.hardware_id || item.hardwareId || generateRandomHex(40);
          const rawTrust = item.trustScore ?? item.trust_score ?? item.trust;
          const trust = rawTrust !== undefined ? parseInt(rawTrust) : 95;
          const status = item.status || (trust < 50 ? 'Quarantined' : 'Verified');
          const rawAnomaly = item.anomalyScore ?? item.anomaly_score ?? item.anomaly;
          const anomaly = rawAnomaly !== undefined ? parseFloat(rawAnomaly) : (trust < 50 ? 0.94 : 0.04);

          parsedNodes.push({
            id: String(id),
            name: String(name),
            type: String(type),
            mac: String(mac),
            protocol: String(protocol),
            trustScore: isNaN(trust) ? 90 : trust,
            status: String(status),
            lastSeen: 'Just now',
            anomalyScore: isNaN(anomaly) ? 0.05 : anomaly
          });

          if (item.reading || item.payload || item.telemetry || item.reading_val || item.value) {
            parsedTelemetry.push({
              deviceId: String(id),
              payload: item.payload || { reading: item.reading || item.reading_val || item.value || 25.4 },
              anomalyScore: isNaN(anomaly) ? 0.05 : anomaly,
              action: anomaly >= 0.85 ? 'DROP' : 'PASS',
              message: anomaly >= 0.85 ? 'Anomaly threshold exceeded at edge' : 'Telemetry validated'
            });
          }
        });
      } else if (parsedTelemetry.length > 0) {
        const devMap = new Map();
        parsedTelemetry.forEach((t, idx) => {
          const id = t.deviceId || t.device_id || t.id || t.sensor_id || `IOT-NODE-${idx + 1}`;
          if (!devMap.has(id)) {
            devMap.set(id, {
              id: String(id),
              name: t.name || t.device_name || `IoT Endpoint (${id})`,
              type: t.type || 'Telemetry Node',
              mac: t.mac || generateRandomHex(40),
              protocol: (t.protocol || 'MQTT').toUpperCase(),
              trustScore: 95,
              status: 'Verified',
              lastSeen: 'Just now',
              anomalyScore: parseFloat(t.anomalyScore || 0.05)
            });
          }
        });
        parsedNodes = Array.from(devMap.values());
      } else if (typeof data === 'object' && data !== null) {
        Object.entries(data).forEach(([key, val]) => {
          if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
            parsedNodes.push({
              id: val.id || val.device_id || key,
              name: val.name || val.device_name || key,
              type: val.type || 'IoT Node',
              mac: val.mac || generateRandomHex(40),
              protocol: (val.protocol || 'MQTT').toUpperCase(),
              trustScore: parseInt(val.trustScore || val.trust_score || 95),
              status: val.status || 'Verified',
              lastSeen: 'Just now',
              anomalyScore: parseFloat(val.anomalyScore || 0.05)
            });
          }
        });
      }

    } else {
      // CSV Parsing
      const csvRows = parseCSV(cleanText);
      csvRows.forEach((row, idx) => {
        const id = row.device_id || row.deviceid || row.id || row.deviceId || row.device || row.sensor_id || row.node || `IOT-CSV-NODE-${idx + 1}`;
        const name = row.device_name || row.devicename || row.name || row.deviceName || row.label || `Field Sensor Node ${idx + 1}`;
        const type = row.type || row.device_type || row.devicetype || row.category || 'Industrial Sensor';
        const protocol = (row.protocol || row.network || 'MQTT').toUpperCase();
        const mac = row.mac || row.mac_address || row.macaddress || generateRandomHex(40);
        const rawTrust = row.trust_score || row.trustscore || row.trust || row.trustScore;
        const trust = rawTrust !== undefined ? parseInt(rawTrust) : 95;
        const status = row.status || (trust < 50 ? 'Quarantined' : 'Verified');
        const rawAnomaly = row.anomaly_score || row.anomalyscore || row.anomaly || row.anomalyScore;
        const anomaly = rawAnomaly !== undefined ? parseFloat(rawAnomaly) : (trust < 50 ? 0.94 : 0.04);

        parsedNodes.push({
          id: String(id),
          name: String(name),
          type: String(type),
          mac: String(mac),
          protocol: String(protocol),
          trustScore: isNaN(trust) ? 90 : trust,
          status: String(status),
          lastSeen: 'Just now',
          anomalyScore: isNaN(anomaly) ? 0.05 : anomaly
        });

        const readingVal = row.reading_val || row.readingval || row.reading || row.val || row.value || '25.4';
        const readingUnit = row.reading_unit || row.readingunit || row.unit || 'C';
        parsedTelemetry.push({
          deviceId: String(id),
          payload: { reading: isNaN(Number(readingVal)) ? readingVal : parseFloat(readingVal), unit: readingUnit },
          anomalyScore: isNaN(anomaly) ? 0.05 : anomaly,
          action: anomaly >= 0.85 ? 'DROP' : 'PASS',
          message: anomaly >= 0.85 ? 'Anomaly threshold exceeded at edge' : 'Telemetry validated'
        });
      });
    }

    if (parsedNodes.length === 0) {
      throw new Error("No recognizable IoT devices found in dataset. Supported formats: JSON array/object or CSV.");
    }

    // Apply dataset to application state
    State.nodes = parsedNodes;
    State.datasetName = datasetTitle;
    State.isCustomDataset = true;

    if (trafficStatsOverride) {
      State.trafficStats = {
        normal: parseInt(trafficStatsOverride.normal) || 120,
        ddos: parseInt(trafficStatsOverride.ddos) || 0,
        spoof: parseInt(trafficStatsOverride.spoof) || 0,
        tamper: parseInt(trafficStatsOverride.tamper) || 0
      };
    } else {
      let normalCount = 0;
      let ddosCount = 0;
      parsedNodes.forEach(n => {
        if (n.status === 'Quarantined' || n.trustScore < 50) ddosCount += 5;
        else normalCount += 25;
      });
      State.trafficStats.normal = Math.max(normalCount, 150);
      State.trafficStats.ddos = ddosCount;
      State.trafficStats.spoof = Math.floor(Math.random() * 5) + 1;
      State.trafficStats.tamper = Math.floor(Math.random() * 3) + 1;
    }

    // Baseline latencies
    State.edgeLatency = 3.9;
    State.cloudLatency = 86.4;

    // Mine Ingestion Block for new dataset
    await mineNewBlock(
      'INGEST-ORCHESTRATOR',
      'DATASET_INGEST',
      {
        dataset: datasetTitle,
        nodesImported: parsedNodes.length,
        telemetryBatchCount: parsedTelemetry.length,
        timestamp: new Date().toISOString()
      },
      'Val-01 [Edge Gatekeeper]'
    );

    // Keep canonical chain in sync
    State.canonicalBackup = JSON.parse(JSON.stringify(State.blockchain));

    // Feed telemetry records into live terminal stream
    if (parsedTelemetry.length > 0) {
      parsedTelemetry.slice(0, 10).forEach(t => {
        const rawScore = t.anomalyScore !== undefined ? t.anomalyScore : 0.05;
        const scoreNum = (typeof rawScore === 'number' && !isNaN(rawScore)) ? rawScore : parseFloat(rawScore) || 0.05;
        addTerminalLog(
          t.deviceId || t.device_id || t.id || 'UPLOAD-NODE',
          t.payload || { status: 'BATCH_INGEST' },
          scoreNum,
          t.action || (scoreNum >= 0.85 ? 'DROP' : 'PASS'),
          t.message || 'Dataset Telemetry Ingested'
        );
      });
    }

    // Update UI components
    renderNodesTable();
    updateKPIs();
    updateDoughnutUI();

    // Show dataset status badge on Overview
    const datasetBanner = document.getElementById('activeDatasetBanner');
    if (datasetBanner) {
      datasetBanner.classList.remove('hidden');
      const nameEl = document.getElementById('activeDatasetName');
      const statsEl = document.getElementById('activeDatasetStats');
      if (nameEl) nameEl.textContent = datasetTitle;
      if (statsEl) statsEl.textContent = `${parsedNodes.length} Nodes loaded • ${parsedTelemetry.length} Telemetry records analyzed`;
    }

    // REVEAL CHARTS IMMEDIATELY with the uploaded dataset data!
    revealCharts();

    // Non-blocking background sync to cloud Supabase if connected
    if (window.SupabaseService && SupabaseService.isConnected) {
      Promise.resolve().then(async () => {
        try {
          await SupabaseService.batchUpsertNodes(parsedNodes);
          await SupabaseService.insertLog('INFO', 'Dataset-Ingestion', `Imported ${parsedNodes.length} devices from ${datasetTitle}`);
        } catch (e) {
          console.warn('[Supabase Sync Non-Fatal]', e);
        }
      });
    }

    showToast('Dataset Ingested & Active!', `Loaded ${parsedNodes.length} devices from "${fileName}". Operations and graphs are live.`, 'success');
    closeUploadModal();

  } catch (err) {
    console.error('[Upload Parser Error]', err);
    showToast('Dataset Parse Error', err.message || 'Could not parse dataset file.', 'error');
  } finally {
    State.isIngestingDataset = false;
  }
}

function handleDatasetFileUpload(file) {
  if (!file) return;
  const isCSV = file.name.toLowerCase().endsWith('.csv');
  const reader = new FileReader();

  reader.onload = function(e) {
    processUploadedDataset(e.target.result, file.name, isCSV);
  };
  reader.onerror = function() {
    showToast('File Read Error', 'Unable to read the selected file.', 'error');
  };
  reader.readAsText(file);
}

function resetToDemoDataset() {
  State.nodes = [];
  State.blockchain = JSON.parse(JSON.stringify(DEFAULT_DEMO_BLOCKS));
  State.canonicalBackup = JSON.parse(JSON.stringify(DEFAULT_DEMO_BLOCKS));
  State.datasetName = "No Dataset Staged";
  State.isCustomDataset = false;
  State.isIngestingDataset = false;
  State.totalIntrusionsBlocked = 0;
  State.trafficStats = { normal: 0, ddos: 0, spoof: 0, tamper: 0 };
  State.edgeLatency = 0.0;
  State.cloudLatency = 0.0;

  const datasetBanner = document.getElementById('activeDatasetBanner');
  if (datasetBanner) datasetBanner.classList.add('hidden');

  renderNodesTable();
  renderBlockchainCards();
  updateKPIs();
  updateDoughnutUI();

  hideChartsForDatasetUpload();

  showToast('Dataset Cleared', 'Active dataset removed. System returned to clean baseline ready for upload.', 'info');
}

function openUploadModal() {
  const modal = document.getElementById('uploadModal');
  if (modal) {
    modal.classList.remove('hidden');
    playSound('click');
    safeCreateIcons({ root: modal });
  }
}

function closeUploadModal() {
  const modal = document.getElementById('uploadModal');
  if (modal) modal.classList.add('hidden');
  const dropzoneSelectedFile = document.getElementById('dropzoneSelectedFile');
  if (dropzoneSelectedFile) {
    dropzoneSelectedFile.textContent = '';
    dropzoneSelectedFile.classList.add('hidden');
  }
}


/* ==========================================================
   12. NAVIGATION & MODALS
   ========================================================== */
const navHistory = [];

function switchTab(tabId, pushHistory = true) {
  if (pushHistory && State.activeTab !== tabId) {
    navHistory.push(State.activeTab);
  }
  State.activeTab = tabId;

  document.querySelectorAll('.tab-btn').forEach(btn => {
    const isCurrent = btn.getAttribute('data-tab') === tabId;
    if (isCurrent) {
      btn.className = 'tab-btn w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-semibold transition text-blue-600 bg-blue-50/60 border-l-2 border-blue-600';
    } else {
      btn.className = 'tab-btn w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition text-slate-600 hover:text-slate-900 hover:bg-slate-100 border-l-2 border-transparent';
    }
  });

  document.querySelectorAll('.tab-content').forEach(content => {
    if (content.id === tabId) {
      content.classList.remove('hidden');
    } else {
      content.classList.add('hidden');
    }
  });

  if (tabId === 'tab-blockchain') {
    renderBlockchainCards();
  } else if (tabId === 'tab-overview' && State.chartsVisible) {
    latencyChart?.resize();
    trafficDoughnutChart?.resize();
  }

  updateBackButtonUI();
  playSound('click');
}

function goBack() {
  if (navHistory.length > 0) {
    const prevTab = navHistory.pop();
    switchTab(prevTab, false);
  } else {
    switchTab('tab-overview', false);
  }
}

function updateBackButtonUI() {
  const btn = document.getElementById('globalBackBtn');
  if (!btn) return;
  if (State.activeTab === 'tab-overview' && navHistory.length === 0) {
    btn.classList.add('opacity-40', 'cursor-not-allowed');
    btn.disabled = true;
  } else {
    btn.classList.remove('opacity-40', 'cursor-not-allowed');
    btn.disabled = false;
  }
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
  }
  showToast('Copied!', `Cryptographic address copied to clipboard.`, 'info');
}

let currentTamperIndex = 0;
function openTamperModal(blockIndex) {
  currentTamperIndex = blockIndex;
  const block = State.blockchain.find(b => b.index === blockIndex);
  if (!block) return;

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setTxt('tamperBlockIndex', `#${block.index} (${block.action})`);
  setTxt('tamperGenuineHash', block.hash);
  const input = document.getElementById('tamperPayloadInput');
  if (input) input.value = JSON.stringify(block.payload, null, 2);

  const modal = document.getElementById('tamperModal');
  if (modal) modal.classList.remove('hidden');
  playSound('click');
}

function closeTamperModal() {
  const modal = document.getElementById('tamperModal');
  if (modal) modal.classList.add('hidden');
}


/* ==========================================================
   13. INITIALIZATION & EVENT LISTENERS
   ========================================================== */

/* ==========================================================
   SUPABASE INTEGRATION LOGIC & SYNC HELPERS
   ========================================================== */
async function syncFromSupabase() {
  if (!window.SupabaseService || !SupabaseService.isConnected) return;
  if (State.isCustomDataset) return; // User's custom dataset is strictly preserved!
  try {
    const remoteNodes = await SupabaseService.fetchNodes();
    if (remoteNodes && remoteNodes.length > 0 && !State.isCustomDataset) {
      State.nodes = remoteNodes;
      renderNodesTable();
      updateKPIs();
    }

    const remoteBlocks = await SupabaseService.fetchBlocks();
    if (remoteBlocks && remoteBlocks.length > 0 && !State.isCustomDataset) {
      State.blockchain = remoteBlocks.slice(-30);
      State.canonicalBackup = JSON.parse(JSON.stringify(State.blockchain));
      renderBlockchainCards();
      updateKPIs();
    }
  } catch (err) {
    console.warn('[Supabase Sync Warning]', err);
  }
}

// Global Realtime Listeners for Supabase Realtime WebSocket events
window.handleSupabaseNodeChange = function(payload) {
  if (State.isCustomDataset || State.isIngestingDataset) return;
  const { eventType, new: newRow, old: oldRow } = payload;
  if (eventType === 'INSERT') {
    if (!State.nodes.some(n => n.id === newRow.id)) {
      State.nodes.unshift({
        id: newRow.id,
        name: newRow.name,
        type: newRow.type,
        mac: newRow.mac,
        protocol: newRow.protocol || 'MQTT',
        trustScore: newRow.trust_score ?? 95,
        status: newRow.status || 'Verified',
        lastSeen: newRow.last_seen || 'Just now',
        anomalyScore: parseFloat(newRow.anomaly_score || 0.05)
      });
      renderNodesTable();
      updateKPIs();
      console.log(`[Cloud Sync] Device ${newRow.id} registered via Supabase.`);
    }
  } else if (eventType === 'UPDATE') {
    const target = State.nodes.find(n => n.id === newRow.id);
    if (target) {
      target.status = newRow.status;
      if (newRow.trust_score !== undefined) target.trustScore = newRow.trust_score;
      renderNodesTable();
      updateKPIs();
    }
  } else if (eventType === 'DELETE') {
    State.nodes = State.nodes.filter(n => n.id !== oldRow.id);
    renderNodesTable();
    updateKPIs();
  }
};

window.handleSupabaseBlockChange = function(payload) {
  const { new: newBlock } = payload;
  if (newBlock && !State.blockchain.some(b => b.index === newBlock.block_index)) {
    State.blockchain.push({
      index: newBlock.block_index,
      timestamp: newBlock.timestamp,
      deviceId: newBlock.device_id,
      action: newBlock.action,
      validator: newBlock.validator,
      payload: newBlock.payload,
      previousHash: newBlock.previous_hash,
      hash: newBlock.hash,
      nonce: newBlock.nonce
    });
    renderBlockchainCards();
    updateKPIs();
    console.log(`[Ledger] Block #${newBlock.block_index} synced from cloud ledger.`);
  }
};

function openSupabaseModal() {
  const modal = document.getElementById('supabaseModal');
  if (!modal) return;
  const urlInput = document.getElementById('supabaseUrlInput');
  const keyInput = document.getElementById('supabaseAnonKeyInput');
  const statusDot = document.getElementById('supabaseModalStatusDot');
  const statusText = document.getElementById('supabaseModalStatusText');

  if (window.SupabaseService) {
    if (urlInput) urlInput.value = SupabaseService.config.url || '';
    if (keyInput) keyInput.value = SupabaseService.config.anonKey || '';

    if (statusDot && statusText) {
      if (SupabaseService.isConnected) {
        statusDot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse';
        statusText.textContent = 'Status: Connected to Cloud PostgreSQL';
        statusText.className = 'text-emerald-400 font-medium';
      } else if (SupabaseService.isConfigured) {
        statusDot.className = 'w-2.5 h-2.5 rounded-full bg-amber-500';
        statusText.textContent = 'Status: Credential Error / Tables Not Found';
        statusText.className = 'text-amber-400 font-medium';
      } else {
        statusDot.className = 'w-2.5 h-2.5 rounded-full bg-slate-500';
        statusText.textContent = 'Status: In-Memory Fallback (No DB Connected)';
        statusText.className = 'text-slate-400 font-medium';
      }
    }
  }

  modal.classList.remove('hidden');
  safeCreateIcons({ root: modal });
}

function closeSupabaseModal() {
  document.getElementById('supabaseModal')?.classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {

  // 1. Initialize Icons & Charts safely
  if (typeof lucide !== 'undefined' && lucide.createIcons) {
    safeCreateIcons();
  }
  if (typeof Chart !== 'undefined') {
    initCharts();
  }

  // 2. Render initial tables & cards
  renderNodesTable();
  renderBlockchainCards();

  // Initial terminal system status
  addTerminalLog('GATEWAY-CORE', { status: 'ONLINE', ledger_height: 1 }, 0.00, 'PASS', 'PoA Consensus Engine Online - Awaiting Data Ingestion');

  // Start live simulation
  startSimulation();

  // Threat Test Button Listeners (Reveals charts after dataset upload)
  document.getElementById('overviewRunThreatBtn')?.addEventListener('click', executeThreatTestAndRevealCharts);
  document.getElementById('runThreatTestPlaceholderBtn')?.addEventListener('click', executeThreatTestAndRevealCharts);

  // Back Button Navigation
  document.getElementById('globalBackBtn')?.addEventListener('click', goBack);
  updateBackButtonUI();

  // 3. Tab switching events
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.getAttribute('data-tab'));
      const sb = document.getElementById('sidebar');
      if (sb) sb.classList.add('-translate-x-full');
    });
  });

  // Mobile Menu Toggle
  document.getElementById('mobileMenuBtn')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('-translate-x-full');
  });

  // Traffic Toggle
  document.getElementById('toggleTrafficBtn')?.addEventListener('click', () => {
    if (State.liveSimulation) {
      pauseSimulation();
    } else {
      startSimulation();
    }
  });

  // Sim Speed Selector
  document.getElementById('simSpeedSelect')?.addEventListener('change', (e) => {
    State.simulationIntervalMs = parseInt(e.target.value);
    if (State.liveSimulation) {
      startSimulation();
    }
  });

  // Audio Toggle
  document.getElementById('audioToggleBtn')?.addEventListener('click', () => {
    audioEnabled = !audioEnabled;
    const icon = document.getElementById('audioIcon');
    if (audioEnabled) {
      icon?.setAttribute('data-lucide', 'volume-2');
      showToast('Audio FX Enabled', 'Web Audio synthesized feedback is active.', 'info');
    } else {
      icon?.setAttribute('data-lucide', 'volume-x');
      showToast('Audio FX Muted', 'UI audio effects muted.', 'info');
    }
    const btn = document.getElementById('audioToggleBtn');
    if (btn) safeCreateIcons({ root: btn });
  });

  // Reset System
  document.getElementById('resetSystemBtn')?.addEventListener('click', resetToDemoDataset);

  // Search & Filters on Nodes Table
  document.getElementById('nodeSearchInput')?.addEventListener('input', renderNodesTable);
  document.getElementById('nodeStatusFilter')?.addEventListener('change', renderNodesTable);

  // Search Blocks
  document.getElementById('blockSearchInput')?.addEventListener('input', renderBlockchainCards);

  // Verify Ledger
  document.getElementById('verifyLedgerBtn')?.addEventListener('click', verifyChainIntegrity);
  document.getElementById('restoreLedgerBtn')?.addEventListener('click', restoreLedger);

  // Clear Terminal
  document.getElementById('clearTerminalBtn')?.addEventListener('click', () => {
    const feed = document.getElementById('liveTerminalFeed');
    if (feed) feed.innerHTML = '';
  });

  // Scenario Simulator Buttons
  document.getElementById('simLegitBtn')?.addEventListener('click', triggerLegitData);
  document.getElementById('simDDoSBtn')?.addEventListener('click', triggerDDoSFlood);
  document.getElementById('simSpoofBtn')?.addEventListener('click', triggerMACSpoof);
  document.getElementById('simTamperBtn')?.addEventListener('click', triggerMITMTamper);

  // Register Modal Events
  const regModal = document.getElementById('registerModal');
  document.getElementById('openRegisterModalBtn')?.addEventListener('click', () => {
    const walletInput = document.getElementById('regWalletAddress');
    if (walletInput) walletInput.value = generateRandomHex(40);
    regModal?.classList.remove('hidden');
    playSound('click');
  });

  document.getElementById('closeRegisterModalBtn')?.addEventListener('click', () => regModal?.classList.add('hidden'));
  document.getElementById('cancelRegisterModalBtn')?.addEventListener('click', () => regModal?.classList.add('hidden'));

  document.getElementById('regenerateKeyBtn')?.addEventListener('click', () => {
    const walletInput = document.getElementById('regWalletAddress');
    if (walletInput) walletInput.value = generateRandomHex(40);
    playSound('click');
  });

  document.getElementById('regTrustScore')?.addEventListener('input', (e) => {
    const val = document.getElementById('regTrustScoreVal');
    if (val) val.textContent = `${e.target.value}%`;
  });

  // Submit Register Form
  document.getElementById('registerNodeForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('regDeviceName').value;
    const type = document.getElementById('regDeviceType').value;
    const protocol = document.getElementById('regProtocol').value;
    const mac = document.getElementById('regWalletAddress').value;
    const trust = parseInt(document.getElementById('regTrustScore').value);

    const newId = `IOT-${type.substring(0, 3).toUpperCase()}-${Math.floor(100 + Math.random() * 899)}`;

    const newNode = {
      id: newId,
      name: name,
      type: type,
      mac: mac,
      protocol: protocol,
      trustScore: trust,
      status: 'Verified',
      lastSeen: 'Just now'
    };

    State.nodes.push(newNode);

    const blk = await mineNewBlock(
      newId,
      'NODE_REGISTERED',
      { name: name, type: type, protocol: protocol, mac: mac, trustInitial: trust },
      'Val-01 [Edge Gatekeeper]'
    );

    renderNodesTable();
    renderBlockchainCards();
    if (window.SupabaseService && SupabaseService.isConnected) {
      SupabaseService.upsertNode(newNode);
      SupabaseService.insertLog('INFO', 'Device-Registry', `Registered IoT endpoint ${newNode.id} (${newNode.name})`);
    }
    regModal?.classList.add('hidden');
    document.getElementById('registerNodeForm')?.reset();

    showToast('Node Registered on Blockchain!', `Device ${newId} anchored to Block #${blk.index} via Smart Contract.`, 'success');
  });

  // Tamper Modal Execution
  document.getElementById('closeTamperModalBtn')?.addEventListener('click', closeTamperModal);
  document.getElementById('cancelTamperModalBtn')?.addEventListener('click', closeTamperModal);

  document.getElementById('executeTamperBtn')?.addEventListener('click', async () => {
    const block = State.blockchain.find(b => b.index === currentTamperIndex);
    if (!block) return;

    try {
      const parsed = JSON.parse(document.getElementById('tamperPayloadInput').value);
      block.payload = parsed;

      const dataToHash = `${block.index}-${block.timestamp}-${block.deviceId}-${block.action}-${JSON.stringify(parsed)}-${block.previousHash}-${block.nonce}`;
      const newRaw = await calculateSHA256(dataToHash);
      block.hash = '0000' + newRaw.substring(4);

      State.isChainTampered = true;
      State.tamperedBlockIndex = block.index;

      closeTamperModal();
      document.getElementById('tamperAlertBanner')?.classList.remove('hidden');
      const info = document.getElementById('tamperedBlockInfo');
      if (info) info.textContent = `Tampered Forgery at Block #${block.index}`;
      renderBlockchainCards();

      showToast('Block Tampered!', `Payload modified at Block #${block.index}. SHA-256 hash changed; subsequent blocks invalidated!`, 'threat');
      playSound('glitch');
    } catch (err) {
      showToast('Invalid JSON', 'Please input valid JSON format into the payload box.', 'warning');
    }
  });

  // ==========================================
  // DATASET UPLOAD UI LISTENERS
  // ==========================================
  document.getElementById('openUploadModalBtn')?.addEventListener('click', openUploadModal);
  document.getElementById('overviewUploadBtn')?.addEventListener('click', openUploadModal);
  document.getElementById('registryUploadBtn')?.addEventListener('click', openUploadModal);
  document.getElementById('closeUploadModalBtn')?.addEventListener('click', closeUploadModal);
  document.getElementById('cancelUploadModalBtn')?.addEventListener('click', closeUploadModal);

  // Close upload modal on backdrop click
  document.getElementById('uploadModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'uploadModal') closeUploadModal();
  });

  // File Input & Dropzone Wiring
  const fileInput = document.getElementById('datasetFileInput');
  const dropzone = document.getElementById('datasetDropzone');
  const dropzoneSelectedFile = document.getElementById('dropzoneSelectedFile');

  // Clicking dropzone triggers file picker without bubbling recursion
  dropzone?.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput?.click();
  });

  fileInput?.addEventListener('click', (e) => {
    e.stopPropagation();
  });

  fileInput?.addEventListener('change', (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
      if (dropzoneSelectedFile) {
        dropzoneSelectedFile.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        dropzoneSelectedFile.classList.remove('hidden');
      }
      handleDatasetFileUpload(file);
      e.target.value = '';
    }
  });

  if (dropzone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('border-blue-500', 'bg-blue-50/60');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-blue-500', 'bg-blue-50/60');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const dt = e.dataTransfer;
      const file = dt && dt.files && dt.files[0];
      if (file) {
        if (dropzoneSelectedFile) {
          dropzoneSelectedFile.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
          dropzoneSelectedFile.classList.remove('hidden');
        }
        handleDatasetFileUpload(file);
      }
    });
  }

  // Prevent browser from navigating away if a file is dragged slightly outside dropzone
  window.addEventListener('dragover', (e) => e.preventDefault(), false);
  window.addEventListener('drop', (e) => e.preventDefault(), false);

  // Paste Raw Dataset Button
  document.getElementById('parseRawDatasetBtn')?.addEventListener('click', () => {
    const rawText = document.getElementById('rawDatasetTextarea')?.value.trim();
    if (!rawText) {
      showToast('Empty Input', 'Please paste JSON or CSV dataset content first.', 'warning');
      return;
    }
    const clean = rawText.replace(/^\uFEFF/, '').trim();
    const isCSV = !clean.startsWith('{') && !clean.startsWith('[');
    processUploadedDataset(clean, isCSV ? 'pasted_dataset.csv' : 'pasted_dataset.json', isCSV);
  });

  // Dataset Reset / Clear Button
  document.getElementById('resetToDemoBtn')?.addEventListener('click', resetToDemoDataset);


  // ==========================================
  // SUPABASE DATABASE INITIALIZATION & LISTENERS
  // ==========================================
  if (window.SupabaseService) {
    SupabaseService.init().then(connected => {
      if (connected) {
        console.log('[Supabase] Initialized & synchronized with cloud database.');
        syncFromSupabase();
      }
    });
  }

  document.getElementById('openSupabaseModalBtn')?.addEventListener('click', openSupabaseModal);
  document.getElementById('closeSupabaseModalBtn')?.addEventListener('click', closeSupabaseModal);

  document.getElementById('supabaseConfigForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('supabaseUrlInput')?.value.trim();
    const key = document.getElementById('supabaseAnonKeyInput')?.value.trim();
    const saveBtn = document.getElementById('saveSupabaseBtn');

    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.innerHTML = '<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i><span>Connecting...</span>';
      safeCreateIcons({ root: saveBtn });
    }

    try {
      const connected = await SupabaseService.saveCredentials(url, key);
      if (connected) {
        showToast('Connected to Supabase!', 'Successfully verified cloud PostgreSQL tables and Realtime channel.', 'success');
        await syncFromSupabase();
        closeSupabaseModal();
      } else {
        const testRes = await SupabaseService.testConnection();
        const msg = testRes.error || 'Please make sure you have executed supabase_schema.sql in your Supabase SQL Editor.';
        showToast('Connection Test Failed', msg, 'error');
        openSupabaseModal();
      }
    } catch (err) {
      showToast('Configuration Error', err.message, 'warning');
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i data-lucide="check" class="w-3.5 h-3.5"></i><span>Test & Save Connection</span>';
        safeCreateIcons({ root: saveBtn });
      }
    }
  });

  document.getElementById('disconnectSupabaseBtn')?.addEventListener('click', () => {
    if (window.SupabaseService) {
      SupabaseService.disconnect();
      showToast('Disconnected', 'Switched to local in-memory fallback mode.', 'info');
      openSupabaseModal();
    }
  });

  document.getElementById('copySupabaseSqlBtn')?.addEventListener('click', () => {
    const sqlText = `-- =========================================================================
-- Project 26-78: Blockchain Enabled Secure IoT Communication Framework
-- Supabase PostgreSQL Database Schema & Seed Data
-- =========================================================================

-- 1. IOT NODES REGISTRY TABLE
CREATE TABLE IF NOT EXISTS public.iot_nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    mac TEXT NOT NULL,
    protocol TEXT DEFAULT 'MQTT',
    trust_score INTEGER DEFAULT 95 CHECK (trust_score >= 0 AND trust_score <= 100),
    status TEXT DEFAULT 'Verified' CHECK (status IN ('Verified', 'Quarantined', 'Pending')),
    last_seen TEXT DEFAULT 'Just now',
    anomaly_score NUMERIC(5, 4) DEFAULT 0.0500,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. BLOCKCHAIN LEDGER TABLE
CREATE TABLE IF NOT EXISTS public.blockchain_ledger (
    block_index INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL,
    validator TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    nonce INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. TELEMETRY & SECURITY EVENT LOGS TABLE
CREATE TABLE IF NOT EXISTS public.telemetry_logs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    timestamp TEXT NOT NULL,
    level TEXT DEFAULT 'INFO' CHECK (level IN ('INFO', 'WARNING', 'CRITICAL', 'BLOCK')),
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =========================================================================
-- INDEXES FOR PERFORMANCE
-- =========================================================================
CREATE INDEX IF NOT EXISTS idx_iot_nodes_status ON public.iot_nodes(status);
CREATE INDEX IF NOT EXISTS idx_blockchain_ledger_hash ON public.blockchain_ledger(hash);
CREATE INDEX IF NOT EXISTS idx_telemetry_logs_level ON public.telemetry_logs(level);
CREATE INDEX IF NOT EXISTS idx_telemetry_logs_created_at ON public.telemetry_logs(created_at DESC);

-- =========================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Enables open read/write access for web browser client prototype
-- =========================================================================
ALTER TABLE public.iot_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blockchain_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_logs ENABLE ROW LEVEL SECURITY;

-- Allow unrestricted anonymous read/write/update for the IoT dashboard prototype
DROP POLICY IF EXISTS "Public access for iot_nodes" ON public.iot_nodes;
CREATE POLICY "Public access for iot_nodes" ON public.iot_nodes
    FOR ALL USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Public access for blockchain_ledger" ON public.blockchain_ledger;
CREATE POLICY "Public access for blockchain_ledger" ON public.blockchain_ledger
    FOR ALL USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Public access for telemetry_logs" ON public.telemetry_logs;
CREATE POLICY "Public access for telemetry_logs" ON public.telemetry_logs
    FOR ALL USING (true) WITH CHECK (true);

-- =========================================================================
-- REALTIME SUBSCRIPTIONS
-- Enables WebSocket push notifications on device registration & quarantine
-- =========================================================================
BEGIN;
  -- Add tables to realtime publication if not already added
  DROP PUBLICATION IF EXISTS supabase_realtime;
  CREATE PUBLICATION supabase_realtime FOR TABLE public.iot_nodes, public.blockchain_ledger, public.telemetry_logs;
COMMIT;

-- =========================================================================
-- OPTIONAL: RUN THIS IN SUPABASE SQL EDITOR TO CLEAR OLD DEMO DATA:
-- TRUNCATE TABLE public.iot_nodes CASCADE;
-- DELETE FROM public.blockchain_ledger WHERE block_index > 0;
-- TRUNCATE TABLE public.telemetry_logs CASCADE;
-- =========================================================================

-- =========================================================================
-- DEFAULT SEED DATA (GENESIS ROOT BLOCK ONLY - NO SYNTHETIC DEMO NODES)
-- =========================================================================

-- Insert Baseline Blockchain Genesis Block Root (Block 0)
INSERT INTO public.blockchain_ledger (block_index, timestamp, device_id, action, validator, payload, previous_hash, hash, nonce)
VALUES
    (0, '2026-10-23 08:00:00 UTC', 'GENESIS-ROOT', 'GENESIS', 'Val-00 [Ledger Origin]', '{"message": "Project 26-78 PoA Genesis Block - Trust Root Established", "difficulty": 1}'::jsonb, '0000000000000000000000000000000000000000000000000000000000000000', '0000a1f8b492e811c7d05634e89a19c5b4e72390a184f7289b418e90c12fa839', 42)
ON CONFLICT (block_index) DO NOTHING;
`;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(sqlText).then(() => {
        showToast('SQL Copied to Clipboard!', 'Paste into Supabase SQL Editor and click Run.', 'success');
      }).catch(() => {
        showToast('Schema Ready', 'See supabase_schema.sql file in project directory.', 'info');
      });
    } else {
      showToast('Schema Ready', 'See supabase_schema.sql file in project directory.', 'info');
    }
  });

});

// Expose functions globally for inline HTML handlers and dev console
window.processUploadedDataset = processUploadedDataset;
window.handleDatasetFileUpload = handleDatasetFileUpload;
window.resetToDemoDataset = resetToDemoDataset;
window.openUploadModal = openUploadModal;
window.closeUploadModal = closeUploadModal;
window.revealCharts = revealCharts;
window.executeThreatTestAndRevealCharts = executeThreatTestAndRevealCharts;
window.goBack = goBack;
window.switchTab = switchTab;
window.safeCreateIcons = safeCreateIcons;
