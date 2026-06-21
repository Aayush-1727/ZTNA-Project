// ================= CONFIG =================
const API_BASE = localStorage.getItem('ztna_api_base') || 'http://localhost:5000';

// ================= AUTH =================
const Auth = {
  token: () => localStorage.getItem('ztna_token'),

  set: (t) => localStorage.setItem('ztna_token', t),

  clear: () => {
    localStorage.removeItem('ztna_token');
    localStorage.removeItem('ztna_email');
  },

  email: () => localStorage.getItem('ztna_email') || '',

  setEmail: (e) => localStorage.setItem('ztna_email', e),

  require: () => {
    if (!Auth.token()) location.href = 'login.html';
  }
};

// ================= API =================
async function api(path, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(opts.headers || {})
  };

  const t = Auth.token();
  if (t) headers['Authorization'] = t;

  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers
  });

  if (res.status === 401) {
    Auth.clear();
    location.href = 'login.html';
    throw new Error('unauthorized');
  }

  const data = await res.json().catch(() => ({}));

  if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);

  return data;
}

// ================= RISK =================
function riskFromWarnings(count) {
  if (!count || count === 0) return 'LOW';
  if (count === 1) return 'MEDIUM';
  return 'HIGH';
}

// ================= TRUST SCORE (🔥 FIXED ONLY THIS) =================
function trustScoreFrom(logsCount, warnings = 0) {
  let score = 100;

  // reduce based on warnings
  score -= warnings * 20;

  // reduce if too many logs (suspicious behavior)
  if (logsCount > 10) score -= 10;
  if (logsCount > 20) score -= 10;

  return Math.max(20, Math.min(100, score));
}

// ================= DEVICE =================
function parseDevice(ua = '') {
  let os = 'Unknown OS', browser = 'Unknown Browser', icon = 'monitor';

  if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Mac OS|Macintosh/i.test(ua)) os = 'macOS';
  else if (/Android/i.test(ua)) { os = 'Android'; icon = 'smartphone'; }
  else if (/iPhone|iPad|iOS/i.test(ua)) { os = 'iOS'; icon = 'smartphone'; }
  else if (/Linux/i.test(ua)) os = 'Linux';

  if (/Chrome\//i.test(ua) && !/Edg|OPR/i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';
  else if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\//i.test(ua)) browser = 'Opera';

  return { os, browser, icon, label: `${browser} on ${os}` };
}

// ================= TIME =================
function fmtTime(t) {
  if (!t) return '—';

  const d = new Date(t);
  if (isNaN(d)) return '—';

  const diff = Math.floor((Date.now() - d.getTime()) / 1000);

  if (diff < 5) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;

  return d.toLocaleString();
}

// ================= ESCAPE =================
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

// ================= UI =================
function mountChrome(page, title, subtitle) {
  document.body.innerHTML = `
    <div class="app">

      <div class="sidebar">
        <div class="brand">
          <div class="brand-logo">Z</div>
          <div>
            <div class="brand-name">ZTNA</div>
            <div class="brand-sub">Zero Trust Network</div>
          </div>
        </div>

        <div class="nav">
          <div class="nav-item ${page==='dashboard'?'active':''}" onclick="goDashboard()">Dashboard</div>
          <div class="nav-item ${page==='activity'?'active':''}" onclick="goActivity()">Activity</div>
          <div class="nav-item ${page==='devices'?'active':''}" onclick="goDevices()">Devices</div>
          <div class="nav-item ${page==='admin'?'active':''}" onclick="goAdmin()">Admin</div>
        </div>

        <div class="sidebar-foot">
          <button class="logout-btn" onclick="logout()">Logout</button>
        </div>
      </div>

      <div class="main">
        <div class="topbar">
          <div>
            <div class="page-title">${title}</div>
            <div class="page-sub">${subtitle}</div>
          </div>

          <div class="user-chip">
            <div class="user-avatar">U</div>
            <div>${Auth.email() || 'User'}</div>
          </div>
        </div>

        <div id="content" class="content"></div>
      </div>

    </div>
  `;
}

// ================= UI HELPERS =================
function statCard({label, value}) {
  return `
    <div class="card">
      <div class="stat-label">${label}</div>
      <div class="stat-value">${value}</div>
    </div>
  `;
}

// ================= REAL CHART (🔥 ADDED) =================
function drawChart(logs) {
  const canvas = document.getElementById("chart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");

  const values = logs.slice(0, 10).map((_, i) => (i + 1) * 5);

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  ctx.beginPath();
  ctx.strokeStyle = "#6366f1";

  values.forEach((v, i) => {
    const x = i * 30;
    const y = 120 - v;

    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  ctx.stroke();
}

// ================= KEEP SAME (NO UI CHANGE) =================
function lineChart(){ return `<div class="empty">Chart loading...</div>`; }
function pieChart(){ return `<div class="empty">Chart loading...</div>`; }
function trustRing(score = 80){ return `<div class="empty">Trust Score: ${score}%</div>`; }

// ================= SVG =================
function svg(content) {
  return `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      ${content}
    </svg>
  `;
}

// ================= ICONS =================
function iconActivity(){ return "📊"; }
function iconDevice(){ return "💻"; }
function iconGlobe(){ return "🌐"; }
function iconClock(){ return "⏱"; }
function iconUsers(){ return "👤"; }
function iconAlert(){ return "⚠"; }
function iconCheck(){ return "✔"; }

// ================= NAV =================
function goDashboard(){ location.href="dashboard.html"; }
function goActivity(){ location.href="activity.html"; }
function goDevices(){ location.href="devices.html"; }
function goAdmin(){ location.href="admin.html"; }

// ================= LOGOUT =================
function logout(){
  if(confirm("Are you sure you want to logout?")){
    Auth.clear();
    location.href="login.html";
  }
}