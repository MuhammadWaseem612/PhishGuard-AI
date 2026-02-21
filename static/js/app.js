// ═══════════════════════════════════════════════
// PhishGuard AI — app.js
// ═══════════════════════════════════════════════

let scanHistory = [];
let modelsLoaded = false;

// ── On page load ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  setupTabs();
});

// ── Tab switching ─────────────────────────────
function setupTabs() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const sec = item.dataset.section;
      if (!sec) return;
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
      item.classList.add('active');
      document.getElementById('sec-' + sec).classList.add('active');
      if (sec === 'models' && !modelsLoaded) loadModels();
    });
  });
}

// ── Load stats from API ───────────────────────
async function loadStats() {
  try {
    const resp = await fetch('/api/stats');
    const data = await resp.json();

    const acc = data.best_accuracy || 0;
    document.getElementById('chipAccuracy').textContent = `📊 ${acc}% Accuracy`;
    document.getElementById('sidebarStatus').textContent =
      data.system_status === 'operational' ? 'System Active' : 'Training Required';
    document.getElementById('sidebarModel').textContent =
      data.best_model !== 'N/A' ? `Best: ${data.best_model}` : 'Run train_model.py';
  } catch (e) {
    document.getElementById('sidebarModel').textContent = 'Models not loaded';
  }
}

// ── Load sample emails ────────────────────────
const SAMPLES = {
  phishing: [
    "URGENT: Your bank account has been compromised! Someone tried to access your account from an unknown device. Click here IMMEDIATELY to verify your identity and avoid permanent suspension: http://secure-login-verify.xyz/account\n\nFAILURE TO ACT WITHIN 24 HOURS WILL RESULT IN ACCOUNT TERMINATION.",
    "Congratulations!!! You have been selected as our lucky WINNER of $1,000,000 in our international lottery draw! 🎉🎉\n\nTo claim your prize IMMEDIATELY, send your full name, bank account details, and social security number to: winner@prize-claim-now.tk\n\nThis offer EXPIRES in 24 hours!!! Act NOW!!!",
  ],
  safe: [
    "Hi Sarah,\n\nJust following up on our meeting from yesterday. I've attached the updated project proposal with the changes we discussed. Could you please review it and share your feedback by Thursday?\n\nAlso, the team lunch is confirmed for Friday at 12:30pm at the usual place.\n\nBest regards,\nMike",
  ]
};

function loadSample(type, idx) {
  const list = SAMPLES[type === 'phishing' ? 'phishing' : 'safe'];
  document.getElementById('emailInput').value = list[idx % list.length];
  document.getElementById('emailInput').style.borderColor = type === 'phishing' ? 'var(--red)' : 'var(--green)';
  setTimeout(() => { document.getElementById('emailInput').style.borderColor = ''; }, 1000);
}

// ── Main scan function ────────────────────────
async function scanEmail() {
  const emailText = document.getElementById('emailInput').value.trim();
  const selectedModel = document.getElementById('modelSelect').value;

  if (!emailText) {
    showInputError();
    return;
  }

  // UI loading state
  const btn = document.getElementById('btnScan');
  btn.disabled = true;
  btn.textContent = '⏳ Scanning...';
  document.getElementById('scanLoading').classList.add('show');

  try {
    const resp = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: emailText, model: selectedModel })
    });

    const data = await resp.json();

    if (data.success) {
      showResult(data, emailText);
      addToHistory(data, emailText);
    } else {
      showError(data.error || 'Prediction failed');
    }

  } catch (err) {
    showError('Connection failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '🔍 Scan for Threats';
    document.getElementById('scanLoading').classList.remove('show');
  }
}

// ── Show result ───────────────────────────────
function showResult(data, emailText) {
  document.getElementById('resultPlaceholder').style.display = 'none';
  const rc = document.getElementById('resultContent');
  rc.style.display = 'block';
  rc.style.animation = 'fadeUp 0.35s ease';

  const isPhishing = data.is_phishing;
  const confidence = data.confidence;

  // Verdict box
  const vBox  = document.getElementById('verdictBox');
  const vIcon = document.getElementById('verdictIcon');
  const vLbl  = document.getElementById('verdictLabel');
  const vTitle= document.getElementById('verdictTitle');
  const vModel= document.getElementById('verdictModel');

  vBox.className = 'verdict-box ' + (isPhishing ? 'phishing' : 'safe');
  vIcon.textContent  = isPhishing ? '🚨' : '✅';
  vLbl.textContent   = isPhishing ? '⚠️ PHISHING DETECTED' : '✅ SAFE EMAIL';
  vTitle.textContent = isPhishing ? 'This Email is Dangerous' : 'This Email Looks Legitimate';
  vModel.textContent = `Analyzed by: ${data.model_used}`;

  // Confidence bar
  const fill   = document.getElementById('confFill');
  const valEl  = document.getElementById('confValue');
  valEl.textContent = confidence + '%';

  const color = isPhishing
    ? 'linear-gradient(90deg,#dc2626,#ef4444)'
    : 'linear-gradient(90deg,#16a34a,#22c55e)';
  fill.style.background = color;
  valEl.style.color = isPhishing ? 'var(--red)' : 'var(--green)';
  fill.style.width = '0%';
  setTimeout(() => { fill.style.width = confidence + '%'; }, 80);

  // Risk indicators grid
  const analysis = data.analysis || {};
  const riskGrid = document.getElementById('riskGrid');
  riskGrid.innerHTML = '';

  const risks = [
    { label: 'Urgent Words',   val: analysis.has_urgent_words || (analysis.phishing_indicators?.urgent?.length > 0), display: 'Detected' },
    { label: 'Suspicious URLs', val: (analysis.suspicious_urls?.length > 0), display: `${(analysis.suspicious_urls||[]).length} found` },
    { label: 'Money / Prize',  val: analysis.has_prize_money || (analysis.phishing_indicators?.money?.length > 0), display: 'Detected' },
    { label: 'Exclamations',   val: (analysis.exclamation_count || 0) > 2, display: `${analysis.exclamation_count || 0} found` },
    { label: 'CAPS Ratio',     val: (analysis.caps_ratio || 0) > 15, display: `${analysis.caps_ratio || 0}%` },
    { label: 'Links Found',    val: (analysis.link_count || analysis.url_count || 0) > 0, display: `${analysis.link_count || analysis.url_count || 0} link(s)` },
  ];

  risks.forEach(r => {
    const cls = r.val ? 'flagged' : 'clear';
    riskGrid.innerHTML += `
      <div class="risk-item ${cls}">
        <div class="risk-dot"></div>
        <div>
          <div class="risk-item-name">${r.label}</div>
          <div class="risk-item-val">${r.display}</div>
        </div>
      </div>`;
  });

  // Indicators list
  const indList = document.getElementById('indicatorsList');
  const indicators = analysis.phishing_indicators || {};
  const allTags = [];

  Object.entries(indicators).forEach(([cat, words]) => {
    if (words && words.length > 0) {
      words.forEach(w => allTags.push(`${cat}: "${w}"`));
    }
  });

  if (allTags.length > 0) {
    indList.innerHTML = allTags.map(t =>
      `<span class="indicator-tag">⚠️ ${t}</span>`
    ).join('');
  } else {
    indList.innerHTML = `<div class="no-indicators">✅ No phishing keyword indicators detected</div>`;
  }
}

// ── Add to history ────────────────────────────
function addToHistory(data, emailText) {
  const emptyRow = document.getElementById('emptyRow');
  if (emptyRow) emptyRow.remove();

  const now  = new Date();
  const time = now.getHours().toString().padStart(2,'0') + ':' + now.getMinutes().toString().padStart(2,'0');
  const preview = emailText.substring(0, 50).replace(/\n/g, ' ') + (emailText.length > 50 ? '...' : '');
  const indCount = Object.keys(data.analysis?.phishing_indicators || {}).length;

  const body = document.getElementById('historyBody');
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="font-family:var(--font-mono);color:var(--text-muted);font-size:12px">${time}</td>
    <td>${data.is_phishing
      ? '<span class="verdict-tag-phish">🚨 PHISHING</span>'
      : '<span class="verdict-tag-safe">✅ SAFE</span>'}</td>
    <td><span class="conf-tag-small">${data.confidence}%</span></td>
    <td style="font-size:12px;color:var(--text-muted)">${data.model_used}</td>
    <td style="font-size:12px">${indCount > 0 ? `<span style="color:var(--red);font-weight:700">${indCount} found</span>` : '<span style="color:var(--green);font-weight:700">None</span>'}</td>
    <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis">${preview}</td>`;

  body.insertBefore(tr, body.firstChild);

  scanHistory.push(data);
  document.getElementById('historyCount').textContent = scanHistory.length;
}

// ── Clear history ─────────────────────────────
function clearHistory() {
  scanHistory = [];
  document.getElementById('historyCount').textContent = '0';
  document.getElementById('historyBody').innerHTML =
    `<tr class="empty-row" id="emptyRow"><td colspan="6">No scans yet. Paste an email and run a scan! 🛡️</td></tr>`;
}

// ── Load models ───────────────────────────────
async function loadModels() {
  modelsLoaded = true;
  try {
    const resp = await fetch('/api/models');
    const data = await resp.json();
    const grid = document.getElementById('modelsGrid');

    if (!data.models || Object.keys(data.models).length === 0) {
      grid.innerHTML = `<div class="no-models-msg">⚠️ No trained models found. Run <code style="color:var(--red)">python train_model.py</code> first.</div>`;
      return;
    }

    grid.innerHTML = '';
    const COLORS = ['#ef4444','#fb923c','#eab308','#22c55e','#06b6d4'];
    Object.entries(data.models).forEach(([name, info], i) => {
      const isBest = name === data.best_model;
      grid.innerHTML += `
        <div class="model-card ${isBest ? 'best-model' : ''}">
          <div class="model-card-name">
            <span style="color:${COLORS[i % COLORS.length]}">●</span>
            ${name}
            ${isBest ? '<span class="best-badge">Best</span>' : ''}
          </div>
          <div class="model-stat">
            <span class="model-stat-key">Accuracy</span>
            <span class="model-stat-val" style="color:${COLORS[i % COLORS.length]}">${info.accuracy}%</span>
          </div>
          <div class="model-stat">
            <span class="model-stat-key">CV Score</span>
            <span class="model-stat-val">${info.cv_score}%</span>
          </div>
          <div class="model-stat">
            <span class="model-stat-key">Status</span>
            <span class="model-stat-val" style="color:${info.status==='loaded'?'var(--green)':'var(--red)'}">${info.status === 'loaded' ? '✅ Loaded' : '❌ Not loaded'}</span>
          </div>
        </div>`;
    });
  } catch (e) {
    document.getElementById('modelsGrid').innerHTML =
      `<div class="no-models-msg">❌ Error loading model data: ${e.message}</div>`;
  }
}

// ── Error helpers ─────────────────────────────
function showInputError() {
  const ta = document.getElementById('emailInput');
  ta.style.borderColor = 'var(--red)';
  ta.placeholder = '⚠️ Please paste an email first!';
  setTimeout(() => {
    ta.style.borderColor = '';
    ta.placeholder = 'Paste email content here to scan for phishing threats...';
  }, 2000);
}

function showError(msg) {
  alert('Error: ' + msg);
}

// ── Enter key shortcut ────────────────────────
document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') scanEmail();
});
