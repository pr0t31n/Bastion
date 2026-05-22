/* Bastion static/js/main.js — Complete UI logic */
"use strict";

// ---------------------------------------------------------------------------
// Theme system (Arbiter-style palette picker)
// ---------------------------------------------------------------------------
const PALETTES_META = [
  // Professional
  { id: 'tuxedo',      label: 'Tuxedo',       d: ['#0a0a0a','#e0e0e0'],   l: ['#ffffff','#111111'] },
  { id: 'meridian',    label: 'Meridian',     d: ['#0e1628','#4a88cc'],   l: ['#f6f9ff','#1a4a8c'] },
  { id: 'alabaster',   label: 'Alabaster',    d: ['#121416','#9caab8'],   l: ['#faf8f5','#2c3038'] },
  { id: 'leadership',  label: 'Leadership',   d: ['#0b1428','#f5c842'],   l: ['#fdf8f0','#c8940a'] },
  { id: 'blueprint',   label: 'Blueprint',    d: ['#061830','#5090e0'],   l: ['#f0f5ff','#1a4898'] },
  { id: 'resume',      label: 'Resume',       d: ['#141008','#c8a860'],   l: ['#faf6ee','#1c2840'] },
  // Casual
  { id: 'foundry',     label: 'Foundry',      d: ['#0d0d0d','#f0a500'],   l: ['#f5f0e8','#c88000'] },
  { id: 'forge',       label: 'Forge',        d: ['#0a0804','#c8921f'],   l: ['#ede0c4','#8b5e10'] },
  { id: 'frigid',      label: 'Frigid',       d: ['#060e18','#5ab0d8'],   l: ['#e4f4ff','#1a70a0'] },
  { id: 'bloom',       label: 'Bloom',        d: ['#120e18','#c490c8'],   l: ['#f8f0f8','#9060a8'] },
  { id: 'prism',       label: 'Prism',        d: ['#0c0f2e','#c084fc'],   l: ['#ede9fe','#7c3aed'] },
  { id: 'ember',       label: 'Ember',        d: ['#140206','#e83020'],   l: ['#fff4ee','#b82010'] },
  { id: 'oldglory',    label: 'Old Glory',    d: ['#010410','#f03050'],   l: ['#e0e4f0','#021a5c'] },
  { id: 'alchemist',   label: 'Alchemist',    d: ['#020606','#50c8a0'],   l: ['#daf0ec','#0a2820'] },
  // Nerdy
  { id: 'coruscant',   label: 'Coruscant',    d: ['#050007','#ff2040'],   l: ['#f5f8fe','#1a4a8c'] },
  { id: 'retro',       label: 'Retro',        d: ['#020a02','#33ff33'],   l: ['#0d0700','#ffaa00'] },
  { id: 'jarvis',      label: 'JARVIS',       d: ['#020c1b','#00d0ff'],   l: ['#d0e8f8','#0068c8'] },
  { id: 'hal9000',     label: 'HAL-9000',     d: ['#040202','#aa1800'],   l: ['#f8f5f2','#aa1800'] },
  { id: 'neuromancer', label: 'Neuromancer',  d: ['#06030c','#d010b8'],   l: ['#faf0ff','#b010a0'] },
  { id: 'deepspace',   label: 'Deep Space',   d: ['#030610','#9070f0'],   l: ['#f0f4ff','#5040c0'] },
  { id: 'bladerunner', label: 'Blade Runner', d: ['#0a0810','#ff8c00'],   l: ['#f4f0e8','#c06800'] },
  { id: 'synthwave',   label: 'Synthwave',    d: ['#0d0018','#ff0880'],   l: ['#fce8ff','#c00060'] },
  // Natural
  { id: 'espresso',    label: 'Espresso',     d: ['#130c06','#c07030'],   l: ['#fef8ee','#8b4a10'] },
  { id: 'terracotta',  label: 'Terracotta',   d: ['#180806','#d45828'],   l: ['#faf2e8','#b04020'] },
  { id: 'sage',        label: 'Sage',         d: ['#060c06','#78b860'],   l: ['#f4f9f0','#2a6830'] },
  { id: 'blush',       label: 'Blush',        d: ['#160608','#d06878'],   l: ['#fdf4f5','#8a2848'] },
];

const PALETTE_CATEGORIES = [
  { id: 'professional', label: 'Professional', palettes: ['tuxedo','meridian','alabaster','leadership','blueprint','resume'] },
  { id: 'casual',       label: 'Casual',       palettes: ['foundry','forge','frigid','bloom','prism','ember','oldglory','alchemist'] },
  { id: 'nerdy',        label: 'Nerdy',        palettes: ['coruscant','retro','jarvis','hal9000','neuromancer','deepspace','bladerunner','synthwave'] },
  { id: 'natural',      label: 'Natural',      palettes: ['espresso','terracotta','sage','blush'] },
];

function _swatchHtml(colors) {
  return colors.map(c =>
    `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;` +
    `background:${c};border:1px solid rgba(128,128,128,.3);flex-shrink:0"></span>`
  ).join('');
}

function _applyTheme(palette, mode) {
  const html = document.documentElement;
  html.setAttribute('data-palette', palette);
  html.setAttribute('data-mode',    mode);

  const modeLabel = document.getElementById('modeLabel');
  if (modeLabel) modeLabel.textContent = mode === 'dark' ? 'Dark' : 'Light';

  const toggle = document.getElementById('themeToggle');
  if (toggle) toggle.checked = (mode === 'dark');

  const sel = document.getElementById('paletteSelect');
  if (sel) sel.value = palette;

  _updatePickerUI(palette, mode);

  try { localStorage.setItem('bastion-palette', palette); } catch(e) {}
  try { localStorage.setItem('bastion-mode',    mode);    } catch(e) {}
}

function _updatePickerUI(palette, mode) {
  const label    = document.getElementById('palettePickerLabel');
  const swatches = document.getElementById('palettePickerSwatches');
  if (!label || !swatches) return;
  const meta = PALETTES_META.find(p => p.id === palette) || PALETTES_META[0];
  const cols = mode === 'dark' ? meta.d : meta.l;
  label.textContent  = meta.label;
  swatches.innerHTML = _swatchHtml(cols);
}

function _buildDropdown() {
  const ul = document.getElementById('palettePickerDropdown');
  if (!ul || ul.children.length) return;
  const mode = document.documentElement.getAttribute('data-mode') || 'light';

  ul.innerHTML = PALETTE_CATEGORIES.map(cat => {
    const itemsHtml = cat.palettes.map(pid => {
      const meta = PALETTES_META.find(p => p.id === pid);
      if (!meta) return '';
      const cols = mode === 'dark' ? meta.d : meta.l;
      return `<li role="option" data-palette="${meta.id}"
                  style="display:flex;align-items:center;gap:.45rem;padding:.32rem .6rem;
                         cursor:pointer;white-space:nowrap;font-size:.75rem">
                ${_swatchHtml(cols)}
                <span>${meta.label}</span>
              </li>`;
    }).join('');
    return `<li class="palette-cat-item" data-cat="${cat.id}">
      <div class="palette-cat-header" role="presentation">
        <span>${cat.label}</span>
        <span class="cat-arrow">&#9658;</span>
      </div>
      <ul class="palette-cat-sub" role="group" aria-label="${cat.label} themes">
        ${itemsHtml}
      </ul>
    </li>`;
  }).join('');

  ul.querySelectorAll('li[data-palette]').forEach(li => {
    li.addEventListener('click', e => {
      e.stopPropagation();
      _applyTheme(li.dataset.palette, document.documentElement.getAttribute('data-mode') || 'light');
      _closePicker();
    });
  });

  ul.querySelectorAll('.palette-cat-header').forEach(header => {
    header.addEventListener('click', e => {
      e.stopPropagation();
      const item   = header.closest('.palette-cat-item');
      const isOpen = item.classList.contains('open');
      ul.querySelectorAll('.palette-cat-item.open').forEach(i => i.classList.remove('open'));
      if (!isOpen) item.classList.add('open');
    });
  });
}

function _refreshDropdownSwatches(mode) {
  const ul = document.getElementById('palettePickerDropdown');
  if (!ul) return;
  ul.querySelectorAll('li[data-palette]').forEach(li => {
    const meta = PALETTES_META.find(p => p.id === li.dataset.palette);
    if (!meta) return;
    const cols = mode === 'dark' ? meta.d : meta.l;
    const spans = li.querySelectorAll('span[style*="border-radius:50%"]');
    spans.forEach((s, i) => { if (cols[i]) s.style.background = cols[i]; });
  });
}

function _openPicker() {
  const picker = document.getElementById('palettePicker');
  const dd     = document.getElementById('palettePickerDropdown');
  if (!picker || !dd) return;
  _buildDropdown();
  _refreshDropdownSwatches(document.documentElement.getAttribute('data-mode') || 'light');
  dd.classList.remove('drop-up');
  picker.setAttribute('aria-expanded', 'true');
  dd.style.display = 'block';
  const rect = dd.getBoundingClientRect();
  if (rect.bottom > (window.innerHeight || document.documentElement.clientHeight)) {
    dd.classList.add('drop-up');
  }
}

function _closePicker() {
  const picker = document.getElementById('palettePicker');
  const dd     = document.getElementById('palettePickerDropdown');
  if (picker) picker.setAttribute('aria-expanded', 'false');
  if (dd) {
    dd.style.display = 'none';
    dd.classList.remove('drop-up');
    dd.querySelectorAll('.palette-cat-item.open').forEach(i => i.classList.remove('open'));
  }
}

function _togglePicker() {
  const dd = document.getElementById('palettePickerDropdown');
  if (!dd) return;
  dd.style.display === 'block' ? _closePicker() : _openPicker();
}

function initPalettePicker() {
  const palette = document.documentElement.getAttribute('data-palette') || 'resume';
  const mode    = document.documentElement.getAttribute('data-mode')    || 'light';
  _updatePickerUI(palette, mode);

  document.addEventListener('click', function(e) {
    if (e.target.closest('#themeToggle')) return;
    if (e.target.closest('#palettePickerDropdown')) return;
    if (e.target.closest('#palettePicker')) { _togglePicker(); return; }
    _closePicker();
  });

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') _closePicker();
    const picker = document.getElementById('palettePicker');
    if (document.activeElement === picker && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault(); _togglePicker();
    }
  });
}

function initModeToggle() {
  const toggle = document.getElementById('themeToggle');
  if (!toggle) return;
  const mode = document.documentElement.getAttribute('data-mode') || 'light';
  toggle.checked = (mode === 'dark');
  toggle.addEventListener('change', function() {
    const palette = document.documentElement.getAttribute('data-palette') || 'resume';
    const newMode = this.checked ? 'dark' : 'light';
    _applyTheme(palette, newMode);
    _refreshDropdownSwatches(newMode);
  });
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
window._esc = function(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
};

window._fmtSize = function(b) {
  b = Number(b) || 0;
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  return (b / 1048576).toFixed(1) + " MB";
};

const RISK_COLORS = {
  Critical: "#FF00FF", High: "#E7716F", Medium: "#FFC000",
  Low: "#92D050", Informational: "#BDD7EC", Unknown: "#a0aec0"
};

window._riskBadge = function(risk) {
  const c = RISK_COLORS[risk] || "#a0aec0";
  const textColor = ["Medium","Low","Informational"].includes(risk) ? "#1a1a1a" : "#fff";
  return `<span class="risk-badge" style="background:${c};color:${textColor}">${_esc(risk)}</span>`;
};

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
const _tabLoaded = {};

window.switchTab = function(name, btnEl) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  if (btnEl) {
    btnEl.classList.add("active");
  } else {
    const btn = document.querySelector(`[data-tab="${name}"]`);
    if (btn) btn.classList.add("active");
  }
  const panel = document.getElementById(`tab-${name}`);
  if (panel) panel.classList.add("active");
  if (!_tabLoaded[name]) {
    _tabLoaded[name] = true;
    loadTabData(name);
  }
};

function loadTabData(name) {
  if (name === "findings")     loadFindings();
  if (name === "source")       loadConfigFiles();
  if (name === "architecture") loadArchitecture();
  if (name === "logs")         loadAllLogs();
  if (name === "errors")       loadErrors();
  if (name === "summary")      loadSummary();
}

// ---------------------------------------------------------------------------
// SocketIO (only on project pages)
// ---------------------------------------------------------------------------
let socket;

function initSocket() {
  if (typeof io === "undefined" || typeof PROJECT_ID === "undefined") return;
  try {
    socket = io({ transports: ["websocket"] });
    socket.on("connect", () => {
      socket.emit("join_project", { project_id: PROJECT_ID });
    });
    socket.on("parse_complete", d => {
      updateFileCard(d.filename, "parsed", d);
      appendParseLog(`Parsed ${d.filename}: ${d.rules_count} rules, ${d.errors} errors`);
    });
    socket.on("parse_error", d => {
      updateFileCard(d.filename, "error", d);
      appendParseLog(`ERROR ${d.filename}: ${d.error}`, "error");
    });
    socket.on("analysis_progress", d => updateProgressBar(d.percent, d.step));
    socket.on("analysis_complete", d => {
      updateProgressBar(100, "Analysis complete");
      setTimeout(() => {
        loadFindings();
        loadSummary();
        const progWrap = document.getElementById("progressWrap");
        if (progWrap) progWrap.setAttribute("hidden", "");
        const analyzeBtn = document.getElementById("analyzeBtn");
        if (analyzeBtn) analyzeBtn.disabled = false;
      }, 500);
      if (d.diff_summary) renderDiffBanner(d.diff_summary);
    });
    socket.on("analysis_error", d => {
      appendError("ANALYSIS", "analysis", d.error);
      const analyzeBtn = document.getElementById("analyzeBtn");
      if (analyzeBtn) analyzeBtn.disabled = false;
    });
    socket.on("diagram_complete", () => {
      if (_tabLoaded["architecture"]) loadArchitecture();
    });
    socket.on("finding_accepted", d => {
      const row = document.getElementById(`finding-row-${d.finding_id}`);
      if (row) {
        if (d.accepted) row.classList.add("accepted");
        else row.classList.remove("accepted");
      }
    });
    socket.on("error_entry", d => appendError(d.type, d.source, d.message));
  } catch(e) {
    console.warn("SocketIO init error:", e);
  }
}

// ---------------------------------------------------------------------------
// Config files
// ---------------------------------------------------------------------------
function loadConfigFiles() {
  if (typeof PROJECT_ID === "undefined") return;
  fetch(`/api/config_files/${PROJECT_ID}`)
    .then(r => r.json())
    .then(d => renderConfigFileList(d.config_files || []))
    .catch(e => console.error("loadConfigFiles:", e));
}

function renderConfigFileList(files) {
  const list = document.getElementById("configFileList");
  if (!list) return;
  if (!files.length) {
    list.innerHTML = `<p class="text-muted mt-1">No config files uploaded yet.</p>`;
    return;
  }
  list.innerHTML = files.map(f => `
    <div class="config-file-card" id="card-${_esc(f.filename)}">
      <div class="filename">${_esc(f.filename)}</div>
      <span class="vendor-badge">${_esc(f.vendor || "unknown")}</span>
      <span class="file-meta">${_fmtSize(f.size)}</span>
      <button class="btn btn-sm btn-ghost"
              onclick="openConfigViewer('${_esc(f.filename)}')">View</button>
      <button class="btn btn-sm btn-ghost"
              onclick="deleteConfig('${_esc(f.filename)}')"
              style="color:var(--danger)">✕</button>
    </div>
  `).join("");
}

function updateFileCard(filename, status, data) {
  const card = document.getElementById(`card-${filename}`);
  if (!card) return;
  card.classList.add(status);
  if (data && data.vendor) {
    const badge = card.querySelector(".vendor-badge");
    if (badge) badge.textContent = data.vendor;
  }
}

window.deleteConfig = function(filename) {
  if (!confirm(`Delete ${filename}?`)) return;
  fetch(`/api/delete_config/${PROJECT_ID}/${encodeURIComponent(filename)}`,
        { method: "DELETE" })
    .then(r => r.json())
    .then(d => { if (d.ok) loadConfigFiles(); })
    .catch(e => console.error(e));
};

// Upload zone
function initUploadZone() {
  const zone = document.getElementById("uploadZone");
  if (!zone) return;

  zone.addEventListener("click", () => {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.multiple = true;
    inp.accept = ".cfg,.conf,.txt,.log,.xml,.json,.exp,.backup,.cli,.yaml,.yml";
    inp.onchange = e => { Array.from(e.target.files).forEach(uploadFile); };
    inp.click();
  });

  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    Array.from(e.dataTransfer.files).forEach(uploadFile);
  });
}

function uploadFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  fetch(`/api/upload_config/${PROJECT_ID}`, { method: "POST", body: fd })
    .then(r => r.json())
    .then(d => {
      if (d.ok) {
        loadConfigFiles();
      } else {
        alert("Upload failed: " + (d.error || "unknown error"));
      }
    })
    .catch(e => console.error("upload:", e));
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
window.triggerAnalysis = function() {
  const btn = document.getElementById("analyzeBtn");
  if (btn) btn.disabled = true;
  const progWrap = document.getElementById("progressWrap");
  if (progWrap) progWrap.removeAttribute("hidden");
  updateProgressBar(5, "Starting analysis...");

  fetch(`/api/analyze/${PROJECT_ID}`, { method: "POST" })
    .then(r => r.json())
    .then(d => {
      if (d.error) {
        alert("Error: " + d.error);
        if (btn) btn.disabled = false;
        if (progWrap) progWrap.setAttribute("hidden", "");
      }
    })
    .catch(e => {
      console.error(e);
      if (btn) btn.disabled = false;
    });
};

function updateProgressBar(pct, label) {
  const bar = document.getElementById("progressBar");
  const lbl = document.getElementById("progressLabel");
  if (bar) bar.style.width = pct + "%";
  if (lbl) lbl.textContent = label || "";
}

function appendParseLog(msg, level) {
  const el = document.getElementById("parseLogEntries");
  if (!el) return;
  const line = document.createElement("div");
  line.className = "log-entry log-level-" + (level || "info");
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------
let _allFindings = [];
let _showAccepted = false;

async function loadFindings() {
  try {
    const r = await fetch(`/api/findings/${PROJECT_ID}`);
    const d = await r.json();
    _allFindings = d.findings || [];
    renderFindingsTable(_allFindings);
    updateFindingsBadge(_allFindings.filter(f => !f.accepted).length);

    const rd = await fetch(`/api/findings_diff/${PROJECT_ID}`);
    const dd = await rd.json();
    if (dd.summary) renderDiffBanner(dd.summary);

    renderQuickWins(_allFindings);
  } catch(e) { console.error("loadFindings:", e); }
}

function updateFindingsBadge(count) {
  const badge = document.getElementById("findingsBadge");
  if (badge) badge.textContent = count;
}

window.filterFindings = function() {
  const search = (document.getElementById("findingsSearch")?.value || "").toLowerCase();
  const risk = document.getElementById("filterRisk")?.value || "";
  const fw = document.getElementById("filterFramework")?.value || "";

  let filtered = _allFindings.filter(f => {
    if (!_showAccepted && f.accepted) return false;
    if (risk && (f.risk || "").toUpperCase() !== risk.toUpperCase()) return false;
    if (fw && f.framework !== fw) return false;
    if (search && !(
      (f.title || "").toLowerCase().includes(search) ||
      (f.description || "").toLowerCase().includes(search) ||
      (f.framework_section || "").toLowerCase().includes(search)
    )) return false;
    return true;
  });

  renderFindingsTable(filtered);
  const countEl = document.getElementById("findingsCount");
  if (countEl) countEl.textContent = `${filtered.length} of ${_allFindings.length}`;
};

const searchFindings = debounce(filterFindings, 200);
window.searchFindings = searchFindings;

function renderFindingsTable(findings) {
  const tbody = document.getElementById("findingsTbody");
  if (!tbody) return;
  if (!findings.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No findings match the current filters.</td></tr>`;
    return;
  }
  tbody.innerHTML = findings.map(f => {
    const accepted = f.accepted ? " accepted" : "";
    const isNew = f.is_new ? " is-new" : "";
    const changed = f.risk_changed ? " risk-changed" : "";
    const prevRisk = f.previous_risk
      ? `<span class="changed-badge" title="Was: ${_esc(f.previous_risk)}">CHANGED</span>` : "";
    const newBadge = f.is_new ? `<span class="new-badge">NEW</span>` : "";
    const accBadge = f.accepted ? `<span class="accepted-badge">ACCEPTED</span>` : "";
    const lines = (f.triggered_lines || []).join(", ");
    const acceptBtn = f.accepted
      ? `<button class="btn btn-sm btn-ghost" onclick='unacceptFinding("${f.id}")'>Un-Accept</button>`
      : `<button class="btn btn-sm btn-ghost" onclick='openAcceptModal("${f.id}","${_esc(f.title).replace(/'/g,"&#39;")}">Accept</button>`;
    const fpBtn = `<button class="btn btn-sm btn-ghost" title="Mark as false positive" onclick='markFp("${f.id}",this)'>🚫 FP</button>`;

    return `
    <tr id="finding-row-${f.id}" class="findings-row${accepted}${isNew}${changed}">
      <td>${_riskBadge(f.risk)} ${prevRisk} ${newBadge} ${accBadge}</td>
      <td class="${f.accepted ? "text-strike" : ""}">${_esc(f.title)}</td>
      <td>${_esc(f.framework)}</td>
      <td>${_esc(f.framework_section)}</td>
      <td class="mono">${_esc(lines) || "—"}</td>
      <td>${_esc(f.vendor)}</td>
      <td>
        <button class="btn btn-sm btn-ghost" onclick='openFindingDetail("${f.id}")'>Details</button>
        <button class="btn btn-sm btn-ghost" onclick='viewFindingInConfig(${JSON.stringify({id:f.id,config_file:f.config_file,triggered_lines:f.triggered_lines})})'>View</button>
        ${acceptBtn}
        ${fpBtn}
      </td>
    </tr>`;
  }).join("");
}

// ── False-positive management ─────────────────────────────────────────────
// Mark removes finding from findings.json (Bastion-wrapped) + adds to
// false_positives.json + false_positives.csv. Recover does the reverse.
// 'Show False Positives' replaces the active-findings table with the FP list.
let _fpShown = false;

async function markFp(findingId, btn) {
  if (!findingId) return;
  if (!confirm("Mark this finding as a false positive? It will be moved to false_positives.json/csv and can be recovered later.")) return;
  if (btn) { btn.disabled = true; btn.textContent = "…"; }
  try {
    const r = await fetch("/api/mark_false_positive", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({project_id: PROJECT_ID, finding_id: findingId}),
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
    _allFindings = _allFindings.filter(fi => fi.id !== findingId);
    renderFindingsTable(_allFindings);
  } catch (e) {
    alert("Mark as false positive failed: " + e.message);
    if (btn) { btn.disabled = false; btn.textContent = "🚫 FP"; }
  }
}

async function recoverFp(findingId, btn) {
  if (!findingId) return;
  if (btn) { btn.disabled = true; btn.textContent = "…"; }
  try {
    const r = await fetch("/api/recover_false_positive", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({project_id: PROJECT_ID, finding_id: findingId}),
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || `HTTP ${r.status}`);
    const row = document.querySelector(`#fp-row-${findingId}`);
    if (row) row.remove();
    // Refresh active findings so the recovered one is in the list when toggled off
    try {
      const rf = await fetch(`/api/findings/${PROJECT_ID}`);
      const df = await rf.json();
      _allFindings = df.findings || [];
    } catch {}
  } catch (e) {
    alert("Recover failed: " + e.message);
    if (btn) { btn.disabled = false; btn.textContent = "↩ Recover"; }
  }
}

async function _loadFpList() {
  try {
    const r = await fetch(`/api/false_positives/${PROJECT_ID}`);
    const d = await r.json();
    return Array.isArray(d.false_positives) ? d.false_positives : [];
  } catch { return []; }
}

function _renderFpRow(f) {
  const fid    = f.id || "";
  const marked = f.marked_fp_at || "—";
  return `<tr id="fp-row-${fid}" class="findings-row">
    <td>${_riskBadge(f.risk)}</td>
    <td>${_esc(f.title || "")}</td>
    <td>${_esc(f.framework || "")}</td>
    <td>${_esc(f.framework_section || "")}</td>
    <td class="mono">${_esc(marked)}</td>
    <td>${_esc(f.vendor || "")}</td>
    <td><button class="btn btn-sm btn-ghost" onclick='recoverFp("${fid}",this)' title="Restore to active findings">↩ Recover</button></td>
  </tr>`;
}

async function toggleFpView() {
  _fpShown = !_fpShown;
  const btn  = document.getElementById("btnToggleFp");
  const tb   = document.getElementById("findingsTbody");
  if (!tb) return;
  if (_fpShown) {
    if (btn) btn.textContent = "👁 Show Active Findings";
    const fps = await _loadFpList();
    tb.innerHTML = fps.length
      ? fps.map(_renderFpRow).join("")
      : `<tr class="empty-row"><td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted)">No false positives.</td></tr>`;
  } else {
    if (btn) btn.textContent = "🚫 Show False Positives";
    renderFindingsTable(_allFindings);
  }
}

window.markFp       = markFp;
window.recoverFp    = recoverFp;
window.toggleFpView = toggleFpView;

window.openFindingDetail = function(findingId) {
  const f = _allFindings.find(fi => fi.id === findingId);
  if (!f) return;
  const modal = document.getElementById("findingDetailModal");
  if (!modal) return;

  const rb = document.getElementById("detailRiskBadge");
  if (rb) rb.innerHTML = _riskBadge(f.risk);

  const titleEl = document.getElementById("detailTitle");
  if (titleEl) titleEl.textContent = f.title || "";

  const cvssEl = document.getElementById("detailCvss");
  if (cvssEl) {
    if (f.cvss_score) {
      cvssEl.innerHTML = `<strong>CVSS ${f.cvss_score}</strong> <span class="text-muted font-mono" style="font-size:11px">${_esc(f.cvss_vector||"")}</span>`;
    } else {
      cvssEl.innerHTML = "";
    }
  }

  const fwEl = document.getElementById("detailFramework");
  if (fwEl) {
    let fwHtml = `<strong>Framework</strong>${_esc(f.framework)} ${_esc(f.framework_section)} — ${_esc(f.framework_control_name)}`;
    if (f.additional_frameworks && f.additional_frameworks.length) {
      fwHtml += f.additional_frameworks.map(af =>
        `<br><small>${_esc(af.framework)} ${_esc(af.section)}</small>`).join("");
    }
    fwEl.innerHTML = fwHtml;
  }

  const descEl = document.getElementById("detailDescription");
  if (descEl) descEl.innerHTML = `<strong>Description</strong>${_esc(f.description||"")}`;

  const impactEl = document.getElementById("detailImpact");
  if (impactEl) impactEl.innerHTML = `<strong>Impact</strong>${_esc(f.impact||"")}`;

  const trigEl = document.getElementById("detailTriggered");
  if (trigEl) {
    if (f.triggered_raw && f.triggered_raw.length) {
      trigEl.innerHTML = `<strong>Triggered Config (Lines: ${(f.triggered_lines||[]).join(", ")})</strong>
        <div class="code-block">${_esc(f.triggered_raw.join("\n"))}</div>`;
    } else {
      trigEl.innerHTML = "";
    }
  }

  const recEl = document.getElementById("detailRecommendation");
  if (recEl) recEl.innerHTML = `<strong>Recommendation</strong>${_esc(f.recommendation||"")}`;

  const notesEl = document.getElementById("detailNotes");
  if (notesEl) {
    notesEl.value = f.analyst_notes || "";
    notesEl.dataset.findingId = findingId;
    notesEl.onblur = () => saveNote(findingId, notesEl.value);
  }

  // v1.1 enrichment row — CVSS already shown above; this adds CWE / MITRE /
  // compliance lists / KEV / etc. when present. Renders nothing if the
  // finding carries no v1.1 fields.
  let enrichEl = document.getElementById("detailV11Enrichment");
  if (!enrichEl && window.renderV11Enrichment) {
    // Lazy-inject container at modal-body end so we don't have to edit the template
    const body = modal.querySelector(".modal-body") || modal;
    enrichEl = document.createElement("div");
    enrichEl.id = "detailV11Enrichment";
    body.appendChild(enrichEl);
  }
  if (enrichEl && window.renderV11Enrichment) {
    enrichEl.innerHTML = window.renderV11Enrichment(f);
  }

  modal.removeAttribute("hidden");
};

function saveNote(findingId, note) {
  fetch(`/api/add_note/${findingId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ project_id: PROJECT_ID, note }),
  }).catch(e => console.error("saveNote:", e));
}

window.filterByRisk = function(risk) {
  const sel = document.getElementById("filterRisk");
  if (sel) sel.value = risk;
  filterFindings();
};

window.exportFindingsCSV = function() {
  const rows = [["Risk","Title","Framework","Section","Lines","Vendor","CVSS","Accepted"]];
  _allFindings.forEach(f => {
    rows.push([
      f.risk, f.title, f.framework, f.framework_section,
      (f.triggered_lines||[]).join(";"), f.vendor,
      f.cvss_score||"", f.accepted?"Yes":"No"
    ]);
  });
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `findings_${PROJECT_ID}.csv`;
  a.click();
};

// ---------------------------------------------------------------------------
// Accept / Un-accept
// ---------------------------------------------------------------------------
window.openAcceptModal = function(findingId, findingTitle) {
  document.getElementById("acceptFindingId").value = findingId;
  const titleEl = document.getElementById("acceptModalTitle");
  if (titleEl) titleEl.textContent = findingTitle || "";
  const just = document.getElementById("acceptJustification");
  if (just) just.value = "";
  document.getElementById("acceptModal").removeAttribute("hidden");
};

window.submitAccept = function() {
  const fid = document.getElementById("acceptFindingId").value;
  const just = (document.getElementById("acceptJustification")?.value || "").trim();
  if (!just) { alert("Justification is required."); return; }
  fetch("/api/accept_finding", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project_id: PROJECT_ID,
      finding_id: fid,
      justification: just,
      accept: true,
    }),
  })
  .then(r => r.json())
  .then(d => {
    if (d.ok) {
      document.getElementById("acceptModal").setAttribute("hidden", "");
      loadFindings();
    } else {
      alert("Error: " + d.error);
    }
  })
  .catch(e => console.error(e));
};

window.unacceptFinding = function(findingId) {
  fetch("/api/accept_finding", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project_id: PROJECT_ID,
      finding_id: findingId,
      justification: "",
      accept: false,
    }),
  })
  .then(r => r.json())
  .then(d => { if (d.ok) loadFindings(); })
  .catch(e => console.error(e));
};

// ---------------------------------------------------------------------------
// Diff banner
// ---------------------------------------------------------------------------
function renderDiffBanner(summary) {
  if (!summary) return;
  const banner = document.getElementById("diffBanner");
  if (!banner) return;
  const parts = [];
  if (summary.new && summary.new.length)
    parts.push(`<span class="diff-pill-new" onclick="filterNew()">+${summary.new.length} new</span>`);
  if (summary.resolved && summary.resolved.length)
    parts.push(`<span class="diff-pill-resolved">${summary.resolved.length} resolved</span>`);
  if (summary.risk_changed && summary.risk_changed.length)
    parts.push(`<span class="diff-pill-changed">${summary.risk_changed.length} risk changed</span>`);
  if (parts.length) {
    banner.innerHTML = `<strong>Changes since last analysis:</strong> ` + parts.join(" ");
    banner.removeAttribute("hidden");
  }
}

window.filterNew = function() {
  renderFindingsTable(_allFindings.filter(f => f.is_new));
};

// ---------------------------------------------------------------------------
// Quick wins
// ---------------------------------------------------------------------------
function renderQuickWins(findings) {
  const container = document.getElementById("quickWinsContainer");
  if (!container) return;
  const qw = findings.filter(f =>
    ["Critical","High"].includes(f.risk) &&
    f.remediation_effort === "immediate" &&
    !f.accepted
  ).slice(0, 3);

  if (!qw.length) {
    container.innerHTML = `<p class="qw-empty">No immediate quick wins — all high-impact issues require planning time.</p>`;
    return;
  }
  container.innerHTML = qw.map((f, i) => `
    <div class="qw-card">
      <div class="qw-header">
        <span class="qw-number">${i+1}</span>
        ${_riskBadge(f.risk)}
        <span class="qw-effort">&#9889; Immediate Fix</span>
      </div>
      <div class="qw-title">${_esc(f.title)}</div>
      <div class="qw-rec">${_esc((f.recommendation||"").split("\n")[0].replace(/^\d+\.\s*/,""))}</div>
      <button class="btn btn-sm btn-ghost"
              onclick="switchTab('findings',null);filterByRisk('${f.risk}')">
        View in Findings &rarr;</button>
    </div>
  `).join("");
}

// ---------------------------------------------------------------------------
// Summary tab
// ---------------------------------------------------------------------------
async function loadSummary() {
  try {
    const r = await fetch(`/api/findings/${PROJECT_ID}`);
    const d = await r.json();
    const findings = d.findings || [];
    renderRiskCards(findings);
    renderFrameworkMatrix(findings);
    renderQuickWins(findings);
    renderAcceptedRiskSummary(findings);
    renderTopFindings(findings.filter(f => !f.accepted).slice(0, 5));
  } catch(e) { console.error("loadSummary:", e); }
}

function renderRiskCards(findings) {
  const active = findings.filter(f => !f.accepted);
  const counts = {};
  active.forEach(f => counts[f.risk] = (counts[f.risk] || 0) + 1);
  const container = document.getElementById("riskCardsContainer");
  if (!container) return;
  const levels = ["Critical","High","Medium","Low","Informational"];
  container.innerHTML = levels.map(l => `
    <div class="risk-count-card" style="border-color:${RISK_COLORS[l]}">
      <div class="risk-count" style="color:${RISK_COLORS[l]}">${counts[l]||0}</div>
      <div class="risk-label">${l}</div>
    </div>
  `).join("");
}

function renderFrameworkMatrix(findings) {
  const container = document.getElementById("frameworkMatrixContainer");
  if (!container) return;
  const matrix = {};
  const levels = ["Critical","High","Medium","Low","Informational"];
  findings.filter(f => !f.accepted).forEach(f => {
    const fw = f.framework || "Unknown";
    matrix[fw] = matrix[fw] || {};
    matrix[fw][f.risk] = (matrix[fw][f.risk] || 0) + 1;
  });
  const fws = Object.keys(matrix);
  if (!fws.length) {
    container.innerHTML = `<p class="text-muted">No findings yet.</p>`;
    return;
  }
  let html = `<table class="framework-matrix-table"><thead><tr><th>Framework</th>
    ${levels.map(l => `<th style="color:${RISK_COLORS[l]}">${l}</th>`).join("")}
    <th>Total</th></tr></thead><tbody>`;
  fws.forEach(fw => {
    const total = levels.reduce((s, l) => s + (matrix[fw][l] || 0), 0);
    html += `<tr><td><strong>${_esc(fw)}</strong></td>
      ${levels.map(l => `<td>${matrix[fw][l] || ""}</td>`).join("")}
      <td><strong>${total}</strong></td></tr>`;
  });
  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderAcceptedRiskSummary(findings) {
  const accepted = findings.filter(f => f.accepted);
  if (!accepted.length) return;
  const counts = {};
  accepted.forEach(f => counts[f.risk] = (counts[f.risk] || 0) + 1);
  const container = document.getElementById("riskCardsContainer");
  if (!container) return;
  const levels = ["Critical","High","Medium","Low","Informational"];
  const row = document.createElement("div");
  row.style.cssText = "width:100%;font-size:11px;color:var(--text-muted);margin-top:8px";
  row.innerHTML = `Accepted Risk: ` + levels.filter(l => counts[l])
    .map(l => `<span class="accepted-badge">${l}: ${counts[l]}</span>`).join(" ");
  container.appendChild(row);
}

function renderTopFindings(findings) {
  const container = document.getElementById("topFindingsContainer");
  if (!container) return;
  if (!findings.length) {
    container.innerHTML = `<p class="text-muted">No findings yet.</p>`;
    return;
  }
  container.innerHTML = findings.map((f, i) => `
    <div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:10px">
      <span style="color:var(--text-muted);min-width:20px">${i+1}.</span>
      ${_riskBadge(f.risk)}
      <span>${_esc(f.title)}</span>
    </div>
  `).join("");
}

// ---------------------------------------------------------------------------
// Architecture
// ---------------------------------------------------------------------------
let _archScale = 1;
let _archDragging = false;
let _archDragStart = { x: 0, y: 0 };
let _archTranslate = { x: 0, y: 0 };

function loadArchitecture() {
  const img = document.getElementById("archDiagram");
  if (!img) return;
  img.src = `/api/architecture/${PROJECT_ID}?t=${Date.now()}`;
  img.onload = () => {
    img.removeAttribute("hidden");
    const ph = document.getElementById("archPlaceholder");
    if (ph) ph.setAttribute("hidden", "");
    initZoomPan();
  };
  img.onerror = () => {
    const ph = document.getElementById("archPlaceholder");
    if (ph) ph.removeAttribute("hidden");
    img.setAttribute("hidden", "");
  };
}

function initZoomPan() {
  const img = document.getElementById("archDiagram");
  if (!img) return;
  const viewer = img.closest(".architecture-viewer");
  if (!viewer) return;

  viewer.addEventListener("wheel", e => {
    e.preventDefault();
    _archScale = Math.max(0.3, Math.min(4.0, _archScale - e.deltaY * 0.001));
    applyArchTransform();
  }, { passive: false });

  img.addEventListener("mousedown", e => {
    _archDragging = true;
    _archDragStart = { x: e.clientX - _archTranslate.x, y: e.clientY - _archTranslate.y };
    img.style.cursor = "grabbing";
  });
  document.addEventListener("mousemove", e => {
    if (!_archDragging) return;
    _archTranslate = { x: e.clientX - _archDragStart.x, y: e.clientY - _archDragStart.y };
    applyArchTransform();
  });
  document.addEventListener("mouseup", () => {
    _archDragging = false;
    if (img) img.style.cursor = "grab";
  });
}

function applyArchTransform() {
  const img = document.getElementById("archDiagram");
  if (img) img.style.transform =
    `translate(${_archTranslate.x}px,${_archTranslate.y}px) scale(${_archScale})`;
}

window.zoomIn = function() { _archScale = Math.min(4.0, _archScale + 0.2); applyArchTransform(); };
window.zoomOut = function() { _archScale = Math.max(0.3, _archScale - 0.2); applyArchTransform(); };
window.zoomReset = function() {
  _archScale = 1; _archTranslate = { x: 0, y: 0 };
  const img = document.getElementById("archDiagram");
  if (img) img.style.transform = "";
};

window.downloadDiagram = function() {
  const a = document.createElement("a");
  a.href = `/api/architecture/${PROJECT_ID}`;
  a.download = "architecture.png";
  a.click();
};

window.regenerateDiagram = function() {
  fetch(`/api/regenerate_diagram/${PROJECT_ID}`, { method: "POST" })
    .then(r => r.json())
    .then(d => {
      if (d.success) loadArchitecture();
      else console.error("Diagram regen failed:", d.error);
    });
};

// ---------------------------------------------------------------------------
// Config viewer
// ---------------------------------------------------------------------------
let _svLines = [];
let _svFilename = "";

window.openConfigViewer = async function(filename) {
  try {
    const r = await fetch(`/api/config_content/${PROJECT_ID}/${encodeURIComponent(filename)}`);
    const d = await r.json();
    if (d.error) { console.error(d.error); return; }
    _svLines = d.content.split("\n");
    _svFilename = d.filename;
    const fnEl = document.getElementById("svFilename");
    if (fnEl) fnEl.textContent = d.filename;
    const lcEl = document.getElementById("svLineCount");
    if (lcEl) lcEl.textContent = `${d.line_count} lines`;
    renderConfigViewer(_svLines, []);
    const panel = document.getElementById("configViewerPanel");
    if (panel) panel.removeAttribute("hidden");
    const body = document.getElementById("svBody");
    if (body) body.scrollTop = 0;
  } catch(e) { console.error("Config viewer error:", e); }
};

function renderConfigViewer(lines, highlightLines) {
  const hlSet = new Set(highlightLines || []);
  const pre = document.getElementById("svContent");
  if (!pre) return;
  pre.innerHTML = lines.map((line, i) => {
    const lineNo = i + 1;
    const hl = hlSet.has(lineNo) ? " sv-line-highlight" : "";
    const escaped = _esc(line) || " ";
    const colored = syntaxColorLine(escaped);
    return `<span class="sv-line${hl}" id="svLine${lineNo}">` +
      `<span class="sv-lineno">${lineNo}</span>` +
      `<span class="sv-code">${colored}</span></span>`;
  }).join("\n");
}

function syntaxColorLine(escaped) {
  return escaped
    .replace(/\b(permit|allow|accept)\b/gi,
             '<span class="sv-permit">$1</span>')
    .replace(/\b(deny|drop|block|reject)\b/gi,
             '<span class="sv-deny">$1</span>')
    .replace(/\b(interface|nameif|access-list|access-group|object|object-group|route|nat|hostname|security-level|set|config|edit|zone|policy|address)\b/gi,
             '<span class="sv-keyword">$1</span>')
    .replace(/(![^\n]*|#[^\n]*)$/gm,
             '<span class="sv-comment">$&</span>')
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g,
             '<span class="sv-ip">$1</span>');
}

function highlightAndScrollTo(lineNumbers) {
  if (!lineNumbers || !lineNumbers.length) return;
  renderConfigViewer(_svLines, lineNumbers);
  const firstLine = Math.min(...lineNumbers);
  const el = document.getElementById(`svLine${firstLine}`);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
}

window.searchConfig = function() {
  const query = (document.getElementById("svSearch")?.value || "").toLowerCase();
  if (!query) { renderConfigViewer(_svLines, []); return; }
  const matchLines = _svLines
    .map((l, i) => l.toLowerCase().includes(query) ? i + 1 : null)
    .filter(Boolean);
  const mc = document.getElementById("svMatchCount");
  if (mc) mc.textContent = `${matchLines.length} matches`;
  renderConfigViewer(_svLines, matchLines);
};

window.closeConfigViewer = function() {
  const panel = document.getElementById("configViewerPanel");
  if (panel) panel.setAttribute("hidden", "");
};

window.viewFindingInConfig = function(finding) {
  switchTab("source", null);
  const sourceTab = document.querySelector('[data-tab="source"]');
  if (sourceTab) sourceTab.click();

  openConfigViewer(finding.config_file || finding.filename || "").then(() => {
    if (finding.triggered_lines && finding.triggered_lines.length) {
      highlightAndScrollTo(finding.triggered_lines);
    }
  }).catch(() => {});
};

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------
function loadAllLogs() {
  loadParseLog();
  loadAppLog();
}

function loadParseLog() {
  if (typeof PROJECT_ID === "undefined") return;
  fetch(`/api/parse_log/${PROJECT_ID}`)
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById("parseLogEntries");
      if (!el) return;
      el.innerHTML = "";
      (d.entries || []).forEach(e => {
        const div = document.createElement("div");
        div.className = "log-entry log-level-" + (e.level || "info").toLowerCase();
        div.textContent = `[${e.ts || ""}] [${e.source || ""}] ${e.message || ""}`;
        el.appendChild(div);
      });
    })
    .catch(e => console.error(e));
}

function loadAppLog() {
  if (typeof PROJECT_ID === "undefined") return;
  fetch(`/api/bastion_log/${PROJECT_ID}`)
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById("appLogEntries");
      if (!el) return;
      el.innerHTML = "";
      (d.entries || []).forEach(e => {
        const div = document.createElement("div");
        div.className = "log-entry log-level-info";
        div.textContent = `[${e.ts || ""}] ${e.event || JSON.stringify(e)}`;
        el.appendChild(div);
      });
    })
    .catch(e => console.error(e));
}

window.showLogPane = function(name) {
  document.querySelectorAll(".log-subtab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".log-pane").forEach(p => p.classList.remove("active"));
  const btn = document.querySelector(`.log-subtab[onclick="showLogPane('${name}')"]`);
  if (btn) btn.classList.add("active");
  const pane = document.getElementById(`logPane${name}`);
  if (pane) pane.classList.add("active");
};

window.toggleLogScroll = function() {};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
function loadErrors() {
  if (typeof PROJECT_ID === "undefined") return;
  fetch(`/api/errors/${PROJECT_ID}`)
    .then(r => r.json())
    .then(d => {
      const container = document.getElementById("errorEntries");
      if (!container) return;
      const entries = d.entries || [];
      const badge = document.getElementById("errorsBadge");
      if (badge) badge.textContent = entries.length;
      if (!entries.length) {
        container.innerHTML = `<p class="empty-state">No errors recorded.</p>`;
        return;
      }
      container.innerHTML = entries.map((e, i) => `
        <div class="error-entry">
          <div class="error-type">${_esc(e.type||"")} <span style="color:var(--text-muted)">${_esc(e.source||"")}</span></div>
          <div style="margin-top:4px">${_esc(e.message||"")}</div>
          ${e.detail ? `
          <a href="#" onclick="this.nextElementSibling.classList.toggle('open');return false"
             style="font-size:11px;color:var(--text-muted)">&#9660; details</a>
          <div class="error-detail">${_esc(e.detail)}</div>` : ""}
        </div>
      `).join("");
    })
    .catch(e => console.error(e));
}

function appendError(type, source, message) {
  const container = document.getElementById("errorEntries");
  if (!container) return;
  const placeholder = container.querySelector(".empty-state");
  if (placeholder) placeholder.remove();
  const div = document.createElement("div");
  div.className = "error-entry";
  div.innerHTML = `<div class="error-type">${_esc(type)} <span>${_esc(source)}</span></div>
    <div style="margin-top:4px">${_esc(message)}</div>`;
  container.prepend(div);
  const badge = document.getElementById("errorsBadge");
  if (badge) badge.textContent = parseInt(badge.textContent || 0) + 1;
}

// ---------------------------------------------------------------------------
// DOMContentLoaded init
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  initPalettePicker();
  initModeToggle();
  initUploadZone();
  initSocket();
  // On project pages, activate the source tab by default
  if (typeof PROJECT_ID !== "undefined") {
    const srcBtn = document.querySelector('[data-tab="source"]');
    if (srcBtn) switchTab("source", srcBtn);
  }
});
