// app.js - Pramaan Forensic Evidence Management System Client Logic
let currentUser = null;
let currentCaseId = 'case_del_2026_01';
let casesList = [];
let annotations = [
  { x: 340, y: 210, label: 'Optimal DNA Swab Target' }
];

// Initialize application
document.addEventListener('DOMContentLoaded', async () => {
  setupTabs();
  setupThemeToggle();
  setupModals();
  setupCanvasSimulation();
  setupEventListeners();

  await checkAuthAndInitialize();
  setupSseStream();
});

// Authentication & Initial State
async function checkAuthAndInitialize() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
    } else {
      // Auto-switch to default Investigating Officer for demo
      await switchDemoRole('investigating_officer');
    }
  } catch (err) {
    console.warn('Auth check fallback to demo switch:', err);
    await switchDemoRole('investigating_officer');
  }

  updateUserUI();
  await refreshAllData();
}

async function switchDemoRole(role) {
  try {
    const res = await fetch('/api/auth/demo-switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    });
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
      updateUserUI();
      await refreshAllData();
    }
  } catch (err) {
    console.error('Error switching demo role:', err);
  }
}

function updateUserUI() {
  if (!currentUser) return;
  const nameEl = document.getElementById('activeUserName');
  const roleEl = document.getElementById('activeUserRole');
  const roleSelect = document.getElementById('demoRoleSelect');

  if (nameEl) nameEl.textContent = currentUser.fullName;
  if (roleEl) {
    const roleLabels = {
      investigating_officer: 'Investigating Officer · ' + currentUser.district,
      forensic_expert: 'Senior Scientific Officer · FSL',
      lab_director: 'Director · FSL Services',
      magistrate_or_prosecutor: 'Chief Metropolitan Magistrate · Court'
    };
    roleEl.textContent = roleLabels[currentUser.role] || currentUser.role;
  }
  if (roleSelect) {
    roleSelect.value = currentUser.role;
  }
}

// Tab Switching
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }

      // Tab specific reloads
      if (targetId === 'tab-triage') loadTriageDashboard();
      if (targetId === 'tab-custody') loadCustodyView();
      if (targetId === 'tab-court') loadCertificateView();
      if (targetId === 'tab-supervision') loadSupervisionChat();
    });
  });
}

// Theme Toggle (2 AM Crime Scene / Day Mode)
function setupThemeToggle() {
  const toggleBtn = document.getElementById('themeToggleBtn');
  toggleBtn.addEventListener('click', () => {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', newTheme);
    toggleBtn.textContent = newTheme === 'light' ? '☀️' : '🌙';
  });
}

// Server-Sent Events (SSE) for Real-Time Updates
function setupSseStream() {
  const evtSource = new EventSource('/api/events');

  evtSource.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      handleLiveEvent(payload);
    } catch (e) {
      console.error('SSE parse error:', e);
    }
  };

  evtSource.onerror = () => {
    // Reconnects automatically by browser
  };
}

function handleLiveEvent(evt) {
  if (evt.type === 'supervision_message') {
    appendChatMessage(evt.data);
    if (evt.data.payload && evt.data.payload.x) {
      annotations.push({
        x: evt.data.payload.x,
        y: evt.data.payload.y,
        label: evt.data.payload.label || 'Expert Marker'
      });
    }
  } else if (evt.type === 'checklist_updated' || evt.type === 'checklist_verified') {
    if (evt.data.caseId === currentCaseId) {
      loadCaseDetail(currentCaseId);
    }
  } else if (evt.type === 'exhibit_added' || evt.type === 'custody_transfer') {
    if (document.getElementById('tab-custody').classList.contains('active')) {
      loadCustodyView();
    }
    loadCaseDetail(currentCaseId);
  }
}

// Data Refresh
async function refreshAllData() {
  await loadCases();
  await loadCaseDetail(currentCaseId);
  await loadTriageDashboard();
}

async function loadCases() {
  try {
    const res = await fetch('/api/cases');
    const data = await res.json();
    casesList = data.cases || [];

    // Populate Cases Table on Dashboard
    const tbody = document.getElementById('casesTableBody');
    if (tbody) {
      tbody.innerHTML = casesList.map(c => `
        <tr>
          <td>
            <strong>${c.fir_number}</strong><br>
            <span style="font-size:0.75rem; color:var(--text-muted);">${c.police_station}, ${c.district}</span>
          </td>
          <td>
            <div style="font-weight:600;">${c.offence_type}</div>
            <span class="chk-badge-ref">${c.penal_sections}</span>
          </td>
          <td>
            <span class="chk-badge-verified">Sec 176(3) BNSS</span>
          </td>
          <td style="font-size:0.8rem; max-width:200px;">${c.scene_location}</td>
          <td>${c.io_name || 'SI Rajesh Sharma'}</td>
          <td>${c.expert_name || 'Dr. Aditi Varma'}</td>
          <td>
            <span class="tab-badge" style="background:${getStatusColor(c.status)}; color:#fff;">
              ${formatStatus(c.status)}
            </span>
          </td>
          <td>
            <button class="btn-icon" onclick="selectCase('${c.id}')" title="Inspect Case">
              👁️ Open
            </button>
          </td>
        </tr>
      `).join('');
    }

    // Populate Selectors
    const captureSelector = document.getElementById('captureCaseSelector');
    const certSelector = document.getElementById('certCaseSelector');

    const optionsHtml = casesList.map(c => `<option value="${c.id}">${c.fir_number} · ${c.police_station}</option>`).join('');
    if (captureSelector) {
      captureSelector.innerHTML = optionsHtml;
      captureSelector.value = currentCaseId;
    }
    if (certSelector) {
      certSelector.innerHTML = optionsHtml;
      certSelector.value = currentCaseId;
    }

    // Update Dashboard Metrics
    const activeCount = casesList.filter(c => c.status === 'scene_active').length;
    const courtReadyCount = casesList.filter(c => c.status === 'court_ready').length;
    document.getElementById('statActiveScenes').textContent = activeCount;
    document.getElementById('statCourtReady').textContent = courtReadyCount;

  } catch (err) {
    console.error('Error loading cases:', err);
  }
}

window.selectCase = function(caseId) {
  currentCaseId = caseId;
  const captureSelector = document.getElementById('captureCaseSelector');
  if (captureSelector) captureSelector.value = caseId;
  loadCaseDetail(caseId);

  // Switch to field capture tab
  const captureTabBtn = document.querySelector('[data-tab="tab-capture"]');
  if (captureTabBtn) captureTabBtn.click();
};

async function loadCaseDetail(caseId) {
  try {
    const res = await fetch(`/api/cases/${caseId}`);
    if (!res.ok) return;
    const data = await res.json();
    const { case: c, checklist, exhibits, supervision } = data;

    // Update Supervision Header
    const supHeader = document.getElementById('supCaseName');
    if (supHeader) supHeader.textContent = `${c.fir_number} (${c.police_station})`;

    // Update Checklist UI
    renderChecklist(checklist);

    // Update Exhibits List on Field Capture
    renderFieldExhibits(exhibits);

    // Populate Custody Exhibit Dropdown
    const custodySelector = document.getElementById('custodyExhibitSelect');
    if (custodySelector) {
      custodySelector.innerHTML = exhibits.map(e => `<option value="${e.id}">${e.exhibit_code} - ${e.category}</option>`).join('');
      if (exhibits.length > 0) {
        loadExhibitCustodyLedger(exhibits[0].id);
      }
    }
  } catch (err) {
    console.error('Error loading case detail:', err);
  }
}

function renderChecklist(checklist) {
  const container = document.getElementById('checklistItemsList');
  if (!container) return;

  const completedCount = checklist.filter(item => item.is_completed === 1).length;
  const progressBadge = document.getElementById('checklistProgressBadge');
  if (progressBadge) {
    progressBadge.textContent = `${completedCount} / ${checklist.length} Completed`;
  }

  container.innerHTML = checklist.map(item => `
    <div class="checklist-item ${item.is_completed ? 'completed' : ''}">
      <input type="checkbox" class="chk-checkbox" 
        ${item.is_completed ? 'checked' : ''} 
        onchange="toggleChecklistStep('${item.id}', this.checked)">
      <div class="chk-content">
        <div class="chk-header">
          <span class="chk-title">${item.title}</span>
          ${item.expert_verified 
            ? `<span class="chk-badge-verified">✓ Expert Verified</span>` 
            : `<button class="btn-icon" style="font-size:0.7rem; padding:0.2rem 0.4rem;" onclick="expertVerifyStep('${item.id}')">Verify</button>`}
        </div>
        <p class="chk-desc">${item.description}</p>
        <div class="chk-meta">
          <span class="chk-badge-ref">${item.dfss_guideline_ref}</span>
          ${item.expert_notes ? `<span style="color:var(--accent-cyan);">💬 Expert: ${item.expert_notes}</span>` : ''}
        </div>
      </div>
    </div>
  `).join('');
}

window.toggleChecklistStep = async function(stepId, isCompleted) {
  try {
    await fetch(`/api/cases/${currentCaseId}/checklist/${stepId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isCompleted })
    });
    loadCaseDetail(currentCaseId);
  } catch (err) {
    console.error('Error updating checklist:', err);
  }
};

window.expertVerifyStep = async function(stepId) {
  const expertNotes = prompt('Enter FSL Expert Endorsement / Observations:');
  if (expertNotes === null) return;
  try {
    const res = await fetch(`/api/cases/${currentCaseId}/checklist/${stepId}/verify`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: true, expertNotes: expertNotes || 'Approved per DFSS Protocol' })
    });
    if (!res.ok) {
      const err = await res.json();
      alert(err.error || 'Permission denied. Only forensic experts can verify.');
      return;
    }
    loadCaseDetail(currentCaseId);
  } catch (err) {
    console.error('Error verifying step:', err);
  }
};

function renderFieldExhibits(exhibits) {
  const container = document.getElementById('sceneExhibitsList');
  if (!container) return;

  if (exhibits.length === 0) {
    container.innerHTML = `<div style="font-size:0.8rem; color:var(--text-muted);">No exhibits tagged yet. Use "Tag & Hash Exhibit" button above.</div>`;
    return;
  }

  container.innerHTML = exhibits.map(ex => `
    <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:0.65rem; display:flex; justify-content:space-between; align-items:center;">
      <div>
        <strong>${ex.exhibit_code}</strong> · <span style="color:var(--accent-cyan); font-size:0.75rem;">${ex.category}</span>
        <div style="font-size:0.78rem; color:var(--text-muted);">${ex.description}</div>
        <div style="display:flex; gap:0.5rem; align-items:center; margin-top:0.25rem;">
          <span class="hash-pill" title="${ex.sha256_hash}">🔒 ${ex.sha256_hash.slice(0, 16)}...</span>
          <span style="font-size:0.7rem; color:var(--text-muted);">Seal: ${ex.physical_seal_number}</span>
        </div>
      </div>
      <button class="btn-icon" onclick="inspectExhibitLedger('${ex.id}')" title="Inspect Custody Chain">
        ⛓️
      </button>
    </div>
  `).join('');
}

window.inspectExhibitLedger = function(exhibitId) {
  const custodyTab = document.querySelector('[data-tab="tab-custody"]');
  if (custodyTab) custodyTab.click();
  const select = document.getElementById('custodyExhibitSelect');
  if (select) {
    select.value = exhibitId;
    loadExhibitCustodyLedger(exhibitId);
  }
};

// Custody View Logic
async function loadCustodyView() {
  const select = document.getElementById('custodyExhibitSelect');
  if (select && select.value) {
    await loadExhibitCustodyLedger(select.value);
  }
}

async function loadExhibitCustodyLedger(exhibitId) {
  try {
    const res = await fetch(`/api/exhibits/${exhibitId}/ledger`);
    if (!res.ok) return;
    const data = await res.json();
    const { exhibit, ledger, integrityCheck } = data;

    // Render Banner
    const banner = document.getElementById('exhibitDetailBanner');
    if (banner) {
      banner.innerHTML = `
        <div>
          <div style="font-size:1.1rem; font-weight:700;">${exhibit.exhibit_code} · ${exhibit.category}</div>
          <div style="font-size:0.85rem; color:var(--text-muted);">${exhibit.description}</div>
          <div style="font-size:0.78rem; margin-top:0.35rem;">
            <span>📍 Found: ${exhibit.found_location}</span> | 
            <span>🔒 Physical Seal: <strong>${exhibit.physical_seal_number}</strong></span>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:0.75rem; color:var(--text-muted);">CRYPTO SHA-256 FINGERPRINT:</div>
          <span class="hash-pill" style="font-size:0.8rem; max-width:100%;">${exhibit.sha256_hash}</span>
          <div style="font-size:0.75rem; margin-top:0.25rem;">
            Current Custodian: <strong>${exhibit.current_custody_holder}</strong>
          </div>
        </div>
      `;
    }

    // Integrity Badge
    const badge = document.getElementById('custodyIntegrityBadge');
    if (badge) {
      if (integrityCheck.valid) {
        badge.style.background = 'rgba(16,185,129,0.2)';
        badge.style.color = 'var(--accent-green)';
        badge.textContent = `✓ Unbroken Chain (${integrityCheck.totalSteps} Blocks Verified)`;
      } else {
        badge.style.background = 'rgba(239,68,68,0.2)';
        badge.style.color = 'var(--accent-red)';
        badge.textContent = `⚠️ Tamper Alert: Chain Broken at ${integrityCheck.brokenAt}`;
      }
    }

    // Render Timeline
    const timeline = document.getElementById('custodyTimeline');
    if (timeline) {
      timeline.innerHTML = ledger.map(step => `
        <div class="timeline-step">
          <div class="timeline-dot ${step.seal_condition === 'intact_and_verified' ? 'green' : ''}"></div>
          <div class="timeline-card">
            <div class="timeline-header">
              <span class="timeline-title">${formatEventType(step.event_type)}</span>
              <span class="timeline-time">🕒 ${new Date(step.timestamp).toLocaleString()}</span>
            </div>
            <div class="timeline-actors">
              <strong>${step.from_person_name}</strong> (${step.from_designation}) 
              ➔ <strong>${step.to_person_name}</strong> (${step.to_designation})
            </div>
            <div style="font-size:0.8rem; color:var(--text-muted); margin-bottom:0.4rem;">
              📍 <strong>Location:</strong> ${step.location} | <strong>Purpose:</strong> ${step.purpose}
            </div>
            <div style="font-size:0.75rem; display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
              <span class="chk-badge-verified">${formatSeal(step.seal_condition)}</span>
              <span class="hash-pill" title="Block Hash: ${step.ledger_hash}">Block: ${step.ledger_hash.slice(0, 20)}...</span>
              ${step.remarks ? `<span style="color:var(--text-muted);">"${step.remarks}"</span>` : ''}
            </div>
          </div>
        </div>
      `).join('');
    }

  } catch (err) {
    console.error('Error loading exhibit ledger:', err);
  }
}

// Lab Triage View
async function loadTriageDashboard() {
  try {
    const res = await fetch('/api/triage/dashboard');
    if (!res.ok) return;
    const data = await res.json();
    const { metrics, divisionBreakdown, districtWorkload } = data;

    // Render Divisions
    const divTbody = document.getElementById('triageDivisionTableBody');
    if (divTbody) {
      divTbody.innerHTML = divisionBreakdown.map(d => `
        <tr>
          <td><strong>${d.division}</strong></td>
          <td><span class="tab-badge" style="background:rgba(239,68,68,0.2); color:var(--accent-red);">${d.pending}</span></td>
          <td><span class="tab-badge" style="background:rgba(245,158,11,0.2); color:var(--accent-gold);">${d.batched}</span></td>
          <td><span class="tab-badge" style="background:rgba(59,130,246,0.2); color:var(--accent-blue);">${d.testing}</span></td>
          <td><span class="tab-badge" style="background:rgba(16,185,129,0.2); color:var(--accent-green);">${d.analyzed}</span></td>
        </tr>
      `).join('');
    }

    // Render Districts
    const distTbody = document.getElementById('triageDistrictTableBody');
    if (distTbody) {
      distTbody.innerHTML = districtWorkload.map(dw => `
        <tr>
          <td><strong>${dw.district}</strong></td>
          <td>${dw.active_scenes} Active</td>
          <td>${dw.in_lab} Exhibits</td>
          <td><span class="chk-badge-verified">100% Compliant</span></td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Error loading triage:', err);
  }
}

// Certificate & Legal View
async function loadCertificateView() {
  const select = document.getElementById('certCaseSelector');
  const caseId = select ? select.value : currentCaseId;
  const container = document.getElementById('certificateContainer');

  try {
    const res = await fetch(`/api/cases/${caseId}/bsa-certificate`);
    if (!res.ok) {
      container.innerHTML = `
        <div style="text-align:center; padding:2rem;">
          <div style="font-size:1.1rem; margin-bottom:0.5rem;">Certificate of Admissibility not yet issued.</div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:1.5rem;">
            Click the "Issue Certificate" button above to generate the court-admissible certificate under Section 63 of Bharatiya Sakshya Adhiniyam 2023.
          </p>
          <button onclick="issueBsaCert('${caseId}')" class="btn-primary" style="padding:0.6rem 1.5rem; border:none; border-radius:var(--radius-sm); cursor:pointer;">
            Generate & Sign Certificate Now
          </button>
        </div>
      `;
      return;
    }

    const { certificate: cert, parsedData: data } = await res.json();
    renderBsaCertificate(cert, data);
  } catch (err) {
    console.error('Error loading certificate:', err);
  }
}

function renderBsaCertificate(cert, data) {
  const container = document.getElementById('certificateContainer');
  container.innerHTML = `
    <div class="bsa-cert-box" id="printableCert">
      <div class="cert-header">
        <div class="cert-emblem-text">GOVERNMENT OF INDIA · FORENSIC EVIDENCE CERTIFICATE</div>
        <div class="cert-title">CERTIFICATE OF ADMISSIBILITY OF ELECTRONIC RECORD</div>
        <div class="cert-subtitle">Under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA)</div>
        <div style="margin-top:0.4rem; font-size:0.8rem; font-family:var(--font-mono); color:#475569;">
          CERTIFICATE NO: <strong>${cert.certificate_number}</strong> | ISSUED: ${new Date(cert.issued_at).toLocaleString()}
        </div>
      </div>

      <div class="cert-section">
        <p>
          I, <strong>${data.investigatingOfficer.name}</strong>, badge ID <strong>${data.investigatingOfficer.badgeId}</strong>, 
          hereby solemnly affirm and declare in accordance with the provisions of <strong>Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023</strong>:
        </p>
        <ol style="margin-left: 1.5rem; margin-top: 0.5rem;">
          <li>That the electronic videography, forensic photographs, and digital exhibits pertaining to <strong>${data.firNumber}</strong> (${data.policeStation}, ${data.district}) were captured by me during the lawful performance of investigation duties under <strong>Section 176(3) of the Bharatiya Nagarik Suraksha Sanhita, 2023 (BNSS)</strong>.</li>
          <li>That throughout the capture, transmission, and laboratory handover, the computer/field recording device (<strong>${data.captureDevice}</strong>) operated properly and with cryptographic integrity protections.</li>
          <li>That all exhibits were sealed at the locus delicti under live remote supervision of <strong>${data.supervisingForensicExpert.name}</strong> (${data.supervisingForensicExpert.designation}).</li>
        </ol>
      </div>

      <div class="cert-section">
        <strong>SCHEDULE OF REGISTERED EXHIBITS & CRYPTOGRAPHIC FINGERPRINTS:</strong>
        <table style="width:100%; border-collapse:collapse; margin-top:0.5rem; font-size:0.85rem;" border="1">
          <thead>
            <tr style="background:#f8fafc;">
              <th style="padding:4px 8px;">Exhibit Code</th>
              <th style="padding:4px 8px;">Classification</th>
              <th style="padding:4px 8px;">Physical Seal No.</th>
              <th style="padding:4px 8px;">SHA-256 Cryptographic Hash Digest</th>
            </tr>
          </thead>
          <tbody>
            ${data.exhibitsCertified.map(e => `
              <tr>
                <td style="padding:4px 8px;"><strong>${e.code}</strong></td>
                <td style="padding:4px 8px;">${e.category}</td>
                <td style="padding:4px 8px;">${e.physicalSeal}</td>
                <td style="padding:4px 8px; font-family:var(--font-mono); font-size:0.75rem;">${e.sha256}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <div class="cert-section">
        <strong>MASTER AUDIT LEDGER DIGEST & HSM HMAC TOKEN:</strong>
        <div class="cert-hash-block">
          MASTER HASH: ${cert.hash_digest_master}<br>
          VERIFICATION HMAC: ${cert.verification_token}
        </div>
      </div>

      <div class="cert-signatures">
        <div class="signature-line">
          <strong>${data.investigatingOfficer.name}</strong><br>
          Investigating Officer · ${data.policeStation}<br>
          Badge: ${data.investigatingOfficer.badgeId}
        </div>
        <div class="signature-line">
          <strong>${data.supervisingForensicExpert.name}</strong><br>
          ${data.supervisingForensicExpert.designation}<br>
          ${data.supervisingForensicExpert.department}
        </div>
      </div>
    </div>
  `;
}

window.issueBsaCert = async function(caseId) {
  try {
    const res = await fetch(`/api/cases/${caseId}/bsa-certificate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (res.ok) {
      loadCertificateView();
      loadCases();
    } else {
      const err = await res.json();
      alert(err.error || 'Failed to issue certificate');
    }
  } catch (err) {
    console.error('Error generating certificate:', err);
  }
};

// Judicial Hash Verification Sandbox
function setupEventListeners() {
  // Demo Role Selector
  const roleSelect = document.getElementById('demoRoleSelect');
  if (roleSelect) {
    roleSelect.addEventListener('change', (e) => {
      switchDemoRole(e.target.value);
    });
  }

  // Capture Case Selector
  const capSelect = document.getElementById('captureCaseSelector');
  if (capSelect) {
    capSelect.addEventListener('change', (e) => {
      currentCaseId = e.target.value;
      loadCaseDetail(currentCaseId);
    });
  }

  // Custody Exhibit Selector
  const custSelect = document.getElementById('custodyExhibitSelect');
  if (custSelect) {
    custSelect.addEventListener('change', (e) => {
      loadExhibitCustodyLedger(e.target.value);
    });
  }

  // Cert Case Selector
  const certSelect = document.getElementById('certCaseSelector');
  if (certSelect) {
    certSelect.addEventListener('change', () => {
      loadCertificateView();
    });
  }

  const genCertBtn = document.getElementById('generateCertBtn');
  if (genCertBtn) {
    genCertBtn.addEventListener('click', () => {
      const caseId = certSelect ? certSelect.value : currentCaseId;
      issueBsaCert(caseId);
    });
  }

  // Verification Sandbox Buttons
  const btnVerify = document.getElementById('btnVerifyHash');
  if (btnVerify) {
    btnVerify.addEventListener('click', () => {
      const input = document.getElementById('verifyHashInput').value;
      performPublicHashVerification(input);
    });
  }

  const btnTestAuth = document.getElementById('btnTestAuthentic');
  if (btnTestAuth) {
    btnTestAuth.addEventListener('click', () => {
      document.getElementById('verifyHashInput').value = 'EX-01/BLOOD';
      performPublicHashVerification('EX-01/BLOOD');
    });
  }

  const btnTestTamper = document.getElementById('btnTestTampered');
  if (btnTestTamper) {
    btnTestTamper.addEventListener('click', () => {
      const forgedHash = 'deadbeef9900112233445566778899aabbccddeeff00112233445566778899aa';
      document.getElementById('verifyHashInput').value = forgedHash;
      performPublicHashVerification(forgedHash);
    });
  }

  // Chat directives
  const sendChatBtn = document.getElementById('sendChatBtn');
  const chatInput = document.getElementById('chatInputText');
  if (sendChatBtn && chatInput) {
    sendChatBtn.addEventListener('click', () => sendDirectiveMessage(chatInput.value));
    chatInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendDirectiveMessage(chatInput.value);
    });
  }

  // Prompt chips
  document.querySelectorAll('.prompt-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const prompt = chip.getAttribute('data-prompt');
      sendDirectiveMessage(prompt);
    });
  });

  // Clear Annotations
  const clearBtn = document.getElementById('clearAnnotationsBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      annotations = [];
    });
  }

  // Large Field Buttons
  const btnPan = document.getElementById('btnCapturePanoramic');
  if (btnPan) {
    btnPan.addEventListener('click', () => {
      alert('🎥 BNSS 176(3) 360-Degree Continuous Video Captured & SHA-256 Hashed: 7a82b99c011e4f...\nStored in Secure Local Vault.');
    });
  }

  const btnVoice = document.getElementById('btnConnectSupervisor');
  if (btnVoice) {
    btnVoice.addEventListener('click', () => {
      sendDirectiveMessage('Officer requested live audio briefing with FSL Supervisor.');
    });
  }
}

async function performPublicHashVerification(query) {
  if (!query || !query.trim()) return;
  const resultBox = document.getElementById('verifyResultBox');
  resultBox.style.display = 'block';
  resultBox.innerHTML = '<div style="color:var(--text-muted);">Querying cryptographic ledger...</div>';

  try {
    const isCode = query.startsWith('EX-');
    const payload = isCode ? { exhibitCode: query.trim() } : { hash: query.trim() };

    const res = await fetch('/api/verify/hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (data.verified) {
      resultBox.innerHTML = `
        <div style="color:var(--accent-green); font-weight:700; font-size:1.05rem; margin-bottom:0.5rem;">
          ✓ VERIFICATION PASSED · 100% AUTHENTIC RECORD
        </div>
        <p style="font-size:0.85rem; margin-bottom:0.75rem;">
          This exhibit's cryptographic SHA-256 fingerprint exactly matches the original locus delicti capture block. The chain of custody is completely unbroken and admissible under Section 63 of Bharatiya Sakshya Adhiniyam, 2023.
        </p>
        <div style="background:var(--bg-card); padding:0.75rem; border-radius:var(--radius-sm); font-size:0.8rem; line-height:1.6;">
          <strong>Case:</strong> ${data.matchedExhibit.firNumber} (${data.matchedExhibit.policeStation}, ${data.matchedExhibit.district})<br>
          <strong>Exhibit:</strong> ${data.matchedExhibit.code} (${data.matchedExhibit.category})<br>
          <strong>Physical Seal:</strong> ${data.matchedExhibit.physicalSeal}<br>
          <strong>Current Custody:</strong> ${data.matchedExhibit.currentCustodyHolder}<br>
          <strong>Ledger Status:</strong> ${data.chainOfCustody.integrityCheck} (${data.chainOfCustody.totalSteps} custodial steps)
        </div>
      `;
    } else {
      resultBox.innerHTML = `
        <div style="color:var(--accent-red); font-weight:700; font-size:1.05rem; margin-bottom:0.5rem;">
          ⚠️ CRITICAL INTEGRITY ALERT · RECORD NOT AUTHENTICATED
        </div>
        <p style="font-size:0.85rem; margin-bottom:0.75rem;">
          ${data.reason || 'Cryptographic signature mismatch. The file or hash does not exist in the official Pramaan state ledger, or has been altered post-capture.'}
        </p>
        <div style="background:var(--bg-card); padding:0.75rem; border-radius:var(--radius-sm); font-size:0.8rem; font-family:var(--font-mono); color:var(--accent-red);">
          QUERY HASH: ${data.computedHash || query}<br>
          LEGAL STATUS: INADMISSIBLE · REJECTED UNDER BSA 2023 SEC 63
        </div>
      `;
    }
  } catch (err) {
    resultBox.innerHTML = `<div style="color:var(--accent-red);">Verification service unavailable: ${err.message}</div>`;
  }
}

// Supervision Chat & Instructions
async function loadSupervisionChat() {
  try {
    const res = await fetch(`/api/cases/${currentCaseId}/supervision`);
    if (!res.ok) return;
    const { messages } = await res.json();
    const chatContainer = document.getElementById('chatMessages');
    if (chatContainer) {
      chatContainer.innerHTML = '';
      messages.forEach(appendChatMessage);
    }
  } catch (err) {
    console.error('Error loading chat:', err);
  }
}

function appendChatMessage(msg) {
  const container = document.getElementById('chatMessages');
  if (!container) return;

  const isExpert = msg.senderRole === 'forensic_expert' || msg.sender_role === 'forensic_expert';
  const roleClass = isExpert ? 'expert' : 'officer';
  const senderName = msg.senderName || msg.sender_name || (isExpert ? 'Dr. Aditi Varma (FSL)' : 'SI Rajesh Sharma');

  const div = document.createElement('div');
  div.className = `chat-bubble ${roleClass}`;
  div.innerHTML = `
    <div class="chat-bubble-header">
      <strong>${senderName}</strong>
      <span>${new Date(msg.createdAt || msg.created_at || Date.now()).toLocaleTimeString()}</span>
    </div>
    <div>${msg.content}</div>
  `;

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

async function sendDirectiveMessage(content) {
  if (!content || !content.trim()) return;
  const chatInput = document.getElementById('chatInputText');
  if (chatInput) chatInput.value = '';

  try {
    await fetch(`/api/cases/${currentCaseId}/supervision/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messageType: 'instruction',
        content: content.trim()
      })
    });
  } catch (err) {
    console.error('Error sending message:', err);
  }
}

// Interactive Canvas Simulation (Field Officer Camera & FSL Supervisor Console)
function setupCanvasSimulation() {
  const officerCanvas = document.getElementById('cameraCanvas');
  const supervisorCanvas = document.getElementById('supervisorCanvas');

  function renderSimulation(timestamp) {
    if (officerCanvas) drawScene(officerCanvas, false, timestamp);
    if (supervisorCanvas) drawScene(supervisorCanvas, true, timestamp);
    requestAnimationFrame(renderSimulation);
  }
  requestAnimationFrame(renderSimulation);

  // Click on Supervisor Canvas to add virtual annotation marker
  if (supervisorCanvas) {
    supervisorCanvas.addEventListener('click', (e) => {
      const rect = supervisorCanvas.getBoundingClientRect();
      const scaleX = supervisorCanvas.width / rect.width;
      const scaleY = supervisorCanvas.height / rect.height;
      const x = Math.round((e.clientX - rect.left) * scaleX);
      const y = Math.round((e.clientY - rect.top) * scaleY);

      const label = prompt('Marker Directive Label (e.g. "Examine blood droplets", "Preserve casing"):', 'Key Evidence Point');
      if (label) {
        annotations.push({ x, y, label });
        fetch(`/api/cases/${currentCaseId}/supervision/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            messageType: 'marker_annotation',
            content: `Supervisor pinned marker "${label}" at (${x}, ${y})`,
            payload: { x, y, label }
          })
        });
      }
    });
  }
}

function drawScene(canvas, isSupervisor, time) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  // Background room perspective (Bank street scene)
  ctx.fillStyle = '#111827';
  ctx.fillRect(0, 0, w, h);

  // Perspective floor
  ctx.fillStyle = '#1f2937';
  ctx.beginPath();
  ctx.moveTo(0, h * 0.45);
  ctx.lineTo(w, h * 0.45);
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.fill();

  // Grid floor lines
  ctx.strokeStyle = '#374151';
  ctx.lineWidth = 1;
  for (let x = 0; x <= w; x += 40) {
    ctx.beginPath();
    ctx.moveTo(x, h * 0.45);
    ctx.lineTo(x * 1.5 - w * 0.25, h);
    ctx.stroke();
  }

  // Draw simulated police flashing beacon light reflection
  const flash = Math.sin(time / 200) > 0;
  ctx.fillStyle = flash ? 'rgba(239, 68, 68, 0.08)' : 'rgba(59, 130, 246, 0.08)';
  ctx.fillRect(0, 0, w, h);

  // Draw Evidence Placards on Floor
  // Placard 1 (Blood stain)
  ctx.fillStyle = '#f59e0b';
  ctx.fillRect(180, 220, 26, 26);
  ctx.fillStyle = '#000000';
  ctx.font = 'bold 14px sans-serif';
  ctx.fillText('01', 184, 238);

  // Blood Stain Spot
  ctx.fillStyle = '#7f1d1d';
  ctx.beginPath();
  ctx.ellipse(225, 235, 18, 9, 0, 0, Math.PI * 2);
  ctx.fill();

  // Placard 2 (Casing)
  ctx.fillStyle = '#f59e0b';
  ctx.fillRect(380, 260, 26, 26);
  ctx.fillStyle = '#000000';
  ctx.fillText('02', 384, 278);

  // Cartridge brass dot
  ctx.fillStyle = '#eab308';
  ctx.fillRect(415, 272, 8, 4);

  // Draw Center Crosshair HUD
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.25)';
  ctx.beginPath();
  ctx.arc(w / 2, h / 2, 35, 0, Math.PI * 2);
  ctx.moveTo(w / 2 - 45, h / 2);
  ctx.lineTo(w / 2 + 45, h / 2);
  ctx.moveTo(w / 2, h / 2 - 45);
  ctx.lineTo(w / 2, h / 2 + 45);
  ctx.stroke();

  // Render Live Annotations / Pins dropped by FSL Expert
  for (const ann of annotations) {
    ctx.save();
    // Glowing Pin Circle
    ctx.strokeStyle = '#06b6d4';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(ann.x, ann.y, 14 + Math.sin(time / 150) * 3, 0, Math.PI * 2);
    ctx.stroke();

    // Pin Target Dot
    ctx.fillStyle = '#06b6d4';
    ctx.beginPath();
    ctx.arc(ann.x, ann.y, 4, 0, Math.PI * 2);
    ctx.fill();

    // Directive Callout Tag
    ctx.fillStyle = 'rgba(6, 182, 212, 0.9)';
    ctx.font = 'bold 11px sans-serif';
    const textWidth = ctx.measureText(ann.label).width;
    ctx.fillRect(ann.x - textWidth / 2 - 6, ann.y - 32, textWidth + 12, 18);
    ctx.fillStyle = '#000000';
    ctx.fillText(ann.label, ann.x - textWidth / 2, ann.y - 19);
    ctx.restore();
  }
}

// Modals Handling
function setupModals() {
  const closeBtns = document.querySelectorAll('.closeModalBtn');
  closeBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
    });
  });

  // Open New Case Modal
  const openCaseBtn = document.getElementById('openNewCaseModalBtn');
  if (openCaseBtn) {
    openCaseBtn.addEventListener('click', () => {
      document.getElementById('newCaseModal').classList.add('active');
    });
  }

  // Handle New Case Submit
  const newCaseForm = document.getElementById('newCaseForm');
  if (newCaseForm) {
    newCaseForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const firNumber = document.getElementById('newFirNumber').value;
      const policeStation = document.getElementById('newPoliceStation').value;
      const offenceType = document.getElementById('newOffenceType').value;
      const penalSections = document.getElementById('newPenalSections').value;
      const sceneLocation = document.getElementById('newSceneLocation').value;
      const priority = document.getElementById('newCasePriority').value;

      try {
        const res = await fetch('/api/cases', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ firNumber, policeStation, offenceType, penalSections, sceneLocation, priority })
        });

        if (res.ok) {
          const data = await res.json();
          document.getElementById('newCaseModal').classList.remove('active');
          newCaseForm.reset();
          await loadCases();
          selectCase(data.caseId);
        }
      } catch (err) {
        console.error('Error creating case:', err);
      }
    });
  }

  // Open Tag Exhibit Modal
  const openExBtn = document.getElementById('btnNewExhibitCapture');
  if (openExBtn) {
    openExBtn.addEventListener('click', () => {
      document.getElementById('newExhibitModal').classList.add('active');
    });
  }

  // Handle New Exhibit Submit
  const newExForm = document.getElementById('newExhibitForm');
  if (newExForm) {
    newExForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const exhibitCode = document.getElementById('exCode').value;
      const category = document.getElementById('exCategory').value;
      const description = document.getElementById('exDescription').value;
      const foundLocation = document.getElementById('exFoundLocation').value;
      const packagingMethod = document.getElementById('exPackaging').value;
      const physicalSealNumber = document.getElementById('exSealNumber').value;
      const fslAssignedDivision = document.getElementById('exFslDivision').value;

      try {
        const res = await fetch(`/api/cases/${currentCaseId}/exhibits`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            exhibitCode,
            category,
            description,
            foundLocation,
            packagingMethod,
            physicalSealNumber,
            fslAssignedDivision
          })
        });

        if (res.ok) {
          document.getElementById('newExhibitModal').classList.remove('active');
          newExForm.reset();
          loadCaseDetail(currentCaseId);
        }
      } catch (err) {
        console.error('Error creating exhibit:', err);
      }
    });
  }

  // Open Custody Transfer Modal
  const openTrBtn = document.getElementById('openTransferModalBtn');
  if (openTrBtn) {
    openTrBtn.addEventListener('click', () => {
      document.getElementById('transferModal').classList.add('active');
    });
  }

  // Handle Transfer Submit
  const trForm = document.getElementById('transferForm');
  if (trForm) {
    trForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const exhibitId = document.getElementById('custodyExhibitSelect').value;
      const eventType = document.getElementById('trEventType').value;
      const toPersonName = document.getElementById('trToPerson').value;
      const toDesignation = document.getElementById('trToDesignation').value;
      const location = document.getElementById('trLocation').value;
      const purpose = document.getElementById('trPurpose').value;
      const sealCondition = document.getElementById('trSealCondition').value;
      const remarks = document.getElementById('trRemarks').value;

      try {
        const res = await fetch(`/api/exhibits/${exhibitId}/transfer`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            eventType,
            toPersonName,
            toDesignation,
            location,
            purpose,
            sealCondition,
            remarks
          })
        });

        if (res.ok) {
          document.getElementById('transferModal').classList.remove('active');
          trForm.reset();
          loadExhibitCustodyLedger(exhibitId);
        }
      } catch (err) {
        console.error('Error recording custody transfer:', err);
      }
    });
  }
}

// Helpers
function formatStatus(status) {
  const map = {
    scene_active: 'Active Crime Scene',
    capture_completed: 'Capture Completed',
    under_remote_review: 'Under Remote Review',
    in_malkhana: 'In Police Malkhana',
    transit_to_fsl: 'In Transit to FSL',
    fsl_received: 'Received at FSL Intake',
    testing_in_progress: 'Testing In Progress',
    report_submitted: 'Report Submitted',
    court_ready: 'Court-Ready (BSA 63)'
  };
  return map[status] || status;
}

function getStatusColor(status) {
  if (status === 'scene_active') return 'rgba(239, 68, 68, 0.8)';
  if (status === 'court_ready') return 'rgba(16, 185, 129, 0.8)';
  return 'rgba(59, 130, 246, 0.8)';
}

function formatEventType(type) {
  const map = {
    initial_scene_collection: '1. Initial Scene Collection & Cordon Packaging',
    malkhana_deposit: '2. Police Station Malkhana Safe Deposit',
    dispatch_to_fsl: '3. Courier Road Certificate Dispatch',
    fsl_reception: '4. Forensic Science Laboratory Intake',
    division_handover: '5. Handover to Testing Division Scientist',
    analysis_started: '6. Laboratory Testing Commenced',
    analysis_completed: '7. Scientific Analysis Completed',
    court_deposition: '8. Produced in Court of Law'
  };
  return map[type] || type;
}

function formatSeal(cond) {
  if (cond === 'intact_and_verified') return '🔒 Physical Seal Intact & Verified';
  if (cond === 'inspected_under_supervision') return '🔍 Inspected by FSL Scientist';
  if (cond === 'broken_for_subsampling_under_fsl_sop') return '✂️ Broken for Sub-sampling (DFSS SOP)';
  return cond;
}
