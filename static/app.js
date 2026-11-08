/**
 * ThreatGuard AI - Web Security & Digital Trust Intelligence Frontend Logic
 * Version 2.2 - Enterprise Cybersecurity Command Center
 */

let currentScanData = null;

document.addEventListener("DOMContentLoaded", () => {
  initScannerForm();
  initPresetButtons();
  initTabs();
  initCardTabJumps();
  initModal();
  initStixModal();
  initExport();

  // Check if bookmarklet or external query invoked with ?url=...
  const urlParams = new URLSearchParams(window.location.search);
  const autoUrl = urlParams.get("url");
  if (autoUrl) {
    document.getElementById("url-input").value = autoUrl;
    runThreatAnalysis(autoUrl);
  }

  // Configure Bookmarklet link and direct click behavior
  initBookmarklet();

  // Load database engine status & threat feed
  loadDbStatus();
  loadGlobalThreatFeed();
});

/**
 * Configure Bookmarklet with dynamic origin
 */
function initBookmarklet() {
  const bookmarkletLink = document.getElementById("bookmarklet-scan-btn");
  if (!bookmarkletLink) return;

  const origin = window.location.origin;
  // Bookmarklet code for drag-and-drop to bookmarks bar:
  bookmarkletLink.setAttribute(
    "href",
    `javascript:(function(){var u=encodeURIComponent(window.location.href);window.open('${origin}/?url='+u,'_blank');})();`
  );

  // Direct click handler: audits current input or defaults to Chase Bank
  bookmarkletLink.addEventListener("click", (e) => {
    e.preventDefault();
    const input = document.getElementById("url-input");
    let url = input.value.trim();
    if (!url) {
      url = "https://chase.com";
      input.value = url;
    }
    runThreatAnalysis(url);
  });
}

/**
 * Check backend database status (SQLite vs Supabase)
 */
async function loadDbStatus() {
  const badge = document.getElementById("db-status-badge");
  if (!badge) return;
  try {
    const resp = await fetch("/api/system/db-status");
    const data = await resp.json();
    if (data.is_cloud_active) {
      badge.textContent = "☁️ Supabase (Postgres Cloud)";
      badge.style.borderColor = "var(--neon-emerald)";
      badge.style.color = "var(--neon-emerald)";
      badge.title = "Supabase PostgreSQL connected with Row Level Security (RLS)";
    } else {
      badge.textContent = "🗄️ SQLite (Air-Gapped)";
      badge.style.borderColor = "rgba(0, 242, 254, 0.4)";
      badge.style.color = "var(--neon-cyan)";
      badge.title = "High-speed zero-latency local SQLite engine";
    }
  } catch (e) {
    badge.textContent = "🗄️ SQLite (Local)";
  }
}

/**
 * Initialize search form and submission
 */
function initScannerForm() {
  const form = document.getElementById("analyze-form");
  const input = document.getElementById("url-input");
  const analyzeBtn = document.getElementById("analyze-btn");

  const submitHandler = (e) => {
    if (e) e.preventDefault();
    let url = input.value.trim();
    if (!url) {
      url = "https://chase.com";
      input.value = url;
    }
    runThreatAnalysis(url);
  };

  if (form) form.addEventListener("submit", submitHandler);
  if (analyzeBtn) analyzeBtn.addEventListener("click", submitHandler);

  // Trigger scan when user presses Enter inside input
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitHandler();
      }
    });
  }
}

/**
 * Initialize preset test scenarios
 */
function initPresetButtons() {
  // Support both preset-chip and preset-pill selectors
  const chips = document.querySelectorAll(".preset-chip, .preset-pill");
  const input = document.getElementById("url-input");

  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const targetUrl = chip.getAttribute("data-url");
      if (targetUrl) {
        input.value = targetUrl;
        runThreatAnalysis(targetUrl);
      }
    });
  });
}

/**
 * Interactive inspection tab switcher
 */
function initTabs() {
  const tabBtns = document.querySelectorAll(".nav-tab-btn, .tab-btn");
  const panes = document.querySelectorAll(".inspection-pane, .tab-pane");

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      panes.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add("active");
      }
    });
  });
}

/**
 * Click on any of the 4 main vector cards to jump directly to its tab
 */
function initCardTabJumps() {
  const cardTabMap = {
    "tile-phish": "tab-threat",
    "tile-crypto": "tab-certs",
    "tile-posture": "tab-web",
    "tile-intel": "tab-intel"
  };

  for (const [tileId, tabId] of Object.entries(cardTabMap)) {
    const tile = document.getElementById(tileId);
    if (tile) {
      tile.addEventListener("click", () => {
        switchToTab(tabId);
      });
    }
  }
}

function switchToTab(tabId) {
  const tabBtns = document.querySelectorAll(".nav-tab-btn, .tab-btn");
  const panes = document.querySelectorAll(".inspection-pane, .tab-pane");

  tabBtns.forEach((b) => {
    if (b.getAttribute("data-tab") === tabId) {
      b.classList.add("active");
    } else {
      b.classList.remove("active");
    }
  });

  panes.forEach((p) => {
    if (p.id === tabId) {
      p.classList.add("active");
      p.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } else {
      p.classList.remove("active");
    }
  });
}

/**
 * Report Threat Modal Setup
 */
function initModal() {
  const modal = document.getElementById("report-modal");
  const openBtn = document.getElementById("report-modal-btn");
  const tabFlagBtn = document.getElementById("tab-flag-threat-btn");
  const closeBtn = document.getElementById("modal-close-btn");
  const cancelBtn = document.getElementById("modal-cancel-btn");
  const form = document.getElementById("threat-report-form");
  const modalUrl = document.getElementById("modal-url");

  const openModal = () => {
    if (currentScanData) {
      modalUrl.value = currentScanData.target_url;
      const brand = currentScanData.threat_analysis.impersonated_brand;
      if (brand) {
        const brandInput = document.getElementById("modal-brand");
        if (brandInput) brandInput.value = brand;
      }
    }
    if (modal) modal.style.display = "flex";
  };

  const closeModal = () => {
    if (modal) modal.style.display = "none";
  };

  if (openBtn) openBtn.addEventListener("click", openModal);
  if (tabFlagBtn) tabFlagBtn.addEventListener("click", openModal);
  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeModal);

  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal();
    });
  }

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        target_url: document.getElementById("modal-url").value,
        category: document.getElementById("modal-category").value,
        impersonated_brand: document.getElementById("modal-brand").value || null,
        description: document.getElementById("modal-desc").value
      };

      try {
        const resp = await fetch("/api/intel/report", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (data.success) {
          alert("✓ Threat report successfully registered in global intelligence feed.");
          closeModal();
          form.reset();
          if (currentScanData && currentScanData.target_url === payload.target_url) {
            runThreatAnalysis(payload.target_url);
          }
          loadGlobalThreatFeed();
        }
      } catch (err) {
        alert("Submission error: " + err.message);
      }
    });
  }
}

/**
 * OASIS STIX 2.1 Inspector Modal
 */
function initStixModal() {
  const stixModal = document.getElementById("stix-modal");
  const viewStixBtn = document.getElementById("view-stix-btn");
  const feedStixBtn = document.getElementById("feed-stix-btn");
  const closeBtn = document.getElementById("stix-modal-close");
  const copyBtn = document.getElementById("stix-copy-btn");
  const codeViewer = document.getElementById("stix-json-content");

  const openStixModal = async () => {
    if (stixModal) stixModal.style.display = "flex";
    if (codeViewer) codeViewer.textContent = "Loading STIX 2.1 Threat Intel Bundle...";

    try {
      const resp = await fetch("/api/threats/stix");
      const json = await resp.json();
      if (codeViewer) {
        codeViewer.textContent = JSON.stringify(json, null, 2);
      }
    } catch (e) {
      if (codeViewer) {
        codeViewer.textContent = "// Error loading STIX 2.1: " + e.message;
      }
    }
  };

  const closeStixModal = () => {
    if (stixModal) stixModal.style.display = "none";
  };

  if (viewStixBtn) viewStixBtn.addEventListener("click", openStixModal);
  if (feedStixBtn) feedStixBtn.addEventListener("click", openStixModal);
  if (closeBtn) closeBtn.addEventListener("click", closeStixModal);

  if (stixModal) {
    stixModal.addEventListener("click", (e) => {
      if (e.target === stixModal) closeStixModal();
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      if (codeViewer) {
        navigator.clipboard.writeText(codeViewer.textContent).then(() => {
          copyBtn.textContent = "✓ Copied!";
          setTimeout(() => {
            copyBtn.textContent = "📋 Copy JSON";
          }, 2000);
        });
      }
    });
  }
}

/**
 * Export handlers (JSON & PDF)
 */
function initExport() {
  const exportBtn = document.getElementById("export-json-btn");
  const exportPdfBtn = document.getElementById("export-pdf-btn");

  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      if (!currentScanData) return;
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanData, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `threat_audit_${currentScanData.domain}_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    });
  }

  if (exportPdfBtn) {
    exportPdfBtn.addEventListener("click", () => {
      if (!currentScanData) return;
      const printTs = document.getElementById("print-timestamp");
      if (printTs) {
        printTs.textContent = `Generated: ${new Date().toLocaleString()} (Scan ID: ${currentScanData.scan_id.substring(0, 8)})`;
      }
      window.print();
    });
  }
}

/**
 * Core threat analysis caller invoking GET /analyze?url=...
 */
async function runThreatAnalysis(url) {
  const loading = document.getElementById("loading-state");
  const results = document.getElementById("results-container");
  const analyzeBtn = document.getElementById("analyze-btn");
  const loadingStep = document.getElementById("loading-step");

  if (loading) loading.style.display = "block";
  if (results) results.style.display = "none";
  if (analyzeBtn) analyzeBtn.disabled = true;

  if (loadingStep) {
    loadingStep.textContent = "Validating X.509 cryptography, checking eMudhra key integrity, and parsing DOM forms...";
  }

  try {
    const encodedUrl = encodeURIComponent(url);
    const response = await fetch(`/analyze?url=${encodedUrl}`);

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Scan request failed");
    }

    const data = await response.json();
    currentScanData = data;
    renderResults(data);
  } catch (err) {
    alert("Analysis Failed: " + err.message);
  } finally {
    if (loading) loading.style.display = "none";
    if (analyzeBtn) analyzeBtn.disabled = false;
  }
}

/**
 * Visual-First Rendering Logic
 */
function renderResults(data) {
  const results = document.getElementById("results-container");
  results.style.display = "block";

  const verdict = data.verdict;
  const threat = data.threat_analysis;
  const certs = data.certificate_analysis;
  const web = data.web_security;
  const intel = data.threat_intelligence;
  const recs = data.recommendations;

  // 1. Domain & Risk Level Badge
  document.getElementById("verdict-domain").textContent = data.domain;
  const badge = document.getElementById("risk-level-badge");
  badge.textContent = verdict.risk_level;
  badge.className = `risk-badge badge-${verdict.risk_level.toLowerCase()}`;

  // Glow Indicator on Target
  const glowIndicator = document.getElementById("target-glow-indicator");
  const threatAmbientGlow = document.getElementById("threat-ambient-glow");
  if (verdict.risk_level === "CRITICAL" || verdict.risk_level === "HIGH") {
    if (glowIndicator) {
      glowIndicator.style.background = "var(--neon-crimson)";
      glowIndicator.style.boxShadow = "0 0 14px var(--neon-crimson)";
    }
    if (threatAmbientGlow) threatAmbientGlow.style.display = "block";
  } else if (verdict.risk_level === "MODERATE") {
    if (glowIndicator) {
      glowIndicator.style.background = "var(--neon-amber)";
      glowIndicator.style.boxShadow = "0 0 14px var(--neon-amber)";
    }
    if (threatAmbientGlow) threatAmbientGlow.style.display = "none";
  } else {
    if (glowIndicator) {
      glowIndicator.style.background = "var(--neon-emerald)";
      glowIndicator.style.boxShadow = "0 0 14px var(--neon-emerald)";
    }
    if (threatAmbientGlow) threatAmbientGlow.style.display = "none";
  }

  // 2. Trust Score Dial
  const trustScore = verdict.trust_score;
  const riskScore = verdict.risk_score;
  document.getElementById("trust-score-val").textContent = trustScore;
  document.getElementById("risk-score-val").textContent = `Risk Exposure: ${riskScore}/100`;

  const circle = document.getElementById("gauge-circle");
  const circumference = 314.159;
  const offset = circumference - (trustScore / 100) * circumference;
  circle.style.strokeDashoffset = offset;

  if (verdict.risk_level === "CRITICAL") {
    circle.style.stroke = "var(--neon-crimson)";
  } else if (verdict.risk_level === "HIGH") {
    circle.style.stroke = "#f97316";
  } else if (verdict.risk_level === "MODERATE") {
    circle.style.stroke = "var(--neon-amber)";
  } else if (verdict.risk_level === "LOW") {
    circle.style.stroke = "var(--neon-blue)";
  } else {
    circle.style.stroke = "var(--neon-emerald)";
  }

  // 3. 4 Visual Vector Status Tiles
  // Tile 1: Phishing
  const phishStatus = threat.impersonated_brand
    ? `Spoofing ${threat.impersonated_brand}`
    : threat.is_phishing
    ? "Malicious Phish"
    : "Clean Domain";
  document.getElementById("tile-phish-status").textContent = phishStatus;
  setTileColor("tile-phish-indicator", threat.is_phishing ? "red" : "green");

  // Tile 2: Cryptography
  const keyTypeShort = certs.cryptography.key_type.split(" ")[0] || "RSA";
  const keyStatus = `${certs.cryptography.key_size_bits}b ${keyTypeShort}`;
  document.getElementById("tile-crypto-status").textContent = keyStatus;
  const isWeakKey = certs.cryptography.key_size_bits < 2048 || certs.trust_chain.is_self_signed;
  setTileColor("tile-crypto-indicator", isWeakKey ? "red" : "green");

  // Tile 3: Web Posture
  document.getElementById("tile-posture-status").textContent = `Grade ${web.security_grade}`;
  const isBadWeb = web.security_grade === "F" || web.security_grade === "D";
  setTileColor(
    "tile-posture-indicator",
    isBadWeb ? "red" : web.security_grade === "A" || web.security_grade === "A+" ? "green" : "amber"
  );

  // Tile 4: Intel
  const repText =
    intel.community_reports_count > 0
      ? `${intel.community_reports_count} Incidents`
      : intel.matched_iocs_count > 0
      ? "IOC Matches"
      : "0 Flags";
  document.getElementById("tile-intel-status").textContent = repText;
  setTileColor(
    "tile-intel-indicator",
    intel.community_reports_count > 0 || intel.matched_iocs_count > 0 ? "red" : "green"
  );

  // 4. Executive AI Verdict & Formatted Findings Cards
  document.getElementById("verdict-summary").textContent = verdict.summary;

  const tagsContainer = document.getElementById("verdict-threat-tags");
  tagsContainer.innerHTML = "";

  const factors = verdict.threat_factors || [];
  if (factors.length === 0) {
    tagsContainer.innerHTML = `
      <div class="finding-card">
        <span class="finding-sev-pill finding-sev-info">CLEAN</span>
        <div class="finding-content">
          <div class="finding-vector-tag">ALL SECURITY CHECKS PASSED</div>
          <div class="finding-message">No active phishing vectors, cryptographic weaknesses, or threat feed IOCs detected.</div>
        </div>
      </div>
    `;
  } else {
    factors.forEach((factor) => {
      const card = document.createElement("div");
      const isCrit = factor.severity === "CRITICAL";
      const isWarn = factor.severity === "HIGH" || factor.severity === "MODERATE";

      card.className = `finding-card ${isCrit ? "finding-critical" : isWarn ? "finding-warning" : ""}`;

      let sevClass = "finding-sev-info";
      if (isCrit) sevClass = "finding-sev-critical";
      else if (isWarn) sevClass = "finding-sev-warning";

      card.innerHTML = `
        <span class="finding-sev-pill ${sevClass}">${factor.severity}</span>
        <div class="finding-content">
          <div class="finding-vector-tag">${factor.vector.toUpperCase()}</div>
          <div class="finding-message">${factor.message}</div>
        </div>
      `;
      tagsContainer.appendChild(card);
    });
  }

  // 5. 4-Pillar Visual Meters
  updatePillar(
    "pillar-threat-bar",
    "pillar-threat-status",
    verdict.breakdown.threat_heuristics.score,
    `${verdict.breakdown.threat_heuristics.score}%`
  );
  updatePillar(
    "pillar-cert-bar",
    "pillar-cert-status",
    verdict.breakdown.digital_trust_certs.score,
    `${verdict.breakdown.digital_trust_certs.score}%`
  );
  updatePillar(
    "pillar-web-bar",
    "pillar-web-status",
    verdict.breakdown.web_security_posture.score,
    `${verdict.breakdown.web_security_posture.score}%`
  );
  updatePillar(
    "pillar-intel-bar",
    "pillar-intel-status",
    verdict.breakdown.collaborative_intelligence.score,
    `${verdict.breakdown.collaborative_intelligence.score}%`
  );

  // 6. eMudhra Incident Alert Banner
  const emudhraBanner = document.getElementById("emudhra-banner");
  const emudhraAdv = certs.emudhra_incident_analysis;
  if (emudhraAdv && emudhraAdv.advisory_status !== "NORMAL") {
    emudhraBanner.style.display = "block";
  } else {
    emudhraBanner.style.display = "none";
  }

  // 7. Tab 1: Phishing Stat Tiles
  document.getElementById("threat-brand").textContent = threat.impersonated_brand || "None";
  document.getElementById("threat-technique").textContent = threat.spoofing_technique || "Standard";
  document.getElementById("threat-punycode").textContent = threat.is_punycode ? "Flagged (IDN / Punycode)" : "Clean";
  document.getElementById("threat-credential").textContent = threat.credential_harvesting_detected
    ? "Credentials / Form Detected"
    : "None";
  document.getElementById("threat-entropy").textContent = `${threat.entropy} bits`;
  document.getElementById("threat-subdomains").textContent = `${threat.lexical_analysis.subdomain_count} Levels`;

  // Rule badges
  const indBody = document.getElementById("threat-indicators-body");
  indBody.innerHTML = "";
  if (threat.all_indicators && threat.all_indicators.length > 0) {
    threat.all_indicators.forEach((ind) => {
      const row = document.createElement("div");
      row.className = "rule-chip-row";
      row.innerHTML = `
        <span class="sev-badge sev-${ind.severity.toLowerCase()}">${ind.severity}</span>
        <span class="rule-code">${ind.type}</span>
        <span class="rule-msg">${ind.message}</span>
      `;
      indBody.appendChild(row);
    });
  } else {
    indBody.innerHTML = `<div style="color: var(--text-muted); font-size: 0.82rem; padding: 6px;">No suspicious heuristics or rules triggered.</div>`;
  }

  // 8. Tab 2: Certificate & Chain
  document.getElementById("cert-key-algo").textContent = certs.cryptography.key_type;
  document.getElementById("cert-key-size").textContent = `${certs.cryptography.key_size_bits} bits`;
  document.getElementById("cert-key-size").style.color =
    certs.cryptography.key_size_bits < 2048 ? "var(--neon-crimson)" : "var(--neon-emerald)";
  document.getElementById("cert-sig-algo").textContent = certs.cryptography.signature_algorithm;
  document.getElementById("cert-ct-status").textContent = certs.trust_chain.has_certificate_transparency_sct
    ? "Verified SCT"
    : "Missing SCT";
  document.getElementById("cert-ct-status").style.color = certs.trust_chain.has_certificate_transparency_sct
    ? "var(--neon-emerald)"
    : "var(--neon-amber)";
  document.getElementById("cert-issuer-org").textContent =
    certs.issuer.organization || certs.issuer.common_name || "Self-Signed";
  document.getElementById("cert-days-left").textContent = `${certs.validity.days_until_expiration} days`;

  // Certificate Trust Chain Flow
  const rootNode = document.getElementById("cert-chain-root");
  const interNode = document.getElementById("cert-chain-intermediate");
  const leafNode = document.getElementById("cert-chain-leaf");

  if (rootNode) {
    rootNode.textContent = certs.trust_chain.is_self_signed
      ? "Self-Signed (Untrusted Root)"
      : certs.issuer.organization || "Public CA Root";
  }
  if (interNode) {
    interNode.textContent = certs.issuer.common_name || certs.issuer.organization || "Direct Root CA";
  }
  if (leafNode) {
    leafNode.textContent = data.domain;
  }

  const sansList = document.getElementById("cert-sans-list");
  sansList.innerHTML = "";
  const sans = certs.trust_chain.subject_alternative_names || [];
  if (sans.length > 0) {
    sans.forEach((san) => {
      const pill = document.createElement("span");
      pill.className = "san-pill";
      pill.textContent = san;
      sansList.appendChild(pill);
    });
  } else {
    sansList.innerHTML = `<span style="color:var(--text-muted); font-size:0.78rem;">No Subject Alternative Names defined.</span>`;
  }

  // 9. Tab 3: Security Headers
  const gradeBox = document.getElementById("web-grade-box");
  gradeBox.textContent = web.security_grade;
  const isGradeGreen = web.security_grade === "A" || web.security_grade === "A+";
  const isGradeRed = web.security_grade === "F" || web.security_grade === "D";
  gradeBox.style.color = isGradeGreen ? "var(--neon-emerald)" : isGradeRed ? "var(--neon-crimson)" : "var(--neon-amber)";
  gradeBox.style.borderColor = gradeBox.style.color;
  gradeBox.style.boxShadow = `0 0 20px ${gradeBox.style.color}40`;

  document.getElementById("web-https-status").textContent = web.is_https ? "HTTPS: Active" : "HTTPS: Missing";
  document.getElementById("web-https-status").style.color = web.is_https ? "var(--neon-emerald)" : "var(--neon-crimson)";
  document.getElementById("web-mixed-content").textContent = `Mixed Content: ${web.mixed_content.count}`;
  document.getElementById("web-server-leaks").textContent = `Server Leaks: ${web.information_leaks.length}`;

  const headersGrid = document.getElementById("security-headers-grid");
  headersGrid.innerHTML = "";
  for (const [hdr, details] of Object.entries(web.security_headers)) {
    const card = document.createElement("div");
    card.className = "header-tile";
    const statusClass = details.status === "PASS" ? "status-pass" : details.status === "WARN" ? "status-warn" : "status-fail";
    card.innerHTML = `
      <span class="hdr-title">${hdr}</span>
      <span class="hdr-status-badge ${statusClass}">${details.status}</span>
    `;
    headersGrid.appendChild(card);
  }

  // 10. Tab 4: Crowd Intel
  document.getElementById("intel-reputation-score").textContent = `${intel.reputation_score}/100`;
  document.getElementById("intel-reports-count").textContent = intel.community_reports_count;
  const net = intel.community_consensus.net_score;
  document.getElementById("intel-net-votes").textContent = net >= 0 ? `+${net}` : `${net}`;

  const repStream = document.getElementById("community-reports-stream");
  repStream.innerHTML = "";
  if (intel.reports && intel.reports.length > 0) {
    intel.reports.forEach((r) => {
      const item = document.createElement("div");
      item.className = "report-tile-compact";
      item.innerHTML = `
        <div>
          <div><span class="rep-cat">${r.category}</span> <span style="font-size:0.75rem; color:var(--text-muted);">@${r.reporter_name}</span></div>
          <div class="rep-txt">${r.description}</div>
        </div>
        <div class="vote-controls">
          <button class="vote-btn-sm" onclick="voteReport(${r.id}, 'up')" title="Upvote finding">▲</button>
          <span class="vote-val">${r.upvotes - r.downvotes}</span>
          <button class="vote-btn-sm" onclick="voteReport(${r.id}, 'down')" title="Downvote finding">▼</button>
        </div>
      `;
      repStream.appendChild(item);
    });
  } else {
    repStream.innerHTML = `<div style="color:var(--text-muted); font-size:0.82rem; padding: 4px;">No community incidents registered for this target.</div>`;
  }

  const iocBody = document.getElementById("iocs-body");
  iocBody.innerHTML = "";
  if (intel.iocs && intel.iocs.length > 0) {
    intel.iocs.forEach((ioc) => {
      const div = document.createElement("div");
      div.className = "ioc-chip-row";
      div.innerHTML = `
        <span><code>${ioc.indicator}</code></span>
        <span class="sev-badge sev-critical">${ioc.threat_type}</span>
        <span style="color:var(--text-muted);">${ioc.confidence}% Confidence</span>
      `;
      iocBody.appendChild(div);
    });
  } else {
    iocBody.innerHTML = `<div style="color:var(--text-muted); font-size:0.82rem; padding: 4px;">No matching threat feed IOCs.</div>`;
  }

  // 11. Tab 5: Remediation Playbook
  const userList = document.getElementById("user-guidance-list");
  userList.innerHTML = "";
  recs.user_guidance.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    userList.appendChild(li);
  });

  const adminList = document.getElementById("admin-remediation-list");
  adminList.innerHTML = "";
  recs.admin_remediation.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    adminList.appendChild(li);
  });

  // Smooth scroll to results
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function setTileColor(indicatorId, color) {
  const el = document.getElementById(indicatorId);
  if (!el) return;
  if (color === "red") {
    el.style.background = "var(--neon-crimson)";
    el.style.boxShadow = "0 0 10px var(--neon-crimson)";
  } else if (color === "amber") {
    el.style.background = "var(--neon-amber)";
    el.style.boxShadow = "0 0 10px var(--neon-amber)";
  } else {
    el.style.background = "var(--neon-emerald)";
    el.style.boxShadow = "0 0 10px var(--neon-emerald)";
  }
}

function updatePillar(barId, statusId, score, label) {
  const bar = document.getElementById(barId);
  const status = document.getElementById(statusId);
  if (!bar || !status) return;

  bar.style.width = `${Math.min(100, Math.max(6, score))}%`;
  status.textContent = label;

  if (score >= 70) {
    bar.style.background = "var(--neon-crimson)";
    bar.style.boxShadow = "0 0 8px var(--neon-crimson)";
    status.style.color = "var(--neon-crimson)";
  } else if (score >= 40) {
    bar.style.background = "var(--neon-amber)";
    bar.style.boxShadow = "0 0 8px var(--neon-amber)";
    status.style.color = "var(--neon-amber)";
  } else {
    bar.style.background = "var(--neon-emerald)";
    bar.style.boxShadow = "0 0 8px var(--neon-emerald)";
    status.style.color = "var(--neon-emerald)";
  }
}

/**
 * Global Threat Feed Loader
 */
async function loadGlobalThreatFeed() {
  const container = document.getElementById("global-threat-feed");
  if (!container) return;
  try {
    const resp = await fetch("/api/threats/feed?limit=6");
    const data = await resp.json();
    const feed = data.feed || [];

    container.innerHTML = "";
    feed.forEach((item) => {
      const div = document.createElement("div");
      div.className = "feed-item";
      div.onclick = () => {
        const input = document.getElementById("url-input");
        if (input) input.value = item.indicator;
        runThreatAnalysis(item.indicator);
      };

      const sevClass = (item.severity || "medium").toLowerCase();

      div.innerHTML = `
        <div class="feed-item-top">
          <span class="feed-domain">${item.indicator}</span>
          <span class="sev-badge sev-${sevClass}">${item.severity}</span>
        </div>
        <div class="feed-desc">${item.description}</div>
      `;
      container.appendChild(div);
    });
  } catch (e) {
    container.innerHTML = "<div style='color: var(--text-muted); padding: 10px;'>Threat feed online.</div>";
  }
}

/**
 * Collaborative Upvote / Downvote Handler
 */
window.voteReport = async function (reportId, voteType) {
  try {
    const resp = await fetch("/api/intel/vote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_id: reportId, vote_type: voteType })
    });
    const res = await resp.json();
    if (res.success && currentScanData) {
      runThreatAnalysis(currentScanData.target_url);
    }
  } catch (e) {
    console.error(e);
  }
};
