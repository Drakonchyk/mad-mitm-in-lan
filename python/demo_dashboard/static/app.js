const durationRange = document.getElementById("durationRange");
const durationNumber = document.getElementById("durationNumber");
const reliabilityRange = document.getElementById("reliabilityRange");
const reliabilityNumber = document.getElementById("reliabilityNumber");
const reliabilityOptions = document.getElementById("reliabilityOptions");
const scenarioButtons = document.getElementById("scenarioButtons");
const runSelectedScenario = document.getElementById("runSelectedScenario");
const downloadLatestRun = document.getElementById("downloadLatestRun");
const debugArtifacts = document.getElementById("debugArtifacts");
const messageBar = document.getElementById("messageBar");

const toolCards = {
  groundTruth: document.getElementById("groundTruthCard"),
  detector: document.getElementById("detectorCard"),
  zeek: document.getElementById("zeekCard"),
  suricata: document.getElementById("suricataCard"),
};

const logTargets = {
  detector: document.getElementById("detectorLog"),
  zeek: document.getElementById("zeekLog"),
  suricata: document.getElementById("suricataLog"),
};

const logPathTargets = {
  detector: document.getElementById("detectorLogPath"),
  zeek: document.getElementById("zeekLogPath"),
  suricata: document.getElementById("suricataLogPath"),
  runner: document.getElementById("runnerLogPath"),
};

let cachedScenarios = [];
let busy = false;
let selectedScenario = "";
let activeResultsDbTab = "overview";
let refreshInFlight = false;

function scenarioByName(name) {
  return cachedScenarios.find((scenario) => scenario.name === name);
}

function setMessage(text, tone = "muted") {
  if (!messageBar) {
    return;
  }
  messageBar.className = `message ${tone}`;
  messageBar.textContent = text;
}

function syncDurationInputs(value) {
  const clamped = Math.max(5, Math.min(60, Number(value) || 20));
  durationRange.value = clamped;
  durationNumber.value = clamped;
}

function syncReliabilityInputs(value) {
  const clamped = Math.max(0, Math.min(100, Number(value) || 0));
  reliabilityRange.value = clamped;
  reliabilityNumber.value = clamped;
}

durationRange.addEventListener("input", (event) => syncDurationInputs(event.target.value));
durationNumber.addEventListener("input", (event) => syncDurationInputs(event.target.value));
reliabilityRange.addEventListener("input", (event) => syncReliabilityInputs(event.target.value));
reliabilityNumber.addEventListener("input", (event) => syncReliabilityInputs(event.target.value));

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.message || `Request failed: ${response.status}`);
  }
  return payload;
}

function scenarioNeedsReliability(name) {
  return name === "reliability";
}

function reliabilityScenarioName() {
  return document.querySelector("input[name='reliabilityScenario']:checked")?.value || "reliability-arp-mitm-dns";
}

function effectiveScenarioName() {
  return selectedScenario === "reliability" ? reliabilityScenarioName() : selectedScenario;
}

function selectedScenarioLabel() {
  if (!selectedScenario) {
    return "";
  }
  if (selectedScenario === "reliability") {
    return reliabilityScenarioName() === "reliability-dhcp-spoof" ? "Reliability DHCP" : "Reliability ARP + DNS";
  }
  return scenarioByName(selectedScenario)?.label || selectedScenario;
}

function scenarioDefaultDuration(name) {
  return Number(scenarioByName(name)?.default_duration || 30);
}

function syncSelectedScenarioDuration() {
  const scenarioName = effectiveScenarioName();
  if (scenarioName) {
    syncDurationInputs(scenarioDefaultDuration(scenarioName));
  }
}

function updateScenarioControls() {
  reliabilityOptions.classList.toggle("hidden", !scenarioNeedsReliability(selectedScenario));
  runSelectedScenario.disabled = busy || !selectedScenario;
  runSelectedScenario.textContent = selectedScenario ? `Run ${selectedScenarioLabel()}` : "Run Selected Scenario";
}

function scenarioButtonRows() {
  const rows = cachedScenarios.filter((scenario) => !scenario.name.startsWith("reliability-"));
  const firstReliability = cachedScenarios.find((scenario) => scenario.name.startsWith("reliability-"));
  if (firstReliability) {
    rows.push({
      name: "reliability",
      label: "Reliability Test",
      featured: true,
    });
  }
  return rows;
}

function renderScenarioButtons() {
  scenarioButtons.innerHTML = "";
  scenarioButtonRows().forEach((scenario) => {
    const button = document.createElement("button");
    button.textContent = scenario.label;
    const classes = [];
    if (scenario.featured) {
      classes.push("featured");
    }
    if (scenario.name === selectedScenario) {
      classes.push("selected");
    }
    button.className = classes.join(" ");
    button.disabled = busy;
    button.addEventListener("click", () => {
      selectedScenario = scenario.name;
      syncSelectedScenarioDuration();
      renderScenarioButtons();
      updateScenarioControls();
      setMessage(`${selectedScenarioLabel()} selected.`, "muted");
    });
    scenarioButtons.appendChild(button);
  });
  updateScenarioControls();
}

runSelectedScenario.addEventListener("click", async () => {
  if (!selectedScenario) {
    setMessage("Select a scenario first.", "danger");
    return;
  }
  const scenarioName = effectiveScenarioName();
  const label = selectedScenarioLabel();
  try {
    setMessage(`Starting ${label}...`);
    runSelectedScenario.disabled = true;
    await fetchJson("/api/action", {
      method: "POST",
      body: JSON.stringify({
        action: "run_scenario",
        scenario: scenarioName,
        duration: Number(durationNumber.value),
        netem_loss: Number(reliabilityNumber.value),
        debug_artifacts: Boolean(debugArtifacts?.checked),
      }),
    });
    setMessage(`${label} launched.`, "muted");
    await refreshAll();
  } catch (error) {
    setMessage(error.message, "danger");
  } finally {
    updateScenarioControls();
  }
});

document.querySelectorAll("input[name='reliabilityScenario']").forEach((input) => {
  input.addEventListener("change", () => {
    syncSelectedScenarioDuration();
    updateScenarioControls();
  });
});

downloadLatestRun.addEventListener("click", () => {
  if (debugArtifacts) {
    debugArtifacts.checked = false;
  }
  setMessage("Packaging retained run artifacts...", "muted");
  window.location.href = "/api/download/latest-run.zip";
});

function setActionButtonsDisabled(disabled) {
  document.querySelectorAll("[data-action]").forEach((button) => {
    const action = button.dataset.action;
    if (action === "open_wireshark") {
      button.disabled = false;
      return;
    }
    button.disabled = Boolean(disabled);
  });
}

function lightClass(running) {
  return running ? "light ok" : "light";
}

function badge(label, running) {
  return `<span class="badge"><span class="${lightClass(running)}"></span>${label}</span>`;
}

function statusBadge(label, tone = "idle") {
  const light = tone === "ok" ? "light ok" : tone === "warn" ? "light warn" : "light";
  return `<span class="badge"><span class="${light}"></span>${label}</span>`;
}

function formatMetric(value, digits = 2) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "—";
  }
  return number.toFixed(digits);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatLossLevels(raw) {
  if (!raw) {
    return "";
  }
  return raw
    .split(",")
    .map((item) => Number(item))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b)
    .map((value) => `${value}%`)
    .join(", ");
}

function displayPathName(path) {
  if (!path) {
    return "";
  }
  const parts = String(path).split("/");
  return parts[parts.length - 1] || path;
}

function displayAttackType(type) {
  const labels = {
    arp_spoof: "ARP spoof",
    dns_spoof: "DNS spoof",
    dhcp_spoof: "DHCP spoof",
    dhcp_rogue_server: "DHCP spoof",
    icmp_redirect: "ICMP redirect",
    dhcp_untrusted_switch_port: "DHCP switch-port",
    dns_source_violation: "DNS switch-port",
  };
  return labels[type] || String(type || "").replaceAll("_", " ");
}

function isArpAttackType(type) {
  return type === "arp_spoof";
}

function detectedMark(value) {
  return Number(value || 0) > 0 ? "✓" : "✗";
}

function detectionClass(value) {
  return Number(value || 0) > 0 ? "detect-yes" : "detect-no";
}

function formatAttackValue(type, value) {
  if (isArpAttackType(type)) {
    return detectedMark(value);
  }
  return value;
}

function formatAttackCounts(counts) {
  const entries = Object.entries(counts || {});
  if (!entries.length) {
    return "none";
  }
  return entries.map(([key, value]) => `${displayAttackType(key)}=${formatAttackValue(key, value)}`).join(", ");
}

function nonArpAttackPacketTotal(counts) {
  return Object.entries(counts || {})
    .filter(([key]) => !isArpAttackType(key))
    .reduce((total, [, value]) => total + Number(value || 0), 0);
}

function arpAttackPresent(counts) {
  return Number((counts || {}).arp_spoof || 0) > 0;
}

function sensorSummaryValue(counts, fallbackTotal) {
  const nonArpPackets = nonArpAttackPacketTotal(counts || {});
  if (nonArpPackets > 0) {
    return nonArpPackets;
  }
  if (Object.prototype.hasOwnProperty.call(counts || {}, "arp_spoof")) {
    return detectedMark(arpAttackPresent(counts || {}));
  }
  return Number(fallbackTotal || 0) > 0 ? fallbackTotal : "✗";
}

function sensorSummaryClass(counts) {
  if (nonArpAttackPacketTotal(counts || {}) > 0) {
    return "";
  }
  if (Object.prototype.hasOwnProperty.call(counts || {}, "arp_spoof")) {
    return detectionClass(arpAttackPresent(counts || {}));
  }
  return "";
}

function renderLabStatus(lab, facts) {
  document.getElementById("labGeneratedAt").textContent = lab.generated_at || "";
  const pool = lab.dhcp_pool || {};
  const hostRows = Object.entries(lab.hosts || {}).map(([key, host]) => {
    const running = (host.state || "").toLowerCase().includes("running");
    const macByHost = {
      gateway: facts.gateway_mac,
      victim: facts.victim_mac,
      attacker: facts.attacker_mac,
    };
    const mac = host.mac || macByHost[key] || "";
    return `
      <div class="row">
        <div>
          <strong>${host.vm_name || key}</strong><br>
          <span class="muted">${host.ip || "no IP yet"}${mac ? ` · ${mac}` : ""}</span>
        </div>
        ${badge(host.state || "unknown", running)}
      </div>
    `;
  }).join("");

  document.getElementById("labStatus").innerHTML = `
    <div class="row">
      <div><strong>Bridge</strong><br><span class="muted">${lab.switch_bridge || ""}</span></div>
      ${badge(lab.networks?.switch_bridge_present ? "present" : "missing", Boolean(lab.networks?.switch_bridge_present))}
    </div>
    <div class="row">
      <div><strong>Sensor Port</strong><br><span class="muted">${lab.sensor_interface || ""}</span></div>
      ${badge(lab.networks?.default_present ? "default net ready" : "default net missing", Boolean(lab.networks?.default_present))}
    </div>
    <div class="row">
      <div><strong>Subnet / DNS</strong><br><span class="muted">${facts.subnet || "—"} · DNS ${facts.dns_server || "—"}</span></div>
      ${badge("switch view", true)}
    </div>
    <div class="row">
      <div><strong>Gateway MAC</strong><br><span class="muted">${facts.gateway_mac || "—"}${facts.gateway_ip ? ` · ${facts.gateway_ip}` : ""}</span></div>
      ${badge("reference", Boolean(facts.gateway_mac))}
    </div>
    <div class="row">
      <div><strong>Tracked Domains</strong><br><span class="muted">${facts.detector_domains || "—"}</span></div>
      ${badge(`${(facts.detector_domains || "").split(/\s+/).filter(Boolean).length || 0} domains`, true)}
    </div>
    <div class="row">
      <div><strong>DHCP Pool</strong><br><span class="muted">free ${pool.free ?? "—"} · taken ${pool.taken ?? "—"}</span></div>
      ${badge(`${pool.pool_total ?? "—"} total`, true)}
    </div>
    ${hostRows}
  `;
}

function renderJobStatus(jobState) {
  const active = jobState.active;
  const last = jobState.last_completed;
  busy = Boolean(active && active.running);
  renderScenarioButtons();
  setActionButtonsDisabled(busy);

  const parts = [];
  if (active) {
    parts.push(`
      <div class="stack compact">
        <div class="row"><strong>${active.label}</strong>${badge("running", true)}</div>
        <div class="muted">Started: ${active.started_at}</div>
        <div class="muted">PID: ${active.pid}</div>
        ${active.scenario ? `<div class="muted">Scenario: ${active.scenario}</div>` : ""}
        ${active.duration ? `<div class="muted">Duration: ${active.duration}s</div>` : ""}
      </div>
    `);
  } else {
    parts.push(`<div class="muted">No background job is running right now.</div>`);
  }

  if (last) {
    parts.push(`
      <div class="stack compact">
        <strong>Last Completed</strong>
        <div class="muted">${last.label}</div>
        <div class="muted">Exit code: ${last.exit_code}</div>
        ${last.artifacts_path ? `<div class="muted">Artifacts: ${last.artifacts_path}</div>` : ""}
      </div>
    `);
  }

  document.getElementById("jobStatus").innerHTML = parts.join("");
}

function renderLatestResult(latest, activeRun = null) {
  const container = document.getElementById("latestResult");
  if (activeRun) {
    downloadLatestRun.disabled = true;
    container.innerHTML = `
      <div><strong>${activeRun.label || activeRun.scenario || "Scenario"}</strong></div>
      <div class="muted">${activeRun.scenario || ""}</div>
      <div class="stack compact">
        <div class="row"><span class="muted">State</span>${statusBadge("running", "ok")}</div>
        <div class="row"><span class="muted">Started</span><strong>${activeRun.started_at || "—"}</strong></div>
        <div class="row"><span class="muted">Duration</span><strong>${activeRun.duration ? `${activeRun.duration}s` : "—"}</strong></div>
        <div class="muted">Saved metrics will appear when the run finishes.</div>
      </div>
    `;
    return;
  }
  downloadLatestRun.disabled = !latest || !latest.path || latest.can_download === false;
  if (!latest || !latest.path) {
    container.innerHTML = `<div class="muted">No saved run yet.</div>`;
    return;
  }
  const gtTypes = formatAttackCounts(latest.ground_truth_attack_types || {});
  const nonArpTruthPackets = nonArpAttackPacketTotal(latest.ground_truth_attack_types || {});
  const arpTruth = arpAttackPresent(latest.ground_truth_attack_types || {});
  const switchOnlyTypes = formatAttackCounts(latest.switch_only_attack_types || {});
  const arpDirections = Object.entries(latest.ground_truth_arp_spoof_direction_counts || {})
    .filter(([, value]) => Number(value) > 0)
    .map(([key, value]) => `${key}=${value}`).join(", ");
  const detectorTypes = formatAttackCounts(latest.detector_attack_type_counts || {});
  const zeekTypes = formatAttackCounts(latest.zeek_attack_type_counts || {});
  const suricataTypes = formatAttackCounts(latest.suricata_attack_type_counts || {});
  container.innerHTML = `
    <div><strong>${latest.scenario || displayPathName(latest.path)}</strong></div>
    <div class="muted">${latest.run_id || displayPathName(latest.path) || ""}${latest.started_at ? ` · ${latest.started_at}` : ""}</div>
    <div class="stack compact">
      <div class="row">
        <span class="muted">${nonArpTruthPackets > 0 ? "Ground-truth packets" : "ARP ground truth"}</span>
        <strong class="${nonArpTruthPackets > 0 ? "" : detectionClass(arpTruth)}">${nonArpTruthPackets > 0 ? `${nonArpTruthPackets} pkts` : detectedMark(arpTruth)}</strong>
      </div>
      <div class="muted">Types: ${gtTypes}</div>
      ${switchOnlyTypes !== "none" ? `<div class="muted">Switch-only: ${switchOnlyTypes}</div>` : ""}
      ${arpDirections ? `<div class="muted">ARP directions: ${arpDirections}</div>` : ""}
      <div class="row"><span class="muted">Detector</span><strong class="${sensorSummaryClass(latest.detector_attack_type_counts || {})}">${sensorSummaryValue(latest.detector_attack_type_counts || {}, latest.detector_alert_events)}</strong></div>
      <div class="muted">Types: ${detectorTypes}</div>
      <div class="row"><span class="muted">Zeek</span><strong class="${sensorSummaryClass(latest.zeek_attack_type_counts || {})}">${sensorSummaryValue(latest.zeek_attack_type_counts || {}, latest.zeek_alert_events)}</strong></div>
      <div class="muted">Types: ${zeekTypes}</div>
      <div class="row"><span class="muted">Suricata</span><strong class="${sensorSummaryClass(latest.suricata_attack_type_counts || {})}">${sensorSummaryValue(latest.suricata_attack_type_counts || {}, latest.suricata_alert_events)}</strong></div>
      <div class="muted">Types: ${suricataTypes}</div>
    </div>
  `;
}

function renderResultsDbSummary(summary) {
  const container = document.getElementById("resultsDbSummary");
  const updatedAt = document.getElementById("resultsDbUpdatedAt");
  if (!summary || !summary.exists) {
    updatedAt.textContent = "";
    container.innerHTML = `<div class="muted">No results database yet.</div>`;
    return;
  }
  updatedAt.textContent = summary.latest_started_at || "";
  const sensors = summary.sensor_totals || {};
  const sensorRows = ["detector", "zeek", "suricata"].map((name) => {
    const sensor = sensors[name] || {};
    const detail = name === "detector"
      ? `max ${formatMetric(sensor.max_processed_pps, 1)} pps`
      : "packet alerts";
    return `
      <div class="mini-metric">
        <div class="label">${name}</div>
        <div class="value">${sensor.alerts ?? 0}</div>
        <div class="muted">${detail}</div>
      </div>
    `;
  }).join("");

  const scenarioRows = (summary.scenarios || []).map((scenario) => {
    const losses = formatLossLevels(scenario.reliability_losses);
    return `
      <tr>
        <td><strong>${escapeHtml(scenario.label || scenario.scenario)}</strong><div class="muted">${escapeHtml(scenario.scenario)}</div></td>
        <td class="num">${scenario.run_count ?? 0}</td>
        <td class="num">${scenario.retained_count ?? 0}</td>
        <td>${escapeHtml(losses || "—")}</td>
        <td class="num">${scenario.detector_alerts ?? 0}</td>
        <td class="num">${scenario.zeek_alerts ?? 0}</td>
        <td class="num">${scenario.suricata_alerts ?? 0}</td>
        <td>${escapeHtml(scenario.latest_started_at || "—")}</td>
      </tr>
    `;
  }).join("");
  const lossRows = (summary.loss_coverage || []).map((row) => `
    <tr>
      <td><strong>${escapeHtml(row.label || row.scenario)}</strong></td>
      <td class="num">${row.loss_percent ?? "—"}%</td>
      <td class="num">${row.run_count ?? 0}</td>
      <td class="num">${formatMetric(row.detector_alerts_avg, 1)}</td>
      <td class="num">${formatMetric(row.zeek_alerts_avg, 1)}</td>
      <td class="num">${formatMetric(row.suricata_alerts_avg, 1)}</td>
    </tr>
  `).join("");
  const attackRows = (summary.attack_types || []).map((row) => `
    <tr>
      <td><strong>${escapeHtml(row.label || row.scenario)}</strong></td>
      <td>${escapeHtml(displayAttackType(row.attack_type))}</td>
      ${isArpAttackType(row.attack_type) ? `
        <td class="num ${detectionClass(row.truth_count)}">${detectedMark(row.truth_count)}</td>
        <td class="num ${detectionClass(row.detector_count)}">${detectedMark(row.detector_count)}</td>
        <td class="num ${detectionClass(row.zeek_count)}">${detectedMark(row.zeek_count)}</td>
        <td class="num ${detectionClass(row.suricata_count)}">${detectedMark(row.suricata_count)}</td>
      ` : `
        <td class="num">${row.truth_count ?? 0}</td>
        <td class="num">${row.detector_count ?? 0}</td>
        <td class="num">${row.zeek_count ?? 0}</td>
        <td class="num">${row.suricata_count ?? 0}</td>
      `}
    </tr>
  `).join("");
  const recentRows = (summary.recent_runs || []).map((row) => `
    <tr>
      <td><strong>${escapeHtml(row.run_id)}</strong><div class="muted">${escapeHtml(row.started_at || "—")}</div></td>
      <td>${escapeHtml(row.label || row.scenario)}</td>
      <td>${escapeHtml(row.mode || "—")}</td>
      <td class="num">${row.reliability_loss_percent === null || row.reliability_loss_percent === undefined ? "—" : `${row.reliability_loss_percent}%`}</td>
      <td>${escapeHtml(row.ground_truth_source || "—")}</td>
      <td class="num">${formatMetric(row.duration_seconds, 1)}</td>
      <td class="num">${row.detector_alert_events ?? 0}</td>
      <td class="num">${row.zeek_alert_events ?? 0}</td>
      <td class="num">${row.suricata_alert_events ?? 0}</td>
      <td>${row.raw_artifacts_retained ? "saved" : "compact"}</td>
    </tr>
  `).join("");

  const tabs = [
    ["overview", "Overview"],
    ["scenarios", "Scenarios"],
    ["loss", "Loss Coverage"],
    ["attacks", "Attack Types"],
    ["recent", "Recent Runs"],
  ];
  if (!tabs.some(([key]) => key === activeResultsDbTab)) {
    activeResultsDbTab = "overview";
  }
  const tabButtons = tabs.map(([key, label]) => `
    <button type="button" class="db-tab-button ${activeResultsDbTab === key ? "active" : ""}" data-db-tab="${key}">${label}</button>
  `).join("");

  const tables = {
    overview: `
      <div class="tool-counters db-topline">
        <div class="mini-metric"><div class="label">runs</div><div class="value">${summary.total_runs ?? 0}</div></div>
        <div class="mini-metric"><div class="label">saved</div><div class="value">${summary.retained_runs ?? 0}</div></div>
        <div class="mini-metric"><div class="label">pcaps</div><div class="value">${summary.pcap_runs ?? 0}</div></div>
      </div>
      <div class="sensor-summary-grid">${sensorRows}</div>
    `,
    scenarios: `
      <div class="db-table-wrap">
        <table class="db-table">
          <thead><tr><th>Scenario</th><th>Runs</th><th>Saved</th><th>Losses</th><th>D</th><th>Z</th><th>S</th><th>Latest</th></tr></thead>
          <tbody>${scenarioRows || `<tr><td colspan="8" class="muted">No scenario rows yet.</td></tr>`}</tbody>
        </table>
      </div>
    `,
    loss: `
      <div class="db-table-wrap">
        <table class="db-table">
          <thead><tr><th>Scenario</th><th>Loss</th><th>Runs</th><th>D avg</th><th>Z avg</th><th>S avg</th></tr></thead>
          <tbody>${lossRows || `<tr><td colspan="6" class="muted">No reliability loss rows yet.</td></tr>`}</tbody>
        </table>
      </div>
    `,
    attacks: `
      <div class="db-table-wrap">
        <table class="db-table">
          <thead><tr><th>Scenario</th><th>Attack Type</th><th>Truth</th><th>Detector</th><th>Zeek</th><th>Suricata</th></tr></thead>
          <tbody>${attackRows || `<tr><td colspan="6" class="muted">No attack-type rows yet.</td></tr>`}</tbody>
        </table>
      </div>
    `,
    recent: `
      <div class="db-table-wrap">
        <table class="db-table">
          <thead><tr><th>Run</th><th>Scenario</th><th>Mode</th><th>Loss</th><th>Truth</th><th>Sec</th><th>D</th><th>Z</th><th>S</th><th>Files</th></tr></thead>
          <tbody>${recentRows || `<tr><td colspan="10" class="muted">No recent runs yet.</td></tr>`}</tbody>
        </table>
      </div>
    `,
  };

  container.innerHTML = `
    <div class="db-tab-buttons" role="tablist" aria-label="Results database tables">${tabButtons}</div>
    <div class="db-tab-panel">${tables[activeResultsDbTab] || tables.overview}</div>
  `;

  container.querySelectorAll("[data-db-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      activeResultsDbTab = button.dataset.dbTab || "overview";
      renderResultsDbSummary(summary);
    });
  });
}

function renderToolCard(toolKey, tool) {
  tool = tool || { name: toolKey, running: false, counters: {} };
  const lastEvent = tool.last_event;
  const counters = tool.counters || {};
  const metrics = Object.entries(counters).map(([key, value]) => `
    <div class="mini-metric">
      <div class="label">${displayAttackType(key)}</div>
      <div class="value ${isArpAttackType(key) ? detectionClass(value) : ""}">${formatAttackValue(key, value)}</div>
    </div>
  `).join("");

  toolCards[toolKey].innerHTML = `
    <div class="tool-header">
      <div>
        <h2>${tool.name}</h2>
        <div class="muted">${tool.log_path || ""}</div>
      </div>
      ${badge(tool.running ? "running" : "idle", tool.running)}
    </div>
    <div class="stack compact">
      <div class="row"><span class="muted">PID</span><strong>${tool.pid || "—"}</strong></div>
      <div>
        <strong>Latest Event</strong>
        <div class="muted">${lastEvent?.timestamp || "No recent event"}</div>
        <div>${lastEvent?.summary || "Waiting for live data."}</div>
      </div>
      ${metrics ? `<div class="tool-counters">${metrics}</div>` : ""}
    </div>
  `;
}

function renderGroundTruthCard(latest, activeRun = null) {
  if (activeRun) {
    toolCards.groundTruth.innerHTML = `
      <div class="tool-header">
        <div>
          <h2>Ground Truth</h2>
          <div class="muted">${activeRun.label || activeRun.scenario || "Scenario running"}</div>
        </div>
        ${statusBadge("pending", "warn")}
      </div>
      <div class="stack compact">
        <div class="row"><span class="muted">Current run</span><strong>${activeRun.scenario || "—"}</strong></div>
        <div class="row"><span class="muted">Started</span><strong>${activeRun.started_at || "—"}</strong></div>
      </div>
    `;
    return;
  }
  if (!latest || !latest.path) {
    toolCards.groundTruth.innerHTML = `
      <div class="tool-header">
        <div><h2>Ground Truth</h2><div class="muted">No completed run yet</div></div>
        ${badge("idle", false)}
      </div>
    `;
    return;
  }
  const metrics = Object.entries(latest.ground_truth_attack_types || {}).map(([key, value]) => `
    <div class="mini-metric">
      <div class="label">${displayAttackType(key)}</div>
      <div class="value ${isArpAttackType(key) ? detectionClass(value) : ""}">${formatAttackValue(key, value)}</div>
    </div>
  `).join("");
  const nonArpTruthPackets = nonArpAttackPacketTotal(latest.ground_truth_attack_types || {});
  const arpTruth = arpAttackPresent(latest.ground_truth_attack_types || {});
  const arpDirections = Object.entries(latest.ground_truth_arp_spoof_direction_counts || {}).map(([key, value]) => `${key}=${value}`).join(", ");
  toolCards.groundTruth.innerHTML = `
    <div class="tool-header">
      <div>
        <h2>Ground Truth (Switch)</h2>
        <div class="muted">${latest.scenario || displayPathName(latest.path)}${latest.started_at ? ` · ${latest.started_at}` : ""}</div>
      </div>
    </div>
    <div class="stack compact">
      <div class="row">
        <span class="muted">${nonArpTruthPackets > 0 ? "Matched packets" : "ARP attack"}</span>
        <strong class="${nonArpTruthPackets > 0 ? "" : detectionClass(arpTruth)}">${nonArpTruthPackets > 0 ? nonArpTruthPackets : detectedMark(arpTruth)}</strong>
      </div>
      <div class="row"><span class="muted">Attack duration</span><strong>${latest.ground_truth_attack_duration_seconds ? `${latest.ground_truth_attack_duration_seconds.toFixed(2)}s` : "—"}</strong></div>
      ${arpDirections ? `<div class="muted">ARP directions: ${arpDirections}</div>` : ""}
      ${metrics ? `<div class="tool-counters">${metrics}</div>` : ""}
    </div>
  `;
}

function renderLogEntries(target, entries) {
  if (!entries.length) {
    target.innerHTML = `<div class="muted">No entries yet.</div>`;
    return;
  }
  target.innerHTML = entries.map((entry) => `
    <div class="log-entry">
      <div class="log-meta">
        <span>${entry.timestamp || ""}</span>
        <span>${entry.kind || ""}</span>
      </div>
      <div>${entry.summary || ""}</div>
    </div>
  `).join("");
}

async function refreshLogs() {
  for (const source of ["detector", "zeek", "suricata", "runner"]) {
    try {
      const payload = await fetchJson(`/api/logs/${source}`);
      if (source === "runner") {
        document.getElementById("runnerLog").textContent = (payload.entries || []).join("\n");
      } else {
        renderLogEntries(logTargets[source], payload.entries || []);
      }
      if (logPathTargets[source]) {
        logPathTargets[source].textContent = payload.path || "";
      }
    } catch (error) {
      if (source === "runner") {
        document.getElementById("runnerLog").textContent = error.message;
      } else {
        logTargets[source].innerHTML = `<div class="muted">${error.message}</div>`;
      }
    }
  }
}

async function postSimpleAction(action) {
  try {
    const payload = await fetchJson("/api/action", {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    setMessage(payload.message || "Action completed.");
    if (payload.download_url) {
      const link = document.createElement("a");
      link.href = payload.download_url;
      link.download = "";
      document.body.appendChild(link);
      link.click();
      link.remove();
    }
    await refreshAll();
  } catch (error) {
    setMessage(error.message, "danger");
  }
}

document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", async () => {
    await postSimpleAction(button.dataset.action);
  });
});

async function refreshStatus() {
  const payload = await fetchJson("/api/status");
  window.__latestResult = payload.latest_result || null;
  cachedScenarios = payload.scenarios || [];
  const activeRun = payload.active_run || null;
  const tools = payload.tools || {};
  renderScenarioButtons();
  renderLabStatus(payload.lab || {}, payload.lab_facts || {});
  renderJobStatus(payload.job || {});
  renderLatestResult(payload.latest_result || {}, activeRun);
  renderResultsDbSummary(payload.results_db || {});
  renderGroundTruthCard(payload.latest_result || null, activeRun);
  renderToolCard("detector", tools.detector);
  renderToolCard("zeek", tools.zeek);
  renderToolCard("suricata", tools.suricata);
}

async function refreshAll() {
  if (refreshInFlight) {
    return;
  }
  refreshInFlight = true;
  try {
    await refreshStatus();
    await refreshLogs();
  } finally {
    refreshInFlight = false;
  }
}

syncDurationInputs(30);
syncReliabilityInputs(0);
refreshAll().catch((error) => setMessage(error.message, "danger"));
setInterval(() => {
  refreshAll().catch((error) => setMessage(error.message, "danger"));
}, 2000);
