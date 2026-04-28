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

function scenarioByName(name) {
  return cachedScenarios.find((scenario) => scenario.name === name);
}

function setMessage(text, tone = "muted") {
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
    return reliabilityScenarioName() === "reliability-dhcp-spoof" ? "Reliability DHCP Rogue" : "Reliability ARP + DNS";
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

function renderLatestResult(latest) {
  const container = document.getElementById("latestResult");
  downloadLatestRun.disabled = !latest || !latest.path || latest.can_download === false;
  if (!latest || !latest.path) {
    container.innerHTML = `<div class="muted">No saved run yet.</div>`;
    return;
  }
  const gtTypes = Object.entries(latest.ground_truth_attack_types || {}).map(([key, value]) => `${key}=${value}`).join(", ") || "none";
  const arpDirections = Object.entries(latest.ground_truth_arp_spoof_direction_counts || {})
    .filter(([, value]) => Number(value) > 0)
    .map(([key, value]) => `${key}=${value}`).join(", ");
  const detectorTypes = Object.entries(latest.detector_attack_type_counts || {}).map(([key, value]) => `${key}=${value}`).join(", ") || "none";
  const zeekTypes = Object.entries(latest.zeek_attack_type_counts || {}).map(([key, value]) => `${key}=${value}`).join(", ") || "none";
  const suricataTypes = Object.entries(latest.suricata_attack_type_counts || {}).map(([key, value]) => `${key}=${value}`).join(", ") || "none";
  container.innerHTML = `
    <div><strong>${latest.scenario || latest.path}</strong></div>
    <div class="muted">${latest.summary_path || latest.path || ""}</div>
    ${latest.can_download === false ? `<div class="inline-help">Compact DB row only; raw run files were not retained.</div>` : ""}
    <div class="stack compact">
      <div class="row"><span class="muted">Ground truth</span><strong>${latest.ground_truth_attack_events ?? "—"} pkts</strong></div>
      <div class="muted">Types: ${gtTypes}</div>
      ${arpDirections ? `<div class="muted">ARP directions: ${arpDirections}</div>` : ""}
      <div class="row"><span class="muted">Detector</span><strong>${latest.detector_alert_events ?? "—"}</strong></div>
      <div class="muted">Types: ${detectorTypes}</div>
      <div class="row"><span class="muted">Zeek</span><strong>${latest.zeek_alert_events ?? "—"}</strong></div>
      <div class="muted">Types: ${zeekTypes}</div>
      <div class="row"><span class="muted">Suricata</span><strong>${latest.suricata_alert_events ?? "—"}</strong></div>
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
    return `
      <div class="mini-metric">
        <div class="label">${name}</div>
        <div class="value">${sensor.alerts ?? 0}</div>
        <div class="muted">ttd ${formatMetric(sensor.avg_ttd_seconds)}s · max ${formatMetric(sensor.max_processed_pps, 1)} pps</div>
      </div>
    `;
  }).join("");
  const scenarioRows = (summary.scenarios || []).slice(0, 8).map((scenario) => {
    const losses = formatLossLevels(scenario.reliability_losses);
    return `
      <div class="scenario-summary-row">
        <div>
          <strong>${scenario.label || scenario.scenario}</strong>
          <div class="muted">${scenario.latest_started_at || ""}${losses ? ` · loss ${losses}` : ""}</div>
          <div class="muted">alerts D/Z/S ${scenario.detector_alerts ?? 0}/${scenario.zeek_alerts ?? 0}/${scenario.suricata_alerts ?? 0}</div>
        </div>
        <div class="scenario-summary-counts">
          <strong>${scenario.run_count}</strong>
          <span class="muted">runs</span>
          ${scenario.retained_count ? `<span class="badge">${scenario.retained_count} saved</span>` : ""}
        </div>
      </div>
    `;
  }).join("");

  container.innerHTML = `
    <div class="tool-counters">
      <div class="mini-metric">
        <div class="label">runs</div>
        <div class="value">${summary.total_runs ?? 0}</div>
      </div>
      <div class="mini-metric">
        <div class="label">saved</div>
        <div class="value">${summary.retained_runs ?? 0}</div>
      </div>
      <div class="mini-metric">
        <div class="label">pcaps</div>
        <div class="value">${summary.pcap_runs ?? 0}</div>
      </div>
    </div>
    <div class="sensor-summary-grid">${sensorRows}</div>
    <div class="db-scenario-list">${scenarioRows || `<div class="muted">No scenario rows yet.</div>`}</div>
  `;
}

function renderToolCard(toolKey, tool) {
  const latest = window.__latestResult || null;
  const arpDirectionNote = window.__sensorNotes?.arp_direction_note && latest?.scenario?.includes("arp");
  const lastEvent = tool.last_event;
  const counters = tool.counters || {};
  const metrics = Object.entries(counters).map(([key, value]) => `
    <div class="mini-metric">
      <div class="label">${key.replaceAll("_", " ")}</div>
      <div class="value">${value}</div>
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
      ${arpDirectionNote ? `<div class="inline-help">ARP note: this card counts one poisoning direction, while switch ground truth may include both gateway-to-victim and victim-to-gateway replies.</div>` : ""}
      ${metrics ? `<div class="tool-counters">${metrics}</div>` : ""}
    </div>
  `;
}

function renderGroundTruthCard(latest) {
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
      <div class="label">${key.replaceAll("_", " ")}</div>
      <div class="value">${value}</div>
    </div>
  `).join("");
  const arpDirections = Object.entries(latest.ground_truth_arp_spoof_direction_counts || {}).map(([key, value]) => `${key}=${value}`).join(", ");
  toolCards.groundTruth.innerHTML = `
    <div class="tool-header">
      <div>
        <h2>Ground Truth (Switch)</h2>
        <div class="muted">${latest.scenario || latest.path}</div>
      </div>
    </div>
    <div class="stack compact">
      <div class="inline-help">Counts here come from the mirrored switch view and represent matched attack packets on the wire.</div>
      <div class="row"><span class="muted">Matched packets</span><strong>${latest.ground_truth_attack_events ?? "—"}</strong></div>
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
  window.__sensorNotes = payload.sensor_notes || {};
  cachedScenarios = payload.scenarios || [];
  renderScenarioButtons();
  renderLabStatus(payload.lab || {}, payload.lab_facts || {});
  renderJobStatus(payload.job || {});
  renderLatestResult(payload.latest_result || {});
  renderResultsDbSummary(payload.results_db || {});
  renderGroundTruthCard(payload.latest_result || null);
  renderToolCard("detector", payload.tools.detector);
  renderToolCard("zeek", payload.tools.zeek);
  renderToolCard("suricata", payload.tools.suricata);
}

async function refreshAll() {
  await refreshStatus();
  await refreshLogs();
}

syncDurationInputs(30);
syncReliabilityInputs(0);
refreshAll().catch((error) => setMessage(error.message, "danger"));
setInterval(() => {
  refreshAll().catch((error) => setMessage(error.message, "danger"));
}, 2000);
