const durationRange = document.getElementById("durationRange");
const durationNumber = document.getElementById("durationNumber");
const visibilityRange = document.getElementById("visibilityRange");
const visibilityNumber = document.getElementById("visibilityNumber");
const visibilityOptions = document.getElementById("visibilityOptions");
const takeoverOptions = document.getElementById("takeoverOptions");
const takeoverEnabled = document.getElementById("takeoverEnabled");
const workersRange = document.getElementById("workersRange");
const workersNumber = document.getElementById("workersNumber");
const scenarioButtons = document.getElementById("scenarioButtons");
const runSelectedScenario = document.getElementById("runSelectedScenario");
const downloadLatestRun = document.getElementById("downloadLatestRun");
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

function setMessage(text, tone = "muted") {
  messageBar.className = `message ${tone}`;
  messageBar.textContent = text;
}

function syncDurationInputs(value) {
  const clamped = Math.max(5, Math.min(60, Number(value) || 20));
  durationRange.value = clamped;
  durationNumber.value = clamped;
}

function syncVisibilityInputs(value) {
  const clamped = Math.max(0, Math.min(100, Number(value) || 0));
  visibilityRange.value = clamped;
  visibilityNumber.value = clamped;
}

function syncWorkersInputs(value) {
  const clamped = Math.max(1, Math.min(108, Number(value) || 1));
  workersRange.value = clamped;
  workersNumber.value = clamped;
}

durationRange.addEventListener("input", (event) => syncDurationInputs(event.target.value));
durationNumber.addEventListener("input", (event) => syncDurationInputs(event.target.value));
visibilityRange.addEventListener("input", (event) => syncVisibilityInputs(event.target.value));
visibilityNumber.addEventListener("input", (event) => syncVisibilityInputs(event.target.value));
workersRange.addEventListener("input", (event) => syncWorkersInputs(event.target.value));
workersNumber.addEventListener("input", (event) => syncWorkersInputs(event.target.value));

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

function scenarioNeedsVisibility(name) {
  return name === "visibility";
}

function scenarioSupportsTakeover(name) {
  return name === "dhcp-starvation-rogue-dhcp";
}

function visibilityScenarioName() {
  return document.querySelector("input[name='visibilityScenario']:checked")?.value || "visibility-arp-mitm-dns";
}

function effectiveScenarioName() {
  return selectedScenario === "visibility" ? visibilityScenarioName() : selectedScenario;
}

function selectedScenarioLabel() {
  if (!selectedScenario) {
    return "";
  }
  if (selectedScenario === "visibility") {
    return visibilityScenarioName() === "visibility-dhcp-spoof" ? "Visibility DHCP" : "Visibility ARP + DNS";
  }
  return cachedScenarios.find((scenario) => scenario.name === selectedScenario)?.label || selectedScenario;
}

function updateScenarioControls() {
  visibilityOptions.classList.toggle("hidden", !scenarioNeedsVisibility(selectedScenario));
  takeoverOptions.classList.toggle("hidden", !scenarioSupportsTakeover(selectedScenario));
  runSelectedScenario.disabled = busy || !selectedScenario;
  runSelectedScenario.textContent = selectedScenario ? `Run ${selectedScenarioLabel()}` : "Run Selected Scenario";
}

function scenarioButtonRows() {
  const rows = cachedScenarios.filter((scenario) => !scenario.name.startsWith("visibility-"));
  const firstVisibility = cachedScenarios.find((scenario) => scenario.name.startsWith("visibility-"));
  if (firstVisibility) {
    rows.push({
      name: "visibility",
      label: "Visibility Test",
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
        visibility: Number(visibilityNumber.value),
        workers: Number(workersNumber.value),
        takeover_enabled: !scenarioSupportsTakeover(selectedScenario) || takeoverEnabled.checked,
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

document.querySelectorAll("input[name='visibilityScenario']").forEach((input) => {
  input.addEventListener("change", () => updateScenarioControls());
});

downloadLatestRun.addEventListener("click", () => {
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
      <div><strong>DHCP Pool</strong><br><span class="muted">free ${pool.free ?? "—"} · taken ${pool.taken ?? "—"} · attack ${pool.attack_taken ?? "—"}</span></div>
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
  downloadLatestRun.disabled = !latest || !latest.path;
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
  const starvationNote = (latest.scenario || "").includes("starvation")
    ? `<div class="inline-help">DHCP starvation note: ground truth here counts matched starvation DHCP packets on the wire. Cleanup release packets are excluded.</div>`
    : "";
  container.innerHTML = `
    <div><strong>${latest.scenario || latest.path}</strong></div>
    <div class="muted">${latest.summary_path || ""}</div>
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
      ${starvationNote}
    </div>
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
  renderGroundTruthCard(payload.latest_result || null);
  renderToolCard("detector", payload.tools.detector);
  renderToolCard("zeek", payload.tools.zeek);
  renderToolCard("suricata", payload.tools.suricata);
}

async function refreshAll() {
  await refreshStatus();
  await refreshLogs();
}

syncDurationInputs(20);
syncVisibilityInputs(100);
syncWorkersInputs(1);
refreshAll().catch((error) => setMessage(error.message, "danger"));
setInterval(() => {
  refreshAll().catch((error) => setMessage(error.message, "danger"));
}, 2000);
