import express from "express";
import { readFile, writeFile } from "node:fs/promises";
import { lookup } from "node:dns/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = 3000;
const logPath = "/var/log/unix-cyber-lab/events.log";
const auditToken = process.env.AUDIT_TOKEN || "";
const maxTargetLength = 512;

const nodeDefinitions = [
  { id: "attacker", name: "Attacker", fallbackIp: "172.28.0.10", role: "Controlled event simulator" },
  { id: "target", name: "Target", fallbackIp: "172.28.0.20", role: "Linux service and log source" },
  { id: "defender", name: "Defender", fallbackIp: "172.28.0.30", role: "Rule-based log analyzer" },
  { id: "dashboard", name: "Dashboard", fallbackIp: "172.28.0.40", role: "Vue transparency layer" }
];

const remediationByLab = {
  "LAB-001": "停用正式環境的除錯端點，或限制只有管理網段與已驗證使用者可存取。",
  "LAB-002": "將備份檔移出網站公開目錄，並限制檔案擁有者與權限。",
  "LAB-003": "為管理匯出功能加入身分驗證與授權檢查。",
  "LAB-004": "使用 chmod 640 與 chown 限制設定檔，只允許服務擁有者修改。"
};

const attackerPhaseByLab = {
  "LAB-001": "Reconnaissance",
  "LAB-002": "Credential Exposure",
  "LAB-003": "Unauthorized Access",
  "LAB-004": "Integrity Impact"
};

async function resolveNodes() {
  return Promise.all(nodeDefinitions.map(async (node) => {
    try {
      const result = await lookup(node.id, { family: 4 });
      return { ...node, ip: result.address, ipSource: "dynamic", status: "online" };
    } catch {
      return { ...node, ip: node.fallbackIp, ipSource: "fallback", status: "unresolved" };
    }
  }));
}

function parseEvent(line, index) {
  const [timestamp, ...parts] = line.trim().split(" ");
  const event = { id: index + 1, timestamp, raw: line.trim() };

  for (const part of parts) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const key = part.slice(0, separator);
    const value = part.slice(separator + 1);
    event[key] = value;
  }

  return event;
}

function summarize(events) {
  const counts = events.reduce(
    (memo, event) => {
      memo.total += 1;
      memo.byType[event.type] = (memo.byType[event.type] || 0) + 1;
      if (event.type === "login_attempt" && event.detail?.includes("result=failed")) {
        memo.failedLogins += 1;
      }
      if (event.type === "vulnerability_access") memo.vulnerabilityAccesses += 1;
      if (event.type === "configuration_changed") memo.configurationChanges += 1;
      if (event.type === "exploit_success") memo.successfulExploits += 1;
      return memo;
    },
    {
      total: 0,
      failedLogins: 0,
      vulnerabilityAccesses: 0,
      configurationChanges: 0,
      successfulExploits: 0,
      byType: {}
    }
  );

  const alerts = [];
  if (counts.failedLogins >= 3) {
    alerts.push({
      severity: "high",
      title: "Multiple Failed Login Attempts",
      description: "Target received repeated failed login attempts from the attacker node.",
      suggestion: "Review account policy, inspect source IP, and consider firewall or rate limit rules."
    });
  }
  if (counts.vulnerabilityAccesses > 0) {
    alerts.push({
      severity: "medium",
      title: "Vulnerable Endpoint Accessed",
      description: `${counts.vulnerabilityAccesses} requests reached known vulnerable lab endpoints.`,
      suggestion: "Disable exposed endpoints, require authentication, and remove public backup files."
    });
  }
  if (counts.configurationChanges > 0) {
    alerts.push({
      severity: "high",
      title: "Configuration Integrity Changed",
      description: "A world-writable simulated configuration file was modified.",
      suggestion: "Restore the file and restrict its permissions to the service owner."
    });
  }
  if (counts.successfulExploits > 0) {
    alerts.push({
      severity: "high",
      title: "Successful Controlled Exploit",
      description: `${counts.successfulExploits} allow-listed exploit actions completed successfully.`,
      suggestion: "Review the exact exposed resource and compare the before/after state in the attack report."
    });
  }

  return {
    ...counts,
    alerts,
    riskLevel: alerts.length ? "High" : "Normal"
  };
}

async function readEvents() {
  try {
    const content = await readFile(logPath, "utf8");
    return content
      .split("\n")
      .filter(Boolean)
      .map(parseEvent)
      .reverse();
  } catch {
    return [];
  }
}

function readTarget(value) {
  if (Array.isArray(value) || (typeof value === "object" && value !== null)) {
    throw new TypeError("target must be a single URL, host, or IP");
  }
  const target = String(value || "target").trim();
  if (!target || target.length > maxTargetLength) {
    throw new TypeError("target is required and must be at most 512 characters");
  }
  return target;
}

app.use("/vendor/vue", express.static(path.join(__dirname, "node_modules/vue/dist")));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/nodes", async (_request, response) => {
  response.json(await resolveNodes());
});

app.get("/api/events", async (_request, response) => {
  response.json(await readEvents());
});

app.delete("/api/events", async (_request, response) => {
  try {
    await writeFile(logPath, "", "utf8");
    response.json({ success: true, message: "event records cleared" });
  } catch {
    response.status(500).json({ success: false, error: "unable to clear event records" });
  }
});

app.get("/api/summary", async (_request, response) => {
  response.json(summarize(await readEvents()));
});

app.get("/api/vulnerabilities/scan", async (_request, response) => {
  try {
    const attackerResponse = await fetch("http://attacker:8090/scan");
    response.status(attackerResponse.status).json(await attackerResponse.json());
  } catch {
    response.status(503).json({ error: "attacker service is unavailable" });
  }
});

app.get("/api/audit/linux", async (_request, response) => {
  try {
    const requestedTarget = readTarget(_request.query.target);
    const targetQuery = encodeURIComponent(requestedTarget);
    const auditResponse = await fetch(`http://attacker:8090/audit/full?target=${targetQuery}`);
    const audit = await auditResponse.json();
    if (!auditResponse.ok) {
      response.status(auditResponse.status).json({ error: audit.error || "target scan failed" });
      return;
    }
    const { target, network, probe } = audit;
    const nodes = await resolveNodes();
    const targetNode = nodes.find((node) => node.id === "target");
    const isLabTarget = target.is_lab === true;
    const systemResponse = isLabTarget
      ? await fetch("http://target:8080/audit/system", { headers: { "X-Audit-Token": auditToken } })
      : null;
    const system = systemResponse?.ok
      ? await systemResponse.json()
      : { collector: "unavailable", os: { PRETTY_NAME: "Remote private host" }, commands: {}, findings: [] };
    const systemFindings = system.findings.map((finding, index) => {
      const portMatch = finding.evidence.match(/0\.0\.0\.0:(\d+)/);
      return {
        ...finding,
        id: `SYS-${String(index + 1).padStart(3, "0")}`,
        source: "unix_collector",
        location: finding.category === "file_permissions"
          ? finding.evidence.split(" ").at(-1)
          : `${targetNode?.ip || "target"}:${portMatch?.[1] || "unknown"}`
      };
    });
    const networkFindings = network.findings.map((finding, index) => ({
      ...finding,
      id: `NET-${String(index + 1).padStart(3, "0")}`,
      source: "nmap",
      location: `${network.target_ip}:${network.open_ports[index]?.port || "unknown"}`
    }));
    const probedFindings = probe.mode === "lab"
      ? probe.findings.map((finding) => ({
          id: finding.id,
          labId: finding.id,
          category: "application_vulnerability",
          severity: finding.severity,
          title: finding.name,
          evidence: finding.evidence,
          reason: finding.description,
          recommendation: remediationByLab[finding.id],
          source: "active_http_probe",
          location: `${target.base_url}${finding.path}`,
          path: finding.path,
          attack: finding.attack,
          exposed: finding.exposed || [],
          attackerValue: finding.attacker_value || "",
          attackerPhase: attackerPhaseByLab[finding.id],
          actionable: true
        }))
      : probe.findings;
    const findings = [...networkFindings, ...probedFindings];
    const defenderFindings = systemFindings;
    response.json({
      generatedAt: new Date().toISOString(),
      target: requestedTarget,
      normalizedTarget: target,
      targetUrl: target.requested_url,
      targetIp: network.target_ip,
      isLabTarget,
      system,
      network,
      webServices: probe.services || [],
      findings,
      defenderFindings,
      score: Math.max(0, 100 - [...findings, ...defenderFindings].reduce((score, item) => score + (item.severity === "high" ? 20 : 8), 0))
    });
  } catch (error) {
    const status = error instanceof TypeError ? 400 : 503;
    response.status(status).json({ error: status === 400 ? error.message : "linux audit services are unavailable" });
  }
});

app.post("/api/vulnerabilities/:id/attack", async (request, response) => {
  try {
    const target = encodeURIComponent(readTarget(request.query.target));
    const attackerResponse = await fetch(`http://attacker:8090/attack/${encodeURIComponent(request.params.id)}?target=${target}`);
    response.status(attackerResponse.status).json(await attackerResponse.json());
  } catch {
    response.status(503).json({ error: "attacker service is unavailable" });
  }
});

app.listen(port, () => {
  console.log(`dashboard listening on 0.0.0.0:${port}`);
});
