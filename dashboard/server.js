import express from "express";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = 3000;
const logPath = "/var/log/unix-cyber-lab/events.log";

const nodes = [
  { id: "attacker", name: "Attacker", ip: "172.28.0.10", role: "Controlled event simulator", status: "online" },
  { id: "target", name: "Target", ip: "172.28.0.20", role: "Linux service and log source", status: "online" },
  { id: "defender", name: "Defender", ip: "172.28.0.30", role: "Rule-based log analyzer", status: "online" },
  { id: "dashboard", name: "Dashboard", ip: "172.28.0.40", role: "Vue transparency layer", status: "online" }
];

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
      return memo;
    },
    { total: 0, failedLogins: 0, byType: {} }
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

app.use("/vendor/vue", express.static(path.join(__dirname, "node_modules/vue/dist")));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/nodes", (_request, response) => {
  response.json(nodes);
});

app.get("/api/events", async (_request, response) => {
  response.json(await readEvents());
});

app.get("/api/summary", async (_request, response) => {
  response.json(summarize(await readEvents()));
});

app.listen(port, () => {
  console.log(`dashboard listening on 0.0.0.0:${port}`);
});
