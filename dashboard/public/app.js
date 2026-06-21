const { createApp } = Vue;

createApp({
  data() {
    return {
      nodes: [],
      activeView: "overview",
      targetInput: "target",
      events: [],
      summary: { byType: {}, alerts: [] },
      attackResults: {},
      defenseResults: {},
      auditReport: null,
      auditing: false,
      auditMessage: "",
      loading: false,
      attackingId: "",
      operationMessage: "",
      terminalOpen: false,
      terminalRunning: false,
      terminalTitle: "",
      terminalMode: "attack",
      terminalLines: [],
      clearConfirmOpen: false,
      clearingRecords: false,
      lastUpdated: "not yet refreshed"
    };
  },
  mounted() {
    this.refreshData();
    setInterval(this.refreshData, 5000);
  },
  methods: {
    async refreshData() {
      this.loading = true;
      try {
        const [nodes, events, summary] = await Promise.all([
          fetch("/api/nodes").then((response) => response.json()),
          fetch("/api/events").then((response) => response.json()),
          fetch("/api/summary").then((response) => response.json())
        ]);

        this.nodes = nodes;
        this.events = events;
        this.summary = summary;
        this.lastUpdated = new Date().toLocaleTimeString("zh-TW", { hour12: false });
      } catch {
        this.lastUpdated = "服務暫時無法連線，等待自動重試";
      } finally {
        this.loading = false;
      }
    },
    nodeIp(id) {
      return this.nodes.find((node) => node.id === id)?.ip || {
        attacker: "172.28.0.10",
        target: "172.28.0.20",
        defender: "172.28.0.30",
        dashboard: "172.28.0.40"
      }[id];
    },
    async runLinuxAudit() {
      const requestedTarget = this.targetInput.trim() || "target";
      this.auditing = true;
      this.auditMessage = `正在分析 ${requestedTarget} 的攻擊面...`;
      this.terminalOpen = true;
      this.terminalRunning = true;
      this.terminalMode = "audit";
      this.terminalTitle = `Authorized Private Web Audit / ${requestedTarget}`;
      this.terminalLines = [];
      try {
        await this.typeTerminalLine("Unix Cyber Lab authorized private web auditor", "system", 18);
        await this.typeTerminalLine(`$ resolve-target \"${requestedTarget}\"`, "command", 12);
        await this.typeTerminalLine("[authorization] resolving and validating private addresses", "system", 9);
        const response = await fetch(`/api/audit/linux?target=${encodeURIComponent(requestedTarget)}`);
        const report = await response.json();
        if (!response.ok) throw new Error(report.error || "audit failed");
        this.auditReport = report;
        await this.typeTerminalLine(`[target] ${report.targetUrl} -> ${report.targetIp}`, "success", 8);
        await this.typeTerminalLine(`$ ${report.network.command}`, "command", 8);
        for (const service of report.webServices || []) {
          await this.typeTerminalLine(`[web] ${service.status} ${service.url}${service.title ? ` · ${service.title}` : ""}`, "success", 7);
        }
        if (report.isLabTarget) {
          await this.typeTerminalLine("[lab probe] running allow-listed teaching paths", "system", 9);
          await this.typeTerminalLine("[defender-side] authorized UNIX Collector results stored separately", "system", 9);
        } else {
          await this.typeTerminalLine("[real target] passive HTTP checks only; exploit actions disabled", "system", 9);
        }
        for (const port of report.network.open_ports) {
          await this.typeTerminalLine(`[open port] ${port.port}/${port.protocol} ${port.service} ${port.product}`.trim(), "warning", 8);
        }
        for (const finding of report.findings) {
          await this.typeTerminalLine(`[${finding.severity}] ${finding.title}`, finding.severity === "high" ? "error" : "warning", 8);
          await this.typeTerminalLine(`[evidence] ${finding.evidence}`, "output", 5);
        }
        await this.typeTerminalLine(`[complete] Security score: ${report.score}/100`, "success", 12);
        this.auditMessage = report.isLabTarget
          ? `Lab 分析完成：發現 ${report.findings.length} 個項目，其中 ${report.findings.filter((item) => item.actionable).length} 個可展示攻擊。`
          : `私人網頁分析完成：識別 ${report.webServices.length} 個 Web 服務與 ${report.findings.length} 個安全項目。`;
        await this.refreshData();
      } catch (error) {
        await this.typeTerminalLine(`[error] ${error.message}`, "error", 14);
        this.auditMessage = `稽核失敗：${error.message}`;
      } finally {
        this.auditing = false;
        this.terminalRunning = false;
      }
    },
    sleep(milliseconds) {
      return new Promise((resolve) => setTimeout(resolve, milliseconds));
    },
    async typeTerminalLine(text, type = "output", speed = 18) {
      const line = { text: "", type };
      this.terminalLines.push(line);
      for (const character of text) {
        line.text += character;
        await this.sleep(speed);
      }
    },
    attackScript(vulnerability) {
      const vulnerabilityId = vulnerability.labId || vulnerability.id;
      const scripts = {
        "LAB-001": [
          "$ export TARGET=http://target:8080",
          "$ curl -s \"$TARGET/debug?inspect=full\""
        ],
        "LAB-002": [
          "$ export TARGET=http://target:8080",
          "$ curl -s -o config.bak \"$TARGET/backup/config.bak?download=true\"",
          "$ cat config.bak"
        ],
        "LAB-003": [
          "$ export TARGET=http://target:8080",
          "$ curl -s \"$TARGET/admin/export?format=json\""
        ],
        "LAB-004": [
          "$ export TARGET=http://target:8080",
          "$ curl -s \"$TARGET/files/permissions\"",
          "$ curl -s \"$TARGET/files/config\"",
          "$ curl -s \"$TARGET/files/config?mode=<alternate-mode>\""
        ]
      };
      return scripts[vulnerabilityId] || [];
    },
    async runAttack(vulnerability) {
      const vulnerabilityId = vulnerability.labId || vulnerability.id;
      this.attackingId = vulnerabilityId;
      this.operationMessage = `正在針對 ${vulnerability.location} 執行受控攻擊...`;
      this.terminalOpen = true;
      this.terminalRunning = true;
      this.terminalMode = "attack";
      this.terminalTitle = `${vulnerabilityId} / ${vulnerability.title || vulnerability.name}`;
      this.terminalLines = [];
      try {
        await this.typeTerminalLine("Unix Cyber Lab controlled shell", "system", 26);
        await this.typeTerminalLine(`attacker@${this.nodeIp("attacker")} -> target@${this.nodeIp("target")}`, "system", 16);
        await this.sleep(250);
        for (const command of this.attackScript(vulnerability)) {
          await this.typeTerminalLine(command, "command", 20);
          await this.sleep(320);
        }
        await this.typeTerminalLine("[running allow-listed exploit...]", "system", 14);
        const response = await fetch(
          `/api/vulnerabilities/${vulnerabilityId}/attack?target=${encodeURIComponent(this.auditReport?.target || "target")}`,
          { method: "POST" }
        );
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "attack failed");
        this.attackResults[vulnerabilityId] = result;
        await this.typeTerminalLine(result.result, "success", 12);
        for (const item of result.exposed || []) {
          await this.typeTerminalLine(`[stolen] ${item.label}: ${item.value}`, "warning", 9);
        }
        await this.typeTerminalLine(`[success] ${result.summary}`, "success", 14);
        await this.typeTerminalLine(`[impact] ${result.impact}`, "warning", 11);
        await this.typeTerminalLine(`[before] ${result.before}`, "output", 12);
        await this.typeTerminalLine(`[after]  ${result.after}`, "success", 12);
        this.operationMessage = `${vulnerabilityId} 攻擊劇本執行完成。`;
        await this.refreshData();
      } catch (error) {
        await this.typeTerminalLine(`[error] ${error.message}`, "error", 16);
        this.operationMessage = `攻擊失敗：${error.message}`;
      } finally {
        this.attackingId = "";
        this.terminalRunning = false;
      }
    },
    defenseScript(finding) {
      const scripts = {
        "LAB-001": ["$ sudo systemctl disable target-debug-endpoint", "$ sudo ufw deny from any to any port 8080"],
        "LAB-002": ["$ sudo mv /srv/www/backup/config.bak /var/backups/", "$ sudo chmod 600 /var/backups/config.bak"],
        "LAB-003": ["$ sudo nano /etc/target/access-control.conf", "$ sudo systemctl reload target-service"],
        "LAB-004": ["$ sudo chown root:target /lab/service.conf", "$ sudo chmod 640 /lab/service.conf"]
      };
      return scripts[finding.labId] || ["$ sudo ss -lntup", "$ sudo ufw default deny incoming"];
    },
    stolenItems(finding) {
      const result = this.attackResults[finding.labId || finding.id];
      if (result?.exposed?.length) return result.exposed;
      return finding.exposed || [];
    },
    exposedCount() {
      if (!this.auditReport) return 0;
      return this.auditReport.findings.reduce((total, finding) => total + (finding.exposed?.length || 0), 0);
    },
    async runDefense(finding) {
      const findingId = finding.labId || finding.id;
      this.attackingId = `defense-${findingId}`;
      this.terminalOpen = true;
      this.terminalRunning = true;
      this.terminalMode = "defense";
      this.terminalTitle = `${findingId} / Defender remediation`;
      this.terminalLines = [];
      try {
        await this.typeTerminalLine("Unix Cyber Lab defender shell / remediation preview", "system", 18);
        await this.typeTerminalLine(`defender@${this.nodeIp("defender")} -> target@${this.nodeIp("target")}`, "system", 12);
        await this.typeTerminalLine(`[finding] ${finding.location}`, "warning", 10);
        for (const command of this.defenseScript(finding)) {
          await this.typeTerminalLine(command, "command", 18);
          await this.sleep(260);
        }
        await this.typeTerminalLine(`[expected result] ${finding.recommendation}`, "success", 8);
        await this.typeTerminalLine(
          this.auditReport?.isLabTarget
            ? "[preview only] 保留教學漏洞，未永久修改 Target。"
            : "[preview only] 僅顯示修補建議，未對私人服務執行任何變更。",
          "system",
          10
        );
        this.defenseResults[findingId] = { recommendation: finding.recommendation };
        this.operationMessage = `${findingId} 防禦修補動畫展示完成。`;
      } finally {
        this.attackingId = "";
        this.terminalRunning = false;
      }
    },
    closeTerminal() {
      if (this.terminalRunning) return;
      this.terminalOpen = false;
      this.terminalLines = [];
    },
    async clearEventRecords() {
      this.clearingRecords = true;
      try {
        const response = await fetch("/api/events", { method: "DELETE" });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "clear failed");
        this.events = [];
        this.summary = { byType: {}, alerts: [] };
        this.attackResults = {};
        this.defenseResults = {};
        this.operationMessage = "事件記錄已清除，可重新執行偵測或攻擊產生新日誌。";
        this.clearConfirmOpen = false;
        await this.refreshData();
      } catch (error) {
        this.operationMessage = `清除失敗：${error.message}`;
      } finally {
        this.clearingRecords = false;
      }
    },
    formatTime(value) {
      if (!value) return "";
      return new Date(value).toLocaleTimeString("zh-TW", { hour12: false });
    }
  }
}).mount("#app");
