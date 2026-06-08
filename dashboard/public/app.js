const { createApp } = Vue;

createApp({
  data() {
    return {
      nodes: [],
      events: [],
      summary: { byType: {}, alerts: [] },
      vulnerabilities: [],
      attackResults: {},
      loading: false,
      scanning: false,
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
      } finally {
        this.loading = false;
      }
    },
    async scanVulnerabilities() {
      this.scanning = true;
      this.operationMessage = "正在由 Attacker 探測 Target...";
      this.terminalOpen = true;
      this.terminalRunning = true;
      this.terminalMode = "scan";
      this.terminalTitle = "Vulnerability Discovery / target:8080";
      this.terminalLines = [];
      try {
        await this.typeTerminalLine("Unix Cyber Lab controlled vulnerability scanner", "system", 22);
        await this.typeTerminalLine("attacker@172.28.0.10 -> target@172.28.0.20", "system", 14);
        await this.typeTerminalLine("$ ping -c 1 target", "command", 20);
        await this.typeTerminalLine("64 bytes from target (172.28.0.20): host reachable", "success", 10);
        await this.typeTerminalLine("$ export TARGET=http://target:8080", "command", 18);
        await this.typeTerminalLine("$ for path in /debug /backup/config.bak /admin/export /files/permissions; do curl -s \"$TARGET$path\"; done", "command", 8);
        await this.typeTerminalLine("[analysis] comparing responses with allow-listed vulnerability signatures...", "system", 10);
        const response = await fetch("/api/vulnerabilities/scan");
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "scan failed");
        this.vulnerabilities = data.findings;
        for (const finding of data.findings) {
          await this.typeTerminalLine(`[found] ${finding.id} ${finding.name} (${finding.severity})`, "warning", 10);
          await this.typeTerminalLine(`[evidence] ${finding.evidence}`, "output", 7);
        }
        await this.typeTerminalLine(`[complete] ${data.findings.length} controlled vulnerabilities discovered`, "success", 12);
        this.operationMessage = `偵測完成，發現 ${data.findings.length} 個可測試漏洞。`;
        await this.refreshData();
      } catch (error) {
        await this.typeTerminalLine(`[error] ${error.message}`, "error", 16);
        this.operationMessage = `偵測失敗：${error.message}`;
      } finally {
        this.scanning = false;
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
          "$ curl -s \"$TARGET/files/config\"",
          "$ curl -s \"$TARGET/files/config?mode=<alternate-mode>\""
        ]
      };
      return scripts[vulnerability.id] || [];
    },
    async runAttack(vulnerability) {
      this.attackingId = vulnerability.id;
      this.operationMessage = `正在執行 ${vulnerability.id} 受控攻擊...`;
      this.terminalOpen = true;
      this.terminalRunning = true;
      this.terminalMode = "attack";
      this.terminalTitle = `${vulnerability.id} / ${vulnerability.name}`;
      this.terminalLines = [];
      try {
        await this.typeTerminalLine("Unix Cyber Lab controlled shell", "system", 26);
        await this.typeTerminalLine(`attacker@172.28.0.10 -> target@172.28.0.20`, "system", 16);
        await this.sleep(250);
        for (const command of this.attackScript(vulnerability)) {
          await this.typeTerminalLine(command, "command", 20);
          await this.sleep(320);
        }
        await this.typeTerminalLine("[running allow-listed exploit...]", "system", 14);
        const response = await fetch(`/api/vulnerabilities/${vulnerability.id}/attack`, { method: "POST" });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "attack failed");
        this.attackResults[vulnerability.id] = result;
        await this.typeTerminalLine(result.result, "success", 12);
        await this.typeTerminalLine(`[success] ${result.summary}`, "success", 14);
        await this.typeTerminalLine(`[impact] ${result.impact}`, "warning", 11);
        await this.typeTerminalLine(`[before] ${result.before}`, "output", 12);
        await this.typeTerminalLine(`[after]  ${result.after}`, "success", 12);
        this.operationMessage = `${vulnerability.id} 攻擊劇本執行完成。`;
        await this.refreshData();
      } catch (error) {
        await this.typeTerminalLine(`[error] ${error.message}`, "error", 16);
        this.operationMessage = `攻擊失敗：${error.message}`;
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
