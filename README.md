# Unix Cyber Lab

基於 WSL2 的 UNIX/Linux 虛擬網路攻防實務與 AI 輔助監控平台。

本專題核心是 UNIX 應用與實務：Shell Script、自動化管理、網路設定、程序監控、權限控管、系統日誌收集與事件分析。資安情境用來呈現 Linux 系統在多節點網路中的實際運作，AI 則作為輔助分析與解釋工具。

## 第一階段目標

建立一個可在 WSL2 中啟動的最小虛擬實驗室：

- `attacker`: 執行受控測試腳本，模擬連線與登入失敗事件。
- `target`: Linux 靶機，提供簡單 Web service 並產生日誌。
- `defender`: 收集與分析事件，輸出初步告警。
- `dashboard`: Vue Web Dashboard，呈現拓撲、事件與告警。
- `lab_net`: Docker bridge network，隔離實驗網路。

## 建議操作流程

在 WSL2 Ubuntu 中執行：

```bash
cd /path/to/unix-cyber-lab

# 啟動實驗室
./scripts/start_lab.sh

# 檢查節點狀態
./scripts/status.sh

# 執行受控事件模擬
./scripts/run_attack_demo.sh

# 開啟 Vue Dashboard
# http://localhost:3000

# 停止實驗室
./scripts/stop_lab.sh
```

## 專案結構

```text
.
├── docker-compose.yml
├── README.md
├── attacker/
│   ├── Dockerfile
│   └── scripts/
│       └── attack_demo.sh
├── target/
│   ├── Dockerfile
│   └── app/
│       └── server.py
├── defender/
│   ├── Dockerfile
│   └── analyzer.py
├── dashboard/
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── public/
│       ├── index.html
│       ├── app.js
│       └── styles.css
└── scripts/
    ├── start_lab.sh
    ├── stop_lab.sh
    ├── status.sh
    └── run_attack_demo.sh
```

## 安全原則

- 所有模擬都限制在 Docker isolated network。
- 攻擊端只連線到 `target` 容器，不掃描外部 IP。
- AI 只分析與解釋 log，不直接執行攻擊指令。
- 第一階段先做可觀察、可紀錄、可展示的受控事件。
