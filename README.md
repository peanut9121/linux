# Unix Cyber Lab

基於 WSL2 的 UNIX/Linux 虛擬網路攻防實務與 AI 輔助監控平台。

本專題核心是 UNIX 應用與實務：Shell Script、自動化管理、網路設定、程序監控、權限控管、系統日誌收集與事件分析。資安情境用來呈現 Linux 系統在多節點網路中的實際運作，AI 則作為輔助分析與解釋工具。

## 第一階段目標

建立一個可在 WSL2 中啟動的最小虛擬實驗室：

- `attacker`: 執行受控測試腳本，並提供白名單漏洞偵測與攻擊劇本。
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

# 在 Dashboard 中按下「偵測漏洞」
# 再選擇個別漏洞執行受控攻擊並查看結果

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
- 真實目標只允許 RFC1918、localhost、link-local、ULA 與 Tailscale `100.64.0.0/10` 位址，公開 IP 會被拒絕。
- 真實私人服務只執行 Nmap 與被動 HTTP 安全檢查，不執行修改資料、fuzzing 或漏洞利用。
- 漏洞偵測與攻擊只允許執行內建白名單劇本。
- AI 只分析與解釋 log，不直接執行攻擊指令。
- 第一階段先做可觀察、可紀錄、可展示的受控事件。

## 私人網頁安全稽核

Dashboard 接受私人 IP、主機名稱、`IP:port` 或完整 HTTP/HTTPS URL：

```text
192.168.1.20
192.168.1.20:3000
http://192.168.1.20:3000
https://nas.local:8443
http://100.107.82.7:8787
```

有指定 Port 時只掃描該 Port；只輸入主機時使用 Nmap 探索 `1-9000,25565`。系統會辨識實際 Web URL，檢查安全 headers、clickjacking 防護、CORS、Cookie 屬性與伺服器資訊洩漏。Redirect 不會自動跟隨，避免掃描越過已授權目標。

`target` 保留為 Lab Mode，只有這個模式可以執行 `LAB-001` 至 `LAB-004` 白名單攻擊展示。其他私人目標一律為 Real Web Mode，攻擊按鈕會停用。

## 受控漏洞情境

| ID | 漏洞 | 可觀察結果 |
|---|---|---|
| LAB-001 | 暴露的 Debug 資訊 | 讀取系統資訊與教學旗標 |
| LAB-002 | 公開備份檔 | 查看模擬備份機密 |
| LAB-003 | 未驗證管理匯出 | 匯出模擬帳號資料 |
| LAB-004 | 所有人可寫入的設定檔 | 修改模擬服務模式並觸發完整性告警 |

## 通用 Linux 安全稽核

Dashboard 的 `Linux Security Audit` 不使用預設漏洞路徑清單，而是執行真實的唯讀檢查：

```bash
nmap -sV -p 1-9000,25565 target
uname -a
id
ps -eo pid,user,comm,args
ss -lntup
find /lab /etc /opt /srv -xdev -type f -perm -0002
find /lab /etc /opt /srv -xdev -type f -perm -4000
```

系統會從指令輸出產生通用安全發現，例如未知開放 Port、所有人可寫入的檔案與 SUID 檔案。Target 的系統 Collector 使用 `X-Audit-Token` 授權，且只允許執行程式內建的唯讀檢查。

## 整合攻防流程

Dashboard 目前只有一個主要入口「偵測漏洞與攻擊面」。執行後會合併：

- Nmap 遠端 Port 與服務探索
- Target 授權唯讀 UNIX Collector
- Attacker 主動 HTTP 漏洞探測

每個發現都會顯示動態 Target IP、Port、檔案或 URL 位置。可利用的 HTTP 漏洞會直接提供受控攻擊動畫，所有發現則提供防禦修補指令動畫。防禦動畫為預覽模式，不會永久關閉教學漏洞。

Dashboard 的分析工作台可輸入 Docker Lab 服務名稱、私人 IP、`IP:port` 或完整私人 URL。系統會拒絕公開網際網路 IP。只有輸入 `target` 時會額外啟用授權 UNIX Collector 與受控攻擊展示；其他私人主機只執行 Nmap 與被動 HTTP 安全檢查。

## 動態節點 IP

Docker 會自動分配 Lab 內各節點的 IP。Dashboard 透過 Docker DNS 即時解析 `attacker`、`target`、`defender` 與 `dashboard`，並標示 IP 來源為 `dynamic`。

目前原始固定 IP 保留為解析失敗時的 fallback：

```text
attacker  172.28.0.10
target    172.28.0.20
defender  172.28.0.30
dashboard 172.28.0.40
```
