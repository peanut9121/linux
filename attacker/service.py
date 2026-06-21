import json
import ipaddress
import socket
import subprocess
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

DEFAULT_TARGET = "target"

VULNERABILITIES = [
    {
        "id": "LAB-001",
        "name": "Exposed Debug Information",
        "severity": "medium",
        "path": "/debug",
        "evidence": "DEBUG_TOKEN=LAB_DEBUG_VISIBLE",
        "description": "除錯頁面公開了系統版本與執行環境資訊。",
        "attack": "讀取除錯資訊與教學旗標",
        "exposed": [
            {"label": "應用程式", "value": "Application: unix-sentinel-api"},
            {"label": "執行環境", "value": "Environment: production"},
            {"label": "作業系統", "value": "OS: Alpine Linux 3.24"},
            {"label": "後端 Runtime", "value": "Runtime: Python 3.12"},
            {"label": "內部程式路徑", "value": "Internal Path: /srv/unix-sentinel/app/server.py"},
            {"label": "內部 API", "value": "API_BASE_URL=http://internal-api:9000"},
            {"label": "管理端點", "value": "ADMIN_PANEL=/admin/export"},
            {"label": "除錯 Token", "value": "DEBUG_TOKEN=LAB_DEBUG_VISIBLE"},
        ],
        "attacker_value": "讓攻擊者知道正式環境、後端版本、內部路徑、管理端點與除錯 Token。",
    },
    {
        "id": "LAB-002",
        "name": "Public Backup File",
        "severity": "high",
        "path": "/backup/config.bak",
        "evidence": "backup_password=",
        "description": "備份設定檔可被未登入使用者直接下載。",
        "attack": "下載公開備份檔並查看模擬機密",
        "exposed": [
            {"label": "環境", "value": "APP_ENV=production"},
            {"label": "資料庫主機", "value": "DB_HOST=10.0.12.8"},
            {"label": "資料庫 Port", "value": "DB_PORT=5432"},
            {"label": "資料庫名稱", "value": "DB_NAME=lab-db"},
            {"label": "資料庫帳號", "value": "DB_USER=lab_admin"},
            {"label": "備份密碼", "value": "backup_password=training-only-secret"},
            {"label": "JWT 密鑰", "value": "JWT_SECRET=lab-jwt-demo-secret"},
        ],
        "attacker_value": "讓攻擊者拿到資料庫位置、帳號、備份密碼與 JWT 密鑰，可能用於後續登入或偽造請求。",
    },
    {
        "id": "LAB-003",
        "name": "Unauthenticated Admin Export",
        "severity": "high",
        "path": "/admin/export",
        "evidence": "admin_export=true",
        "description": "管理資料匯出功能缺少身分驗證。",
        "attack": "未登入直接匯出模擬帳號資料",
        "exposed": [
            {"label": "匯出狀態", "value": "admin_export=true"},
            {"label": "帳號清單", "value": 'users=["alice","bob","lab-admin"]'},
            {"label": "角色資訊", "value": 'roles={"alice":"analyst","bob":"operator","lab-admin":"administrator"}'},
            {"label": "最後登入來源", "value": "last_login_ip=172.28.0.4"},
            {"label": "匯出範圍", "value": "export_scope=users,roles,last_login"},
        ],
        "attacker_value": "讓攻擊者未登入就取得帳號、角色與登入來源，可用於密碼猜測或社交工程。",
    },
    {
        "id": "LAB-004",
        "name": "World-Writable Configuration",
        "severity": "medium",
        "path": "/files/permissions",
        "evidence": "mode=0666",
        "description": "服務設定檔允許所有使用者寫入。",
        "attack": "利用錯誤權限修改模擬服務模式",
        "exposed": [
            {"label": "設定檔位置", "value": "file=/lab/service.conf"},
            {"label": "錯誤權限", "value": "mode=0666"},
            {"label": "擁有者", "value": "owner=root"},
            {"label": "群組", "value": "group=root"},
            {"label": "目前設定", "value": "current_value=service_mode=normal"},
            {"label": "風險", "value": "risk=any local user can overwrite service configuration"},
        ],
        "attacker_value": "讓攻擊者知道哪個設定檔可被覆寫，以及目前服務模式，可用來改變系統行為。",
    },
]


def resolve_allowed_target(value):
    target = value.strip().lower()
    if target == "target":
        return target, socket.gethostbyname(target)
    try:
        address = socket.gethostbyname(target)
        ip = ipaddress.ip_address(address)
    except (socket.gaierror, ValueError):
        raise ValueError("target must be a resolvable private host or IP")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ValueError("public internet targets are not allowed")
    return target, address


def request_target(target, path):
    try:
        with urlopen(f"http://{target}:8080{path}", timeout=4) as response:
            return response.status, response.read().decode("utf-8")
    except HTTPError as error:
        return error.code, error.read().decode("utf-8")
    except URLError as error:
        return 0, str(error.reason)


def scan(target):
    findings = []
    for vulnerability in VULNERABILITIES:
        status, body = request_target(target, vulnerability["path"])
        if status == 200 and vulnerability["evidence"] in body:
            findings.append(
                {
                    key: value
                    for key, value in vulnerability.items()
                    if key != "evidence"
                }
                | {"evidence": body.strip()}
            )
    return findings


def network_audit(target):
    _, target_ip = resolve_allowed_target(target)
    command = ["nmap", "-sV", "-T4", "-p", "1-9000", "-oX", "-", target]
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
    open_ports = []
    if result.stdout:
        root = ET.fromstring(result.stdout)
        for port in root.findall(".//port"):
            state = port.find("state")
            service = port.find("service")
            if state is not None and state.get("state") == "open":
                open_ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                })
    findings = [
        {
            "category": "network_exposure",
            "severity": "medium",
            "title": "Open network port discovered",
            "evidence": f"{item['port']}/{item['protocol']} {item['service']} {item['product']} {item['version']}".strip(),
            "reason": "遠端主機正在提供可連線服務，應確認這個服務是否必要且已安全設定。",
            "recommendation": "確認服務版本與用途，移除不必要服務並限制網路存取。",
        }
        for item in open_ports
    ]
    return {
        "scanner": "nmap",
        "target": target,
        "target_ip": target_ip,
        "command": " ".join(command),
        "open_ports": open_ports,
        "findings": findings,
        "raw_stderr": result.stderr.strip(),
    }


def attack(target, vulnerability_id):
    attacks = {
        "LAB-001": "/debug?inspect=full",
        "LAB-002": "/backup/config.bak?download=true",
        "LAB-003": "/admin/export?format=json",
    }
    details = {
        "LAB-001": {
            "summary": "成功取得正式環境除錯頁洩漏的系統設定與內部路徑。",
            "impact": "資訊洩漏：攻擊者可利用後端版本、內部 API、管理端點與除錯 Token 規劃後續行動。",
            "target": "HTTP endpoint /debug",
            "before": "攻擊者只知道 8080 port 有 HTTP 服務。",
            "after": "攻擊者取得 production 環境、Runtime、內部路徑、管理端點與 DEBUG_TOKEN。",
        },
        "LAB-002": {
            "summary": "成功下載未受保護的備份設定檔。",
            "impact": "機密資料外洩：備份檔揭露資料庫主機、帳號、備份密碼與 JWT 密鑰。",
            "target": "Backup file /backup/config.bak",
            "before": "攻擊者尚未持有備份設定內容。",
            "after": "攻擊者取得 DB_HOST、DB_USER、backup_password 與 JWT_SECRET。",
        },
        "LAB-003": {
            "summary": "未登入管理員帳號，仍成功匯出管理資料。",
            "impact": "存取控制失效：未授權使用者可取得帳號、角色與最後登入來源。",
            "target": "Admin endpoint /admin/export",
            "before": "攻擊者沒有管理員身分，也沒有使用者清單。",
            "after": "攻擊者未經驗證取得 alice、bob、lab-admin、角色與 last_login_ip。",
        },
        "LAB-004": {
            "summary": "成功利用錯誤檔案權限修改服務設定。",
            "impact": "系統完整性受損：攻擊者利用錯誤權限改變 Target 的服務模式。",
            "target": "Linux file /lab/service.conf",
        },
    }
    if vulnerability_id not in details:
        return None

    if vulnerability_id == "LAB-004":
        _, before_body = request_target(target, "/files/config")
        before_mode = before_body.strip().removeprefix("service_mode=")
        after_mode = "diagnostic" if before_mode == "maintenance" else "maintenance"
        path = f"/files/config?mode={after_mode}"
        details[vulnerability_id]["before"] = f"service_mode={before_mode}"
        details[vulnerability_id]["after"] = f"service_mode={after_mode}"
    else:
        path = attacks[vulnerability_id]

    status, body = request_target(target, path)
    vulnerability = next(item for item in VULNERABILITIES if item["id"] == vulnerability_id)
    return {
        "id": vulnerability_id,
        "name": vulnerability["name"],
        "success": status == 200,
        "status": status,
        "result": body.strip(),
        "exposed": vulnerability.get("exposed", []),
        "attacker_value": vulnerability.get("attacker_value", ""),
        "explanation": vulnerability["attack"],
        "action": f"GET {path}",
        **details[vulnerability_id],
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        target = query.get("target", [DEFAULT_TARGET])[0]
        try:
            target, target_ip = resolve_allowed_target(target)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return

        if parsed.path == "/scan":
            self.send_json(200, {"target": target, "target_ip": target_ip, "findings": scan(target)})
            return

        if parsed.path == "/audit/network":
            self.send_json(200, network_audit(target))
            return

        if parsed.path.startswith("/attack/"):
            if target != DEFAULT_TARGET and target_ip != socket.gethostbyname(DEFAULT_TARGET):
                self.send_json(403, {"error": "controlled attacks are limited to the lab target"})
                return
            result = attack(target, parsed.path.removeprefix("/attack/"))
            if result is None:
                self.send_json(404, {"error": "attack script is not allow-listed"})
                return
            self.send_json(200, result)
            return

        self.send_json(200, {"service": "controlled attacker", "status": "ready"})

    def send_json(self, status, data):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8090), Handler)
    print("controlled attacker listening on 0.0.0.0:8090")
    server.serve_forever()
