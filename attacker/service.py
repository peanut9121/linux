import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

TARGET = "http://target:8080"

VULNERABILITIES = [
    {
        "id": "LAB-001",
        "name": "Exposed Debug Information",
        "severity": "medium",
        "path": "/debug",
        "evidence": "debug_mode=true",
        "description": "除錯頁面公開了系統版本與執行環境資訊。",
        "attack": "讀取除錯資訊與教學旗標",
    },
    {
        "id": "LAB-002",
        "name": "Public Backup File",
        "severity": "high",
        "path": "/backup/config.bak",
        "evidence": "backup_password=",
        "description": "備份設定檔可被未登入使用者直接下載。",
        "attack": "下載公開備份檔並查看模擬機密",
    },
    {
        "id": "LAB-003",
        "name": "Unauthenticated Admin Export",
        "severity": "high",
        "path": "/admin/export",
        "evidence": "admin_export=true",
        "description": "管理資料匯出功能缺少身分驗證。",
        "attack": "未登入直接匯出模擬帳號資料",
    },
    {
        "id": "LAB-004",
        "name": "World-Writable Configuration",
        "severity": "medium",
        "path": "/files/permissions",
        "evidence": "mode=0666",
        "description": "服務設定檔允許所有使用者寫入。",
        "attack": "利用錯誤權限修改模擬服務模式",
    },
]


def request_target(path):
    try:
        with urlopen(f"{TARGET}{path}", timeout=4) as response:
            return response.status, response.read().decode("utf-8")
    except HTTPError as error:
        return error.code, error.read().decode("utf-8")
    except URLError as error:
        return 0, str(error.reason)


def scan():
    findings = []
    for vulnerability in VULNERABILITIES:
        status, body = request_target(vulnerability["path"])
        if status == 200 and vulnerability["evidence"] in body:
            findings.append(
                {
                    key: value
                    for key, value in vulnerability.items()
                    if key not in {"path", "evidence"}
                }
                | {"evidence": body.strip()}
            )
    return findings


def attack(vulnerability_id):
    attacks = {
        "LAB-001": "/debug?inspect=full",
        "LAB-002": "/backup/config.bak?download=true",
        "LAB-003": "/admin/export?format=json",
    }
    details = {
        "LAB-001": {
            "summary": "成功取得原本不應公開的 Linux 系統資訊與教學旗標。",
            "impact": "資訊洩漏：攻擊者可利用系統版本、服務名稱與除錯狀態規劃後續行動。",
            "target": "HTTP endpoint /debug",
            "before": "攻擊者尚未持有 Target 的系統資訊。",
            "after": "攻擊者取得 debug_mode、作業系統、服務名稱與旗標。",
        },
        "LAB-002": {
            "summary": "成功下載未受保護的備份設定檔。",
            "impact": "機密資料外洩：備份檔揭露模擬密碼與資料庫名稱。",
            "target": "Backup file /backup/config.bak",
            "before": "攻擊者尚未持有備份設定內容。",
            "after": "攻擊者取得模擬備份密碼與資料庫名稱。",
        },
        "LAB-003": {
            "summary": "未登入管理員帳號，仍成功匯出管理資料。",
            "impact": "存取控制失效：未授權使用者可取得模擬帳號清單。",
            "target": "Admin endpoint /admin/export",
            "before": "攻擊者沒有管理員身分，也沒有使用者清單。",
            "after": "攻擊者未經驗證取得 alice、bob 與 lab-admin 資料。",
        },
        "LAB-004": {
            "summary": "成功利用錯誤檔案權限修改服務設定。",
            "impact": "系統完整性受損：非管理員攻擊者改變了 Target 的服務模式。",
            "target": "Linux file /lab/service.conf",
        },
    }
    if vulnerability_id not in details:
        return None

    if vulnerability_id == "LAB-004":
        _, before_body = request_target("/files/config")
        before_mode = before_body.strip().removeprefix("service_mode=")
        after_mode = "diagnostic" if before_mode == "maintenance" else "maintenance"
        path = f"/files/config?mode={after_mode}"
        details[vulnerability_id]["before"] = f"service_mode={before_mode}"
        details[vulnerability_id]["after"] = f"service_mode={after_mode}"
    else:
        path = attacks[vulnerability_id]

    status, body = request_target(path)
    vulnerability = next(item for item in VULNERABILITIES if item["id"] == vulnerability_id)
    return {
        "id": vulnerability_id,
        "name": vulnerability["name"],
        "success": status == 200,
        "status": status,
        "result": body.strip(),
        "explanation": vulnerability["attack"],
        "action": f"GET {path}",
        **details[vulnerability_id],
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/scan":
            self.send_json(200, {"findings": scan()})
            return

        if self.path.startswith("/attack/"):
            result = attack(self.path.removeprefix("/attack/"))
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
