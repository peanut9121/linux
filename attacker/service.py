import json
import ipaddress
import re
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener, urlopen

DEFAULT_TARGET = "target"
DEFAULT_SCAN_PORTS = "1-9000,25565"
MAX_TARGET_LENGTH = 512
MAX_RESPONSE_BYTES = 256 * 1024

ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

HTTP_SERVICE_NAMES = {
    "http",
    "http-alt",
    "http-proxy",
    "https",
    "https-alt",
    "ssl/http",
    "sun-answerbook",
}

NON_HTTP_SERVICE_NAMES = {
    "domain",
    "ftp",
    "imap",
    "minecraft",
    "ms-wbt-server",
    "mysql",
    "netbios-ssn",
    "pop3",
    "postgresql",
    "redis",
    "rtsp",
    "smtp",
    "ssh",
    "telnet",
}

SECURITY_HEADERS = {
    "content-security-policy": (
        "medium",
        "Content Security Policy is missing",
        "回應未設定 Content-Security-Policy，瀏覽器缺少限制腳本與資源來源的政策。",
        "為正式服務設定符合實際資源需求的 Content-Security-Policy。",
    ),
    "x-content-type-options": (
        "low",
        "MIME sniffing protection is missing",
        "回應未設定 X-Content-Type-Options: nosniff。",
        "加入 X-Content-Type-Options: nosniff。",
    ),
    "referrer-policy": (
        "low",
        "Referrer Policy is missing",
        "回應未設定 Referrer-Policy，導向其他網站時可能送出過多來源資訊。",
        "設定適合服務需求的 Referrer-Policy，例如 strict-origin-when-cross-origin。",
    ),
}

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


def is_allowed_address(address):
    ip = ipaddress.ip_address(address)
    return any(ip in network for network in ALLOWED_NETWORKS)


def resolve_private_addresses(host):
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError("target must be a resolvable private host or IP") from error

    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses or any(not is_allowed_address(address) for address in addresses):
        raise ValueError("public internet targets are not allowed")
    return addresses


def format_url_host(host):
    try:
        return f"[{host}]" if ipaddress.ip_address(host).version == 6 else host
    except ValueError:
        return host


def parse_target(value):
    raw = value.strip()
    if not raw or len(raw) > MAX_TARGET_LENGTH:
        raise ValueError("target is required and must be at most 512 characters")

    if raw.lower() == DEFAULT_TARGET:
        addresses = resolve_private_addresses(DEFAULT_TARGET)
        return {
            "input": raw,
            "host": DEFAULT_TARGET,
            "addresses": addresses,
            "target_ip": addresses[0],
            "scheme": "http",
            "port": 8080,
            "port_explicit": True,
            "path": "/",
            "base_url": "http://target:8080",
            "requested_url": "http://target:8080/",
            "is_lab": True,
        }

    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise ValueError("target contains an invalid port") from error

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials must not be included in the target URL")
    if not parsed.hostname:
        raise ValueError("target must include a host or IP")
    if parsed.fragment:
        raise ValueError("URL fragments are not supported")

    host = parsed.hostname.lower().rstrip(".")
    addresses = resolve_private_addresses(host)
    explicit_port = port is not None
    port = port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    url_host = format_url_host(host)
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = url_host if default_port else f"{url_host}:{port}"
    base_url = f"{scheme}://{authority}"
    requested_url = f"{base_url}{path}"
    if parsed.query:
        requested_url = f"{requested_url}?{parsed.query}"

    return {
        "input": raw,
        "host": host,
        "addresses": addresses,
        "target_ip": addresses[0],
        "scheme": scheme,
        "port": port,
        "port_explicit": explicit_port,
        "path": path,
        "base_url": base_url,
        "requested_url": requested_url,
        "is_lab": False,
    }


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def build_audit_opener():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return build_opener(NoRedirectHandler(), HTTPSHandler(context=context))


AUDIT_OPENER = build_audit_opener()


def request_target(target, path):
    try:
        with urlopen(f"http://{target}:8080{path}", timeout=4) as response:
            return response.status, response.read().decode("utf-8")
    except HTTPError as error:
        return error.code, error.read().decode("utf-8")
    except URLError as error:
        return 0, str(error.reason)


def scan_lab(target):
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


def read_limited(response):
    return response.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")


def response_title(body):
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160] if match else ""


def probe_url(url):
    request = Request(url, headers={"User-Agent": "Unix-Cyber-Lab/1.0", "Accept": "text/html,*/*;q=0.8"})
    try:
        with AUDIT_OPENER.open(request, timeout=6) as response:
            status = response.status
            headers = response.headers
            body = read_limited(response)
    except HTTPError as error:
        status = error.code
        headers = error.headers
        body = read_limited(error)
    except (URLError, TimeoutError, ssl.SSLError, OSError):
        return None

    content_type = headers.get("Content-Type", "")
    if "text/html" not in content_type.lower() and not body.lstrip().lower().startswith(("<!doctype html", "<html")):
        return {
            "url": url,
            "status": status,
            "title": "",
            "content_type": content_type,
            "headers": dict(headers.items()),
            "cookies": headers.get_all("Set-Cookie", []),
        }

    return {
        "url": url,
        "status": status,
        "title": response_title(body),
        "content_type": content_type,
        "headers": dict(headers.items()),
        "cookies": headers.get_all("Set-Cookie", []),
    }


def candidate_urls(target, open_ports):
    urls = [target["requested_url"]]
    if not target["port_explicit"]:
        urls = []
        for item in open_ports:
            service = item["service"].lower()
            port = item["port"]
            if service in NON_HTTP_SERVICE_NAMES:
                continue
            host = format_url_host(target["host"])
            if service in HTTP_SERVICE_NAMES or any(token in service for token in ("http", "ssl")):
                schemes = ["https"] if "https" in service or "ssl" in service or port in {443, 8443} else ["http"]
            else:
                schemes = ["https", "http"] if port in {443, 8443} else ["http", "https"]
            for scheme in schemes:
                default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                urls.append(f"{scheme}://{host}{'' if default_port else f':{port}'}/")
    return list(dict.fromkeys(urls))


def finding(identifier, severity, title, evidence, reason, recommendation, location):
    return {
        "id": identifier,
        "category": "web_security",
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "reason": reason,
        "recommendation": recommendation,
        "source": "passive_http_probe",
        "location": location,
        "actionable": False,
    }


def audit_web_service(service, start_index):
    findings = []
    headers = {key.lower(): value for key, value in service["headers"].items()}
    index = start_index

    for header, (severity, title, reason, recommendation) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(finding(
                f"WEB-{index:03d}", severity, title, f"Missing header: {header}", reason,
                recommendation, service["url"],
            ))
            index += 1

    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(finding(
            f"WEB-{index:03d}", "medium", "Clickjacking protection is missing",
            "Missing X-Frame-Options and CSP frame-ancestors",
            "頁面可能被嵌入其他網站的 iframe，增加 clickjacking 風險。",
            "設定 CSP frame-ancestors 或 X-Frame-Options。", service["url"],
        ))
        index += 1

    server = headers.get("server")
    if server:
        findings.append(finding(
            f"WEB-{index:03d}", "low", "Server software is disclosed",
            f"Server: {server[:160]}", "回應公開伺服器識別資訊，可能協助版本指紋辨識。",
            "移除或最小化 Server header 的版本資訊。", service["url"],
        ))
        index += 1

    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append(finding(
            f"WEB-{index:03d}", "medium", "CORS allows every origin", "Access-Control-Allow-Origin: *",
            "任何來源都可讀取允許跨來源存取的回應；對含敏感資料的 API 可能過度寬鬆。",
            "改用明確可信任來源 allowlist，並逐 endpoint 評估是否需要 CORS。", service["url"],
        ))
        index += 1

    for cookie in service["cookies"]:
        lower_cookie = cookie.lower()
        missing = []
        if "httponly" not in lower_cookie:
            missing.append("HttpOnly")
        if "samesite=" not in lower_cookie:
            missing.append("SameSite")
        if service["url"].startswith("https://") and "secure" not in lower_cookie:
            missing.append("Secure")
        if missing:
            cookie_name = cookie.split("=", 1)[0][:80]
            findings.append(finding(
                f"WEB-{index:03d}", "medium", "Cookie security attributes are incomplete",
                f"Cookie {cookie_name} missing: {', '.join(missing)}",
                "缺少安全屬性的 Cookie 可能增加跨站請求或前端腳本竊取風險。",
                "依部署協定加入 HttpOnly、SameSite，HTTPS Cookie 另加入 Secure。", service["url"],
            ))
            index += 1

    return findings, index


def scan_web(target, open_ports):
    services = []
    findings = []
    next_index = 1
    for url in candidate_urls(target, open_ports):
        service = probe_url(url)
        if not service:
            continue
        services.append(service)
        service_findings, next_index = audit_web_service(service, next_index)
        findings.extend(service_findings)
    return {"mode": "real", "services": services, "findings": findings}


def network_audit(target):
    port_range = str(target["port"]) if target["port_explicit"] else DEFAULT_SCAN_PORTS
    command = ["nmap", "-Pn", "-sV", "-T4", "-p", port_range, "-oX", "-", target["host"]]
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
        "target": target["host"],
        "target_ip": target["target_ip"],
        "command": " ".join(command),
        "open_ports": open_ports,
        "findings": findings,
        "raw_stderr": result.stderr.strip(),
    }


def full_audit(value):
    target = parse_target(value)
    network = network_audit(target)
    if target["is_lab"]:
        probe = {"mode": "lab", "services": [], "findings": scan_lab(DEFAULT_TARGET)}
    else:
        probe = scan_web(target, network["open_ports"])
    return {"target": target, "network": network, "probe": probe}


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
        query = parse_qs(parsed.query, max_num_fields=8)
        target = query.get("target", [DEFAULT_TARGET])[0]
        try:
            target_spec = parse_target(target)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return

        if parsed.path == "/scan":
            if target_spec["is_lab"]:
                self.send_json(200, {"target": target_spec, "mode": "lab", "findings": scan_lab(DEFAULT_TARGET)})
            else:
                self.send_json(400, {"error": "real targets must use the integrated audit endpoint"})
            return

        if parsed.path == "/audit/network":
            self.send_json(200, network_audit(target_spec))
            return

        if parsed.path == "/audit/full":
            try:
                self.send_json(200, full_audit(target))
            except (subprocess.TimeoutExpired, ET.ParseError) as error:
                self.send_json(504, {"error": f"scan failed: {error}"})
            return

        if parsed.path.startswith("/attack/"):
            if not target_spec["is_lab"]:
                self.send_json(403, {"error": "controlled attacks are limited to the lab target"})
                return
            result = attack(DEFAULT_TARGET, parsed.path.removeprefix("/attack/"))
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
