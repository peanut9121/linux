import json
import os
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOG_PATH = Path("/var/log/unix-cyber-lab/events.log")
CONFIG_PATH = Path("/lab/service.conf")
AUDIT_TOKEN = os.environ.get("AUDIT_TOKEN", "")


def run_readonly(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    return {
        "command": " ".join(command),
        "exit_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def collect_system_audit():
    commands = {
        "kernel": ["uname", "-a"],
        "identity": ["id"],
        "processes": ["ps", "-eo", "pid,user,comm,args"],
        "listening_ports": ["ss", "-lntup"],
        "world_writable_files": [
            "find", "/lab", "/etc", "/opt", "/srv",
            "-xdev", "-type", "f", "-perm", "-0002",
            "-printf", "%m %u:%g %p\n",
        ],
        "suid_files": [
            "find", "/lab", "/etc", "/opt", "/srv",
            "-xdev", "-type", "f", "-perm", "-4000",
            "-printf", "%m %u:%g %p\n",
        ],
    }
    results = {name: run_readonly(command) for name, command in commands.items()}
    os_release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')

    findings = []
    writable_lines = [line for line in results["world_writable_files"]["stdout"].splitlines() if line]
    for line in writable_lines:
        findings.append({
            "category": "file_permissions",
            "severity": "high",
            "title": "World-writable file discovered",
            "evidence": line,
            "reason": "任何本機使用者都能修改這個檔案，可能破壞服務設定或系統完整性。",
            "recommendation": "確認檔案用途，並使用 chmod/chown 限制為服務擁有者可寫入。",
        })

    listening_lines = [
        line for line in results["listening_ports"]["stdout"].splitlines()
        if line and "LISTEN" in line and "0.0.0.0:" in line and "127.0.0.11:" not in line
    ]
    for line in listening_lines:
        findings.append({
            "category": "network_exposure",
            "severity": "medium",
            "title": "Listening network service discovered",
            "evidence": line,
            "reason": "監聽中的服務會增加主機攻擊面，應確認是否為必要服務。",
            "recommendation": "確認服務用途；若非必要，關閉服務或使用防火牆限制來源。",
        })

    return {
        "collector": "authorized-readonly-agent",
        "hostname": os.uname().nodename,
        "os": os_release,
        "commands": results,
        "findings": findings,
        "score": max(0, 100 - sum(20 if item["severity"] == "high" else 8 for item in findings)),
    }


def write_event(event_type, source_ip, detail):
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"{timestamp} type={event_type} source={source_ip} detail={detail}\n"
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(line)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        source_ip = self.client_address[0]

        if parsed.path == "/audit/system":
            if not AUDIT_TOKEN or self.headers.get("X-Audit-Token") != AUDIT_TOKEN:
                self.send_json(403, {"error": "authorized audit token required"})
                return
            write_event("security_audit", source_ip, "scope=system,mode=readonly")
            self.send_json(200, collect_system_audit())
            return

        if parsed.path == "/login":
            user = query.get("user", ["unknown"])[0]
            result = query.get("result", ["unknown"])[0]
            write_event("login_attempt", source_ip, f"user={user},result={result}")
            self.send_text(200, "login event recorded\n")
            return

        if parsed.path == "/debug":
            write_event("vulnerability_access", source_ip, "id=LAB-001,path=/debug")
            if query.get("inspect") == ["full"]:
                write_event("exploit_success", source_ip, "id=LAB-001,effect=debug_information_disclosed")
            self.send_text(200, "\n".join([
                "DEBUG MODE ENABLED",
                "Application: unix-sentinel-api",
                "Environment: production",
                "OS: Alpine Linux 3.24",
                "Runtime: Python 3.12",
                "Server: BaseHTTPServer 0.6",
                "Internal Path: /srv/unix-sentinel/app/server.py",
                "API_BASE_URL=http://internal-api:9000",
                "ADMIN_PANEL=/admin/export",
                "DEBUG_TOKEN=LAB_DEBUG_VISIBLE",
                "",
            ]))
            return

        if parsed.path == "/backup/config.bak":
            write_event("vulnerability_access", source_ip, "id=LAB-002,path=/backup/config.bak")
            if query.get("download") == ["true"]:
                write_event("exploit_success", source_ip, "id=LAB-002,effect=backup_file_downloaded")
            self.send_text(200, "\n".join([
                "# config.bak - copied from /srv/unix-sentinel/.env",
                "APP_ENV=production",
                "DB_HOST=10.0.12.8",
                "DB_PORT=5432",
                "DB_NAME=lab-db",
                "DB_USER=lab_admin",
                "backup_password=training-only-secret",
                "JWT_SECRET=lab-jwt-demo-secret",
                "",
            ]))
            return

        if parsed.path == "/admin/export":
            write_event("vulnerability_access", source_ip, "id=LAB-003,path=/admin/export")
            if query.get("format") == ["json"]:
                write_event("exploit_success", source_ip, "id=LAB-003,effect=admin_data_exported")
            self.send_text(200, "\n".join([
                "admin_export=true",
                'users=["alice","bob","lab-admin"]',
                'roles={"alice":"analyst","bob":"operator","lab-admin":"administrator"}',
                "last_login_ip=172.28.0.4",
                "export_scope=users,roles,last_login",
                "",
            ]))
            return

        if parsed.path == "/files/permissions":
            write_event("vulnerability_access", source_ip, "id=LAB-004,path=/files/permissions")
            self.send_text(200, "\n".join([
                "file=/lab/service.conf",
                "mode=0666",
                "owner=root",
                "group=root",
                "current_value=service_mode=normal",
                "risk=any local user can overwrite service configuration",
                "",
            ]))
            return

        if parsed.path == "/files/config":
            current_mode = CONFIG_PATH.read_text(encoding="utf-8").strip() if CONFIG_PATH.exists() else "normal"
            if "mode" not in query:
                self.send_text(200, f"service_mode={current_mode}\n")
                return
            mode = query["mode"][0]
            CONFIG_PATH.write_text(mode, encoding="utf-8")
            write_event("configuration_changed", source_ip, f"file=/lab/service.conf,before={current_mode},after={mode}")
            write_event("exploit_success", source_ip, "id=LAB-004,effect=service_configuration_modified")
            self.send_text(200, f"configuration changed: before={current_mode} after={mode}\n")
            return

        write_event("http_request", source_ip, f"path={parsed.path}")
        self.send_text(200, "target service is running\n")

    def send_text(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

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
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("target service listening on 0.0.0.0:8080")
    server.serve_forever()
