from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOG_PATH = Path("/var/log/unix-cyber-lab/events.log")
CONFIG_PATH = Path("/var/log/unix-cyber-lab/service-mode.txt")


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
            self.send_text(200, "debug_mode=true os=linux service=target flag=LAB_DEBUG_VISIBLE\n")
            return

        if parsed.path == "/backup/config.bak":
            write_event("vulnerability_access", source_ip, "id=LAB-002,path=/backup/config.bak")
            if query.get("download") == ["true"]:
                write_event("exploit_success", source_ip, "id=LAB-002,effect=backup_file_downloaded")
            self.send_text(200, "backup_password=training-only-secret database=lab-db\n")
            return

        if parsed.path == "/admin/export":
            write_event("vulnerability_access", source_ip, "id=LAB-003,path=/admin/export")
            if query.get("format") == ["json"]:
                write_event("exploit_success", source_ip, "id=LAB-003,effect=admin_data_exported")
            self.send_text(200, 'admin_export=true users=["alice","bob","lab-admin"]\n')
            return

        if parsed.path == "/files/permissions":
            write_event("vulnerability_access", source_ip, "id=LAB-004,path=/files/permissions")
            self.send_text(200, "file=/lab/service.conf mode=0666 owner=root\n")
            return

        if parsed.path == "/files/config":
            current_mode = CONFIG_PATH.read_text(encoding="utf-8") if CONFIG_PATH.exists() else "normal"
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

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("target service listening on 0.0.0.0:8080")
    server.serve_forever()
