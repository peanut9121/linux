from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOG_PATH = Path("/var/log/unix-cyber-lab/events.log")


def write_event(event_type, source_ip, detail):
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"{timestamp} type={event_type} source={source_ip} detail={detail}\n"
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(line)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        source_ip = self.client_address[0]

        if parsed.path == "/login":
            query = parse_qs(parsed.query)
            user = query.get("user", ["unknown"])[0]
            result = query.get("result", ["unknown"])[0]
            write_event("login_attempt", source_ip, f"user={user},result={result}")
            self.send_text(200, "login event recorded\n")
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
