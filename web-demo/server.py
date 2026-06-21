from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


INDEX_HTML = """<!doctype html>
<html lang="zh-Hant">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unix Sentinel Web Demo</title>
    <style>
      :root {
        color-scheme: dark;
        --bg: #090d11;
        --panel: #121a22;
        --line: #2a3743;
        --text: #edf5f8;
        --muted: #93a5b2;
        --cyan: #4cc9e8;
        --green: #52d681;
      }
      * { box-sizing: border-box; }
      body {
        min-height: 100vh;
        margin: 0;
        display: grid;
        place-items: center;
        padding: 24px;
        color: var(--text);
        background:
          linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px),
          linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
          var(--bg);
        background-size: 32px 32px;
        font-family: "Trebuchet MS", system-ui, sans-serif;
      }
      main {
        width: min(760px, 100%);
        padding: clamp(24px, 5vw, 52px);
        border: 1px solid var(--line);
        border-top: 4px solid var(--cyan);
        background: rgba(18, 26, 34, .94);
        box-shadow: 0 22px 70px rgba(0,0,0,.42);
      }
      code, small { font-family: Consolas, "Courier New", monospace; }
      small {
        color: var(--cyan);
        text-transform: uppercase;
        letter-spacing: .08em;
      }
      h1 {
        margin: 10px 0 14px;
        font-family: Georgia, serif;
        font-size: clamp(2rem, 6vw, 4rem);
        line-height: 1;
      }
      p {
        max-width: 58ch;
        color: var(--muted);
        font-size: 1.04rem;
        line-height: 1.7;
      }
      .status {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 24px;
      }
      .status code {
        padding: 8px 10px;
        border: 1px solid var(--line);
        border-radius: 6px;
        color: var(--green);
        background: #070a0d;
      }
    </style>
  </head>
  <body>
    <main>
      <small>Linux Web Practice</small>
      <h1>Unix Sentinel Web Demo</h1>
      <p>
        這是一個獨立的 Linux Web 服務，用來測試你的黑箱掃描功能。
        它不是預設漏洞 Target，而是一般網站服務，適合觀察 Nmap 如何偵測開放 Port 與 HTTP 服務。
      </p>
      <div class="status">
        <code>service=web-demo</code>
        <code>port=8080</code>
        <code>status=running</code>
      </div>
    </main>
  </body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in {"/", "/index.html"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"not found\n")

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("web demo listening on 0.0.0.0:8080")
    server.serve_forever()
