#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HOST = "0.0.0.0"
PORT = 8080
LOG_FILE = "/home/ubuntu/receiver.log"


class WebhookHandler(BaseHTTPRequestHandler):
    def _handle_request(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        text = body.decode("utf-8", errors="replace")
        lines = []

        def log(line=""):
            lines.append(line)
            print(line, flush=True)

        log("\n" + "=" * 72)
        log(f"Received at: {datetime.now(timezone.utc).isoformat()}")
        log(f"From: {self.client_address[0]}:{self.client_address[1]}")
        log(f"Request: {self.command} {self.path}")
        log("Headers:")
        for key, value in self.headers.items():
            log(f"  {key}: {value}")

        log("Payload:")
        try:
            parsed = json.loads(text) if text else None
            log(json.dumps(parsed, indent=2, sort_keys=True))
        except json.JSONDecodeError:
            log(text)

        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write("\n".join(lines) + "\n")

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}\n')

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), WebhookHandler)
    print(f"Webhook receiver listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()
