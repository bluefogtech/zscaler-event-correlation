#!/usr/bin/env python3
import argparse
import csv
import html
import json
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO


HOST = "0.0.0.0"
PORT = 8080
LOG_FILE = "/home/ubuntu/receiver.log"
DB_FILE = "/home/ubuntu/alerts.sqlite"
DB_LOCK = threading.Lock()

ALERT_COLUMNS = [
    "id",
    "received_at",
    "source_ip",
    "alert_id",
    "event",
    "alias",
    "alert_type",
    "type",
    "status",
    "severity",
    "rule_name",
    "message",
    "create_time",
    "start_time",
    "impacted_device_count",
    "impacted_user_count",
    "geolocation_count",
    "dept_count",
    "osver_count",
    "zloc_count",
    "criteria_string",
]

DISPLAY_COLUMNS = ["record"] + ALERT_COLUMNS

DB_COLUMNS = [
    "id",
    "received_at",
    "source_ip",
    "source_port",
    "content_type",
    "user_agent",
    "headers_json",
    "raw_payload",
    "payload_json",
    "alert_id",
    "event",
    "alias",
    "alert_type",
    "type",
    "status",
    "severity",
    "rule_name",
    "message",
    "description",
    "text",
    "zdx_url",
    "version",
    "create_time",
    "start_time",
    "impacted_device_count",
    "impacted_user_count",
    "geolocation_count",
    "dept_count",
    "osver_count",
    "zloc_count",
    "criteria_string",
    "criteria_json",
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_int(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def connect_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def create_alerts_table(conn, table_name="webhook_alerts"):
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            source_ip TEXT,
            source_port INTEGER,
            content_type TEXT,
            user_agent TEXT,
            headers_json TEXT NOT NULL,
            raw_payload TEXT,
            payload_json TEXT,
            alert_id TEXT,
            event TEXT,
            alias TEXT,
            alert_type TEXT,
            type TEXT,
            status TEXT,
            severity TEXT,
            rule_name TEXT,
            message TEXT,
            description TEXT,
            text TEXT,
            zdx_url TEXT,
            version TEXT,
            create_time INTEGER,
            start_time INTEGER,
            impacted_device_count INTEGER,
            impacted_user_count INTEGER,
            geolocation_count INTEGER,
            dept_count INTEGER,
            osver_count INTEGER,
            zloc_count INTEGER,
            criteria_string TEXT,
            criteria_json TEXT
        )
        """
    )


def table_columns(conn, table_name):
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")]


def migrate_alerts_table(conn):
    existing_columns = table_columns(conn, "webhook_alerts")
    if not existing_columns:
        create_alerts_table(conn)
        return

    desired_columns = DB_COLUMNS
    if existing_columns == desired_columns:
        return

    conn.execute("ALTER TABLE webhook_alerts RENAME TO webhook_alerts_old")
    create_alerts_table(conn)

    old_columns = table_columns(conn, "webhook_alerts_old")
    columns_to_copy = [column for column in desired_columns if column in old_columns]
    where_clause = "WHERE method = 'POST'" if "method" in old_columns else ""
    if columns_to_copy:
        column_list = ", ".join(columns_to_copy)
        conn.execute(
            f"""
            INSERT INTO webhook_alerts ({column_list})
            SELECT {column_list}
            FROM webhook_alerts_old
            {where_clause}
            """
        )
    conn.execute("DROP TABLE webhook_alerts_old")


def init_db():
    with DB_LOCK:
        with connect_db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            migrate_alerts_table(conn)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_webhook_alerts_received_at "
                "ON webhook_alerts(received_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_webhook_alerts_alert_id "
                "ON webhook_alerts(alert_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_webhook_alerts_status "
                "ON webhook_alerts(status)"
            )


def store_alert(received_at, client_address, headers, raw_payload, parsed):
    payload = parsed if isinstance(parsed, dict) else {}
    payload_json = (
        json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        if parsed is not None
        else None
    )
    criteria = payload.get("criteria")
    criteria_json = (
        json.dumps(criteria, sort_keys=True, separators=(",", ":"))
        if criteria is not None
        else None
    )

    values = {
        "received_at": received_at,
        "source_ip": client_address[0],
        "source_port": client_address[1],
        "content_type": headers.get("content-type"),
        "user_agent": headers.get("user-agent"),
        "headers_json": json.dumps(dict(headers.items()), sort_keys=True),
        "raw_payload": raw_payload,
        "payload_json": payload_json,
        "alert_id": payload.get("alertId"),
        "event": payload.get("event"),
        "alias": payload.get("alias"),
        "alert_type": payload.get("alertType"),
        "type": payload.get("type"),
        "status": payload.get("status"),
        "severity": payload.get("severity"),
        "rule_name": payload.get("ruleName"),
        "message": payload.get("message"),
        "description": payload.get("description"),
        "text": payload.get("text"),
        "zdx_url": payload.get("zdxUrl"),
        "version": payload.get("version"),
        "create_time": parse_int(payload.get("createTime")),
        "start_time": parse_int(payload.get("startTime")),
        "impacted_device_count": parse_int(payload.get("impactedDeviceCount")),
        "impacted_user_count": parse_int(payload.get("impactedUserCount")),
        "geolocation_count": parse_int(payload.get("geolocationCount")),
        "dept_count": parse_int(payload.get("deptCount")),
        "osver_count": parse_int(payload.get("osverCount")),
        "zloc_count": parse_int(payload.get("zloc_count")),
        "criteria_string": payload.get("criteriaString"),
        "criteria_json": criteria_json,
    }

    columns = ", ".join(values.keys())
    placeholders = ", ".join(f":{key}" for key in values)
    with DB_LOCK:
        with connect_db() as conn:
            cursor = conn.execute(
                f"INSERT INTO webhook_alerts ({columns}) VALUES ({placeholders})",
                values,
            )
            return cursor.lastrowid


def get_alert_rows(limit=100):
    with connect_db() as conn:
        return conn.execute(
            f"""
            SELECT {", ".join(ALERT_COLUMNS)}
            FROM webhook_alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def rows_as_dicts(rows):
    return [dict(row) for row in rows]


def numbered_rows(rows):
    return [
        {"record": index, **dict(row)}
        for index, row in enumerate(rows, start=1)
    ]


def render_alert_table(rows):
    display_rows = numbered_rows(rows)
    body = []
    body.append("<!doctype html><html><head><meta charset='utf-8'>")
    body.append("<title>Zscaler alerts</title>")
    body.append(
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:24px;}"
        "table{border-collapse:collapse;width:100%;font-size:13px;}"
        "th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top;}"
        "th{background:#f4f6f8;position:sticky;top:0;}"
        "td{max-width:420px;overflow-wrap:anywhere;}"
        "caption{text-align:left;font-weight:700;margin-bottom:12px;font-size:20px;}"
        "a{color:#0b5cab;}"
        "</style></head><body>"
    )
    body.append("<table><caption>Zscaler alerts</caption><thead><tr>")
    for column in DISPLAY_COLUMNS:
        body.append(f"<th>{html.escape(column)}</th>")
    body.append("</tr></thead><tbody>")
    for row in display_rows:
        body.append("<tr>")
        for column in DISPLAY_COLUMNS:
            value = row[column]
            cell = "" if value is None else html.escape(str(value))
            body.append(f"<td>{cell}</td>")
        body.append("</tr>")
    body.append("</tbody></table></body></html>")
    return "".join(body)


def rows_as_csv(rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=DISPLAY_COLUMNS)
    writer.writeheader()
    for row in numbered_rows(rows):
        writer.writerow({column: row[column] for column in DISPLAY_COLUMNS})
    return output.getvalue()


def print_alerts(limit):
    rows = numbered_rows(get_alert_rows(limit))
    widths = {
        column: max([len(column)] + [len(str(row.get(column, ""))) for row in rows])
        for column in DISPLAY_COLUMNS
    }
    print(" | ".join(column.ljust(widths[column]) for column in DISPLAY_COLUMNS))
    print("-+-".join("-" * widths[column] for column in DISPLAY_COLUMNS))
    for row in rows:
        print(
            " | ".join(
                str(row.get(column, "") or "").replace("\n", " ").ljust(widths[column])
                for column in DISPLAY_COLUMNS
            )
        )


class WebhookHandler(BaseHTTPRequestHandler):
    def _send_bytes(self, status, content_type, body):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_alert_view(self):
        rows = get_alert_rows()
        if self.path == "/alerts.json":
            body = json.dumps(numbered_rows(rows), indent=2).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", body)
            return
        if self.path == "/alerts.csv":
            body = rows_as_csv(rows).encode("utf-8")
            self._send_bytes(200, "text/csv; charset=utf-8", body)
            return
        body = render_alert_table(rows).encode("utf-8")
        self._send_bytes(200, "text/html; charset=utf-8", body)

    def _handle_request(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        text = body.decode("utf-8", errors="replace")
        lines = []
        received_at = utc_now()

        def log(line=""):
            lines.append(line)
            print(line, flush=True)

        log("\n" + "=" * 72)
        log(f"Received at: {received_at}")
        log(f"From: {self.client_address[0]}:{self.client_address[1]}")
        log(f"Request: {self.command} {self.path}")
        log("Headers:")
        for key, value in self.headers.items():
            log(f"  {key}: {value}")

        log("Payload:")
        parsed = None
        try:
            parsed = json.loads(text) if text else None
            log(json.dumps(parsed, indent=2, sort_keys=True))
        except json.JSONDecodeError:
            log(text)

        if self.command == "POST":
            row_id = store_alert(
                received_at,
                self.client_address,
                self.headers,
                text,
                parsed,
            )
            log(f"SQLite row: {row_id}")
        else:
            log("SQLite row: skipped non-POST request")

        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write("\n".join(lines) + "\n")

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}\n')

    def do_GET(self):
        if self.path in ("/alerts", "/alerts.json", "/alerts.csv"):
            self._handle_alert_view()
            return
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
    parser = argparse.ArgumentParser(description="Webhook receiver with SQLite storage")
    parser.add_argument("--list", action="store_true", help="print stored alerts as a table")
    parser.add_argument("--limit", type=int, default=25, help="number of alerts to show")
    args = parser.parse_args()

    init_db()
    if args.list:
        print_alerts(args.limit)
        sys.exit(0)

    server = ThreadingHTTPServer((HOST, PORT), WebhookHandler)
    print(f"Webhook receiver listening on http://{HOST}:{PORT}", flush=True)
    print(f"SQLite storage: {DB_FILE}", flush=True)
    server.serve_forever()
