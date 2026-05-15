#!/usr/bin/env python3
import argparse
import base64
import csv
import html
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO


HOST = "0.0.0.0"
PORT = 8080
LOG_FILE = "/home/ubuntu/receiver.log"
PROJECT_WEBHOOK_PATH = "/project-webhook"
PROJECT_WEBHOOK_LOG_FILE = "/home/ubuntu/project_webhook.log"
DB_FILE = "/home/ubuntu/alerts.sqlite"
CLICKHOUSE_HOST = os.environ.get(
    "CLICKHOUSE_HOST", "dz6sj5iq7e.us-central1.gcp.clickhouse.cloud"
)
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8443"))
CLICKHOUSE_SECURE = os.environ.get("CLICKHOUSE_SECURE", "1").lower() not in (
    "0",
    "false",
    "no",
)
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "Fk4A_L83MRlsw")
CLICKHOUSE_HTTP_URL = os.environ.get(
    "CLICKHOUSE_HTTP_URL",
    f"{'https' if CLICKHOUSE_SECURE else 'http'}://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/",
)
CLICKHOUSE_ALERT_PAYLOADS_TABLE = os.environ.get(
    "CLICKHOUSE_ALERT_PAYLOADS_TABLE", "aiops.alert_payloads"
)
CLICKHOUSE_TIMEOUT_SECONDS = 5
ZSCALER_TOKEN_URL = "https://esoczscalerlab.zslogin.net/oauth2/v1/token"
ZSCALER_API_BASE_URL = "https://api.zsapi.net/zdx/v1"
ZSCALER_CLIENT_ID = "102qek806d50626"
ZSCALER_CLIENT_SECRET = "jQFIy4vURXP2mFznP8W3RPM31zT8N5E0jAxdx3jbkdsgCbM"
ZSCALER_TOKEN_FILE = "/home/ubuntu/zscaler_bearer_token.txt"
ZSCALER_ENRICHMENT_RETRY_DELAYS = (5, 15, 30)
DB_LOCK = threading.Lock()
PROJECT_WEBHOOK_LOG_LOCK = threading.Lock()
CLICKHOUSE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")

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
    "location",
    "device_name",
    "user_name",
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

FORTINET_COLUMNS = [
    "id",
    "received_at",
    "source_ip",
    "adom",
    "from_device",
    "type",
    "timestamp",
    "alertid",
    "alerttime",
    "severity",
    "triggername",
    "subject",
    "devid",
    "devname",
    "devtype",
    "eventtype",
    "subtype",
    "logtype",
    "extrainfo",
    "vdom",
    "logcount",
    "readflag",
    "ackflag",
    "log_detail",
]

FORTINET_DISPLAY_COLUMNS = ["record"] + FORTINET_COLUMNS

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
    "location",
    "device_name",
    "user_name",
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

FORTINET_DB_COLUMNS = [
    "id",
    "received_at",
    "source_ip",
    "source_port",
    "content_type",
    "user_agent",
    "headers_json",
    "raw_payload",
    "payload_json",
    "notification_json",
    "alert_json",
    "adom",
    "apiver",
    "from_device",
    "timestamp",
    "type",
    "ackflag",
    "alertid",
    "alerttime",
    "devid",
    "devname",
    "devtype",
    "ephostname",
    "epid",
    "epip",
    "epmac",
    "epname",
    "eposname",
    "eposversion",
    "euid",
    "euname",
    "eventtype",
    "extrainfo",
    "fctuid",
    "firstlogtime",
    "groupby1",
    "groupby2",
    "groupby3",
    "indicator",
    "lastlogtime",
    "log_detail",
    "log_length",
    "logcount",
    "logtype",
    "readflag",
    "severity",
    "subject",
    "subtype",
    "tag",
    "triggername",
    "vdom",
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


def validate_clickhouse_table_name(table_name):
    if not CLICKHOUSE_IDENTIFIER_RE.fullmatch(table_name):
        raise ValueError(f"Invalid ClickHouse table name: {table_name}")
    return table_name


def clickhouse_request(query, data=None):
    url = (
        CLICKHOUSE_HTTP_URL.rstrip("/")
        + "/?query="
        + urllib.parse.quote(query, safe="")
    )
    body = data.encode("utf-8") if data is not None else b""
    headers = {}
    if CLICKHOUSE_USER or CLICKHOUSE_PASSWORD:
        credentials = f"{CLICKHOUSE_USER}:{CLICKHOUSE_PASSWORD}".encode("utf-8")
        headers["Authorization"] = (
            "Basic " + base64.b64encode(credentials).decode("ascii")
        )
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(
        request, timeout=CLICKHOUSE_TIMEOUT_SECONDS
    ) as response:
        return response.read().decode("utf-8", errors="replace")


def log_clickhouse_error(message):
    line = f"{utc_now()} ClickHouse error: {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(line + "\n")


def init_clickhouse():
    table_name = validate_clickhouse_table_name(CLICKHOUSE_ALERT_PAYLOADS_TABLE)
    clickhouse_request(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            payload_json Nullable(String),
            payload_type LowCardinality(String)
        )
        ENGINE = MergeTree
        ORDER BY tuple()
        """
    )
    try:
        clickhouse_request(
            f"ALTER TABLE {table_name} RENAME COLUMN payload_tyoe TO payload_type"
        )
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        pass


def insert_clickhouse_alert_payloads(payload_json, payload_type, count=1):
    if count <= 0:
        return
    table_name = validate_clickhouse_table_name(CLICKHOUSE_ALERT_PAYLOADS_TABLE)
    rows = [
        json.dumps(
            {"payload_json": payload_json, "payload_type": payload_type},
            separators=(",", ":"),
        )
        for _ in range(count)
    ]
    clickhouse_request(
        f"INSERT INTO {table_name} (payload_json, payload_type) FORMAT JSONEachRow",
        "\n".join(rows) + "\n",
    )


def store_clickhouse_alert_payload(payload_json, payload_type, count=1):
    try:
        insert_clickhouse_alert_payloads(payload_json, payload_type, count)
    except (ValueError, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        log_clickhouse_error(
            f"failed to insert {count} {payload_type} row(s): {error}"
        )


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
            location TEXT,
            device_name TEXT,
            user_name TEXT,
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


def create_fortinet_table(conn, table_name="fortinet_alerts"):
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
            notification_json TEXT NOT NULL,
            alert_json TEXT NOT NULL,
            adom TEXT,
            apiver INTEGER,
            from_device TEXT,
            timestamp INTEGER,
            type TEXT,
            ackflag TEXT,
            alertid TEXT,
            alerttime TEXT,
            devid TEXT,
            devname TEXT,
            devtype TEXT,
            ephostname TEXT,
            epid TEXT,
            epip TEXT,
            epmac TEXT,
            epname TEXT,
            eposname TEXT,
            eposversion TEXT,
            euid TEXT,
            euname TEXT,
            eventtype TEXT,
            extrainfo TEXT,
            fctuid TEXT,
            firstlogtime TEXT,
            groupby1 TEXT,
            groupby2 TEXT,
            groupby3 TEXT,
            indicator TEXT,
            lastlogtime TEXT,
            log_detail TEXT,
            log_length INTEGER,
            logcount TEXT,
            logtype TEXT,
            readflag TEXT,
            severity TEXT,
            subject TEXT,
            subtype TEXT,
            tag TEXT,
            triggername TEXT,
            vdom TEXT
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


def migrate_fortinet_table(conn):
    existing_columns = table_columns(conn, "fortinet_alerts")
    if not existing_columns:
        create_fortinet_table(conn)
        return

    if existing_columns == FORTINET_DB_COLUMNS:
        return

    conn.execute("ALTER TABLE fortinet_alerts RENAME TO fortinet_alerts_old")
    create_fortinet_table(conn)

    old_columns = table_columns(conn, "fortinet_alerts_old")
    columns_to_copy = [
        column for column in FORTINET_DB_COLUMNS if column in old_columns
    ]
    if columns_to_copy:
        column_list = ", ".join(columns_to_copy)
        conn.execute(
            f"""
            INSERT INTO fortinet_alerts ({column_list})
            SELECT {column_list}
            FROM fortinet_alerts_old
            """
        )
    conn.execute("DROP TABLE fortinet_alerts_old")


def init_db():
    with DB_LOCK:
        with connect_db() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            migrate_alerts_table(conn)
            migrate_fortinet_table(conn)
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fortinet_alerts_received_at "
                "ON fortinet_alerts(received_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fortinet_alerts_alertid "
                "ON fortinet_alerts(alertid)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_fortinet_alerts_severity "
                "ON fortinet_alerts(severity)"
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
        "alert_id": get_payload_alert_id(payload),
        "event": payload.get("event"),
        "alias": payload.get("alias"),
        "alert_type": payload.get("alertType") or payload.get("alert_type"),
        "type": payload.get("type"),
        "status": payload.get("status") or payload.get("alert_status"),
        "severity": payload.get("severity"),
        "rule_name": payload.get("ruleName") or payload.get("rule_name"),
        "location": payload.get("location"),
        "device_name": payload.get("deviceName"),
        "user_name": payload.get("userName"),
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
            row_id = cursor.lastrowid
    store_clickhouse_alert_payload(payload_json, "zscaler payload")
    return row_id


def request_zscaler_bearer_token():
    form_data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": ZSCALER_CLIENT_ID,
            "client_secret": ZSCALER_CLIENT_SECRET,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        ZSCALER_TOKEN_URL,
        data=form_data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        response_body = response.read().decode("utf-8", errors="replace")

    try:
        token_response = json.loads(response_body)
    except json.JSONDecodeError:
        token_response = {"raw_response": response_body}

    token = (
        token_response.get("access_token")
        or token_response.get("token")
        or token_response.get("bearer_token")
    )
    if not token:
        raise RuntimeError("Zscaler token response did not include a bearer token")

    fd = os.open(
        ZSCALER_TOKEN_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(token + "\n")

    return token_response


def get_stored_zscaler_bearer_token():
    try:
        with open(ZSCALER_TOKEN_FILE, "r", encoding="utf-8") as file:
            token = file.read().strip()
    except FileNotFoundError:
        return None
    return token or None


def extract_zscaler_token(token_response):
    return (
        token_response.get("access_token")
        or token_response.get("token")
        or token_response.get("bearer_token")
    )


def get_zscaler_bearer_token():
    token = get_stored_zscaler_bearer_token()
    if token:
        return token
    return extract_zscaler_token(request_zscaler_bearer_token())


def zscaler_api_get(path, token):
    request = urllib.request.Request(
        f"{ZSCALER_API_BASE_URL}{path}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        response_body = response.read().decode("utf-8", errors="replace")
    try:
        return json.loads(response_body) if response_body else {}
    except json.JSONDecodeError:
        return {"raw_response": response_body}


def zscaler_api_get_with_refresh(path):
    token = get_zscaler_bearer_token()
    try:
        return zscaler_api_get(path, token)
    except urllib.error.HTTPError as error:
        if error.code not in (401, 403):
            raise
        token = extract_zscaler_token(request_zscaler_bearer_token())
        return zscaler_api_get(path, token)


def get_payload_alert_id(payload):
    if not isinstance(payload, dict):
        return None
    return payload.get("alertId") or payload.get("alert_id") or payload.get("id")


def enrich_zscaler_alert_payload(payload):
    if not isinstance(payload, dict):
        return None

    alert_id = get_payload_alert_id(payload)
    if alert_id in (None, ""):
        raise RuntimeError("Zscaler alert payload did not include an alert id")

    alert_detail = zscaler_api_get_with_refresh(f"/alerts/{alert_id}")
    locations = alert_detail.get("locations") if isinstance(alert_detail, dict) else None
    if isinstance(locations, list) and locations:
        first_location = locations[0]
        if isinstance(first_location, dict):
            payload["location"] = first_location.get("name")

    affected_devices = zscaler_api_get_with_refresh(
        f"/alerts/{alert_id}/affected_devices"
    )
    devices = (
        affected_devices.get("devices")
        if isinstance(affected_devices, dict)
        else None
    )
    if isinstance(devices, list) and devices:
        first_device = devices[0]
        if isinstance(first_device, dict):
            payload["deviceName"] = first_device.get("name")
            payload["userName"] = first_device.get("userName")

    return {
        "alert_id": alert_id,
        "location": payload.get("location"),
        "device_name": payload.get("deviceName"),
        "user_name": payload.get("userName"),
    }


def is_retryable_zscaler_enrichment_error(error):
    if isinstance(error, TimeoutError):
        return True
    if isinstance(error, urllib.error.URLError):
        return True
    if isinstance(error, urllib.error.HTTPError):
        if error.code in (408, 409, 425, 429, 500, 502, 503, 504):
            return True
        if error.code == 400:
            body = error.read().decode("utf-8", errors="replace")
            error.enrichment_body = body
            return "Provided Alert ID not valid or more than 14 days old" in body
    return False


def enrich_zscaler_alert_payload_with_retry(payload, log):
    delays = (0,) + ZSCALER_ENRICHMENT_RETRY_DELAYS
    last_error = None
    for attempt, delay in enumerate(delays, start=1):
        if delay:
            time.sleep(delay)
        try:
            return enrich_zscaler_alert_payload(payload)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if not is_retryable_zscaler_enrichment_error(error):
                raise
            if attempt == len(delays):
                break
            log(
                "Zscaler alert enrichment retrying: "
                f"attempt={attempt}, next_delay_seconds={delays[attempt]}"
            )
    if last_error is not None:
        raise last_error
    return None


def get_fortinet_notification(parsed):
    if not isinstance(parsed, dict):
        return None
    notification = parsed.get("fortianalyzer_notification")
    return notification if isinstance(notification, dict) else None


def store_fortinet_alerts(received_at, client_address, headers, raw_payload, parsed):
    notification = get_fortinet_notification(parsed)
    if notification is None:
        return []

    payload_json = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    notification_json = json.dumps(
        notification, sort_keys=True, separators=(",", ":")
    )
    data = notification.get("data")
    alerts = data if isinstance(data, list) else [notification]
    row_ids = []

    with DB_LOCK:
        with connect_db() as conn:
            for alert in alerts:
                alert_data = alert if isinstance(alert, dict) else {"value": alert}
                values = {
                    "received_at": received_at,
                    "source_ip": client_address[0],
                    "source_port": client_address[1],
                    "content_type": headers.get("content-type"),
                    "user_agent": headers.get("user-agent"),
                    "headers_json": json.dumps(dict(headers.items()), sort_keys=True),
                    "raw_payload": raw_payload,
                    "payload_json": payload_json,
                    "notification_json": notification_json,
                    "alert_json": json.dumps(
                        alert_data, sort_keys=True, separators=(",", ":")
                    ),
                    "adom": notification.get("adom"),
                    "apiver": parse_int(notification.get("apiver")),
                    "from_device": notification.get("from"),
                    "timestamp": parse_int(notification.get("timestamp")),
                    "type": notification.get("type"),
                    "ackflag": alert_data.get("ackflag"),
                    "alertid": alert_data.get("alertid"),
                    "alerttime": alert_data.get("alerttime"),
                    "devid": alert_data.get("devid"),
                    "devname": alert_data.get("devname"),
                    "devtype": alert_data.get("devtype"),
                    "ephostname": alert_data.get("ephostname"),
                    "epid": alert_data.get("epid"),
                    "epip": alert_data.get("epip"),
                    "epmac": alert_data.get("epmac"),
                    "epname": alert_data.get("epname"),
                    "eposname": alert_data.get("eposname"),
                    "eposversion": alert_data.get("eposversion"),
                    "euid": alert_data.get("euid"),
                    "euname": alert_data.get("euname"),
                    "eventtype": alert_data.get("eventtype"),
                    "extrainfo": alert_data.get("extrainfo"),
                    "fctuid": alert_data.get("fctuid"),
                    "firstlogtime": alert_data.get("firstlogtime"),
                    "groupby1": alert_data.get("groupby1"),
                    "groupby2": alert_data.get("groupby2"),
                    "groupby3": alert_data.get("groupby3"),
                    "indicator": alert_data.get("indicator"),
                    "lastlogtime": alert_data.get("lastlogtime"),
                    "log_detail": alert_data.get("log-detail"),
                    "log_length": parse_int(alert_data.get("log-length")),
                    "logcount": alert_data.get("logcount"),
                    "logtype": alert_data.get("logtype"),
                    "readflag": alert_data.get("readflag"),
                    "severity": alert_data.get("severity"),
                    "subject": alert_data.get("subject"),
                    "subtype": alert_data.get("subtype"),
                    "tag": alert_data.get("tag"),
                    "triggername": alert_data.get("triggername"),
                    "vdom": alert_data.get("vdom"),
                }
                columns = ", ".join(values.keys())
                placeholders = ", ".join(f":{key}" for key in values)
                cursor = conn.execute(
                    f"INSERT INTO fortinet_alerts ({columns}) VALUES ({placeholders})",
                    values,
                )
                row_ids.append(cursor.lastrowid)
    store_clickhouse_alert_payload(
        payload_json,
        "fortinet payload",
        count=len(row_ids),
    )
    return row_ids


def migrate_existing_fortinet_payloads():
    with DB_LOCK:
        with connect_db() as conn:
            rows = conn.execute(
                """
                SELECT id, received_at, source_ip, source_port, content_type,
                       user_agent, headers_json, raw_payload, payload_json
                FROM webhook_alerts
                WHERE payload_json LIKE '%fortianalyzer_notification%'
                """
            ).fetchall()

    migrated_ids = []
    for row in rows:
        try:
            parsed = json.loads(row["payload_json"] or row["raw_payload"] or "{}")
            headers = json.loads(row["headers_json"] or "{}")
        except json.JSONDecodeError:
            continue

        notification = get_fortinet_notification(parsed)
        if notification is None:
            continue

        row_ids = store_fortinet_alerts(
            row["received_at"],
            (row["source_ip"], row["source_port"] or 0),
            headers,
            row["raw_payload"] or "",
            parsed,
        )
        if row_ids:
            migrated_ids.append(row["id"])

    if migrated_ids:
        placeholders = ", ".join("?" for _ in migrated_ids)
        with DB_LOCK:
            with connect_db() as conn:
                conn.execute(
                    f"DELETE FROM webhook_alerts WHERE id IN ({placeholders})",
                    migrated_ids,
                )
    return len(migrated_ids)


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


def get_fortinet_rows(limit=100):
    with connect_db() as conn:
        return conn.execute(
            f"""
            SELECT {", ".join(FORTINET_COLUMNS)}
            FROM fortinet_alerts
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


def render_cell(column, value):
    if value is None:
        return ""
    escaped_value = html.escape(str(value))
    if column == "log_detail":
        return f"<pre class='log-detail'>{escaped_value}</pre>"
    return escaped_value


def render_table(caption, rows, columns):
    display_rows = numbered_rows(rows)
    body = [
        "<div class='table-wrap'>",
        f"<table><caption>{html.escape(caption)}</caption><thead><tr>",
    ]
    for column in columns:
        body.append(f"<th>{html.escape(column)}</th>")
    body.append("</tr></thead><tbody>")
    for row in display_rows:
        body.append("<tr>")
        for column in columns:
            value = row[column]
            css_class = " class='log-detail-cell'" if column == "log_detail" else ""
            cell = render_cell(column, value)
            body.append(f"<td{css_class}>{cell}</td>")
        body.append("</tr>")
    body.append("</tbody></table></div>")
    return "".join(body)


def render_alert_page(zscaler_rows, fortinet_rows):
    body = []
    body.append("<!doctype html><html><head><meta charset='utf-8'>")
    body.append("<title>Security alerts</title>")
    body.append(
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:24px;}"
        "section{margin-bottom:36px;}"
        ".table-wrap{max-width:100%;overflow:auto;}"
        "table{border-collapse:collapse;width:100%;font-size:13px;}"
        "th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top;}"
        "th{background:#f4f6f8;position:sticky;top:0;}"
        "td{max-width:420px;overflow-wrap:anywhere;}"
        "caption{text-align:left;font-weight:700;margin-bottom:12px;font-size:20px;}"
        ".log-detail-cell{min-width:520px;max-width:720px;}"
        ".log-detail{max-height:120px;overflow:auto;margin:0;white-space:pre-wrap;"
        "font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;"
        "line-height:1.35;background:#f8fafc;border:1px solid #d9e1ea;"
        "border-radius:4px;padding:8px;}"
        "a{color:#0b5cab;}"
        "</style></head><body>"
    )
    body.append("<section>")
    body.append(render_table("Zscaler alerts", zscaler_rows, DISPLAY_COLUMNS))
    body.append("</section><section>")
    body.append(render_table("Fortinet alerts", fortinet_rows, FORTINET_DISPLAY_COLUMNS))
    body.append("</section></body></html>")
    return "".join(body)


def rows_as_csv(rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=DISPLAY_COLUMNS)
    writer.writeheader()
    for row in numbered_rows(rows):
        writer.writerow({column: row[column] for column in DISPLAY_COLUMNS})
    return output.getvalue()


def fortinet_rows_as_csv(rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=FORTINET_DISPLAY_COLUMNS)
    writer.writeheader()
    for row in numbered_rows(rows):
        writer.writerow({column: row[column] for column in FORTINET_DISPLAY_COLUMNS})
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


def print_fortinet_alerts(limit):
    rows = numbered_rows(get_fortinet_rows(limit))
    widths = {
        column: max([len(column)] + [len(str(row.get(column, ""))) for row in rows])
        for column in FORTINET_DISPLAY_COLUMNS
    }
    print(" | ".join(column.ljust(widths[column]) for column in FORTINET_DISPLAY_COLUMNS))
    print("-+-".join("-" * widths[column] for column in FORTINET_DISPLAY_COLUMNS))
    for row in rows:
        print(
            " | ".join(
                str(row.get(column, "") or "").replace("\n", " ").ljust(widths[column])
                for column in FORTINET_DISPLAY_COLUMNS
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
        fortinet_rows = get_fortinet_rows()
        if self.path == "/alerts.json":
            body = json.dumps(numbered_rows(rows), indent=2).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", body)
            return
        if self.path == "/alerts.csv":
            body = rows_as_csv(rows).encode("utf-8")
            self._send_bytes(200, "text/csv; charset=utf-8", body)
            return
        body = render_alert_page(rows, fortinet_rows).encode("utf-8")
        self._send_bytes(200, "text/html; charset=utf-8", body)

    def _handle_fortinet_view(self):
        rows = get_fortinet_rows()
        if self.path == "/fortinet.json":
            body = json.dumps(numbered_rows(rows), indent=2).encode("utf-8")
            self._send_bytes(200, "application/json; charset=utf-8", body)
            return
        if self.path == "/fortinet.csv":
            body = fortinet_rows_as_csv(rows).encode("utf-8")
            self._send_bytes(200, "text/csv; charset=utf-8", body)
            return
        body = render_alert_page(get_alert_rows(), rows).encode("utf-8")
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
            if get_fortinet_notification(parsed) is not None:
                row_ids = store_fortinet_alerts(
                    received_at,
                    self.client_address,
                    self.headers,
                    text,
                    parsed,
                )
                log(f"Fortinet SQLite rows: {row_ids}")
            else:
                try:
                    enrichment = enrich_zscaler_alert_payload_with_retry(parsed, log)
                    if enrichment is not None:
                        log(
                            "Zscaler alert enrichment: "
                            f"alert_id={enrichment['alert_id']}, "
                            f"location={enrichment['location']}, "
                            f"device_name={enrichment['device_name']}, "
                            f"user_name={enrichment['user_name']}"
                        )
                except urllib.error.HTTPError as error:
                    error_body = getattr(error, "enrichment_body", None)
                    if error_body is None:
                        error_body = error.read().decode("utf-8", errors="replace")
                    log(
                        "Zscaler alert enrichment failed: "
                        f"HTTP {error.code} {error.reason}: {error_body}"
                    )
                except (urllib.error.URLError, TimeoutError, RuntimeError) as error:
                    log(f"Zscaler alert enrichment failed: {error}")

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
        if self.path in ("/fortinet", "/fortinet.json", "/fortinet.csv"):
            self._handle_fortinet_view()
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
    parser.add_argument(
        "--list-fortinet",
        action="store_true",
        help="print stored Fortinet alerts as a table",
    )
    parser.add_argument(
        "--migrate-fortinet",
        action="store_true",
        help="move previously misclassified Fortinet payloads into fortinet_alerts",
    )
    parser.add_argument("--limit", type=int, default=25, help="number of alerts to show")
    args = parser.parse_args()

    init_db()
    try:
        init_clickhouse()
    except (ValueError, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        log_clickhouse_error(f"initialization failed: {error}")
    if args.migrate_fortinet:
        migrated = migrate_existing_fortinet_payloads()
        print(f"Migrated {migrated} Fortinet payload rows")
        sys.exit(0)
    if args.list_fortinet:
        print_fortinet_alerts(args.limit)
        sys.exit(0)
    if args.list:
        print_alerts(args.limit)
        sys.exit(0)

    server = ThreadingHTTPServer((HOST, PORT), WebhookHandler)
    print(f"Webhook receiver listening on http://{HOST}:{PORT}", flush=True)
    print(f"SQLite storage: {DB_FILE}", flush=True)
    print(f"ClickHouse payload table: {CLICKHOUSE_ALERT_PAYLOADS_TABLE}", flush=True)
    server.serve_forever()
