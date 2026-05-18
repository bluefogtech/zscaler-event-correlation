#!/usr/bin/env python3
import argparse
import datetime
import json
import sqlite3
import sys
import time
import urllib.error

import webhook_receiver

DEFAULT_SERVICE_LOG_FILE = "/home/ubuntu/zscaler_enrichment_service.log"
DEFAULT_SERVICE_COUNT_FILE = "/home/ubuntu/zscaler_enrichment_service.count"


def is_blank(value):
    return value is None or str(value).strip() == ""


def utc_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def log_message(message, log_file=None):
    line = f"{utc_timestamp()} {message}"
    print(line, flush=True)
    if log_file:
        with open(log_file, "a", encoding="utf-8") as file:
            file.write(line + "\n")


def read_counter(count_file):
    try:
        with open(count_file, "r", encoding="utf-8") as file:
            return int(file.read().strip() or "0")
    except (FileNotFoundError, ValueError):
        return 0


def write_counter(count_file, value):
    with open(count_file, "w", encoding="utf-8") as file:
        file.write(f"{value}\n")


def clickhouse_string_literal(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def load_alert_rows(db_file, alert_id):
    query = """
        SELECT id, alert_id, event, status, location, device_name, user_name,
               enriched_data, payload_json
        FROM webhook_alerts
        WHERE alert_id = ?
    """
    params = [alert_id]
    query += " ORDER BY id"

    with sqlite3.connect(db_file) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, params).fetchall()


def load_unenriched_rows_from_id(db_file, start_id):
    query = """
        SELECT id, alert_id, event, status, location, device_name, user_name,
               enriched_data, payload_json
        FROM webhook_alerts
        WHERE id >= ?
          AND event = 'Zscaler-ZDX'
          AND alert_id IS NOT NULL
          AND trim(alert_id) != ''
          AND (
              location IS NULL OR trim(location) = ''
              OR device_name IS NULL OR trim(device_name) = ''
              OR user_name IS NULL OR trim(user_name) = ''
          )
        ORDER BY id
    """
    with sqlite3.connect(db_file) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, [start_id]).fetchall()


def row_is_enriched(row):
    return (
        not is_blank(row["location"])
        and not is_blank(row["device_name"])
        and not is_blank(row["user_name"])
    )


def update_sqlite_row(db_file, row_id, payload_json, enrichment):
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            """
            UPDATE webhook_alerts
               SET payload_json = ?,
                   enriched_data = 'yes',
                   location = ?,
                   device_name = ?,
                   user_name = ?
             WHERE id = ?
            """,
            (
                payload_json,
                enrichment["location"],
                enrichment["device_name"],
                enrichment["user_name"],
                row_id,
            ),
        )


def update_clickhouse_cleaned_alert(row, new_payload_json):
    alert_id = row["alert_id"]
    status = row["status"]
    if is_blank(alert_id) or is_blank(status):
        raise RuntimeError(
            f"SQLite row {row['id']} missing alert_id/status for cleaned table update"
        )

    query = f"""
        ALTER TABLE aiops.zscaler_alerts_cleaned
        UPDATE payload_json = {clickhouse_string_literal(new_payload_json)},
               enriched_data = 'yes'
        WHERE alert_id = {clickhouse_string_literal(alert_id)}
          AND status = {clickhouse_string_literal(status)}
        SETTINGS mutations_sync = 1
    """
    webhook_receiver.clickhouse_request(query)


def enrich_row(row):
    if is_blank(row["payload_json"]):
        raise RuntimeError(f"SQLite row {row['id']} has empty payload_json")

    try:
        payload = json.loads(row["payload_json"])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"SQLite row {row['id']} has invalid payload_json: {error}")

    if not isinstance(payload, dict):
        raise RuntimeError(f"SQLite row {row['id']} payload_json is not a JSON object")

    enrichment = webhook_receiver.enrich_zscaler_alert_payload_with_retry(
        payload,
        lambda message: print(message, file=sys.stderr),
    )
    if enrichment is None:
        raise RuntimeError(f"SQLite row {row['id']} enrichment returned no data")

    payload["enriched_data"] = "yes"
    enriched_payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return enriched_payload_json, enrichment


def process_row(row, db_file, skip_clickhouse, dry_run, log_file=None, force=False):
    if row_is_enriched(row) and not force:
        log_message(
            f"Skipping SQLite row id={row['id']} alert_id={row['alert_id']} "
            f"status={row['status']}: already enriched",
            log_file,
        )
        return False

    log_message(
        f"Enriching SQLite row id={row['id']} alert_id={row['alert_id']} "
        f"status={row['status']}",
        log_file,
    )
    new_payload_json, enrichment = enrich_row(row)
    log_message(
        "  enrichment: "
        f"location={enrichment['location']!r}, "
        f"device_name={enrichment['device_name']!r}, "
        f"user_name={enrichment['user_name']!r}",
        log_file,
    )

    if dry_run:
        return True

    update_sqlite_row(db_file, row["id"], new_payload_json, enrichment)
    if not skip_clickhouse:
        update_clickhouse_cleaned_alert(row, new_payload_json)
    return True


def run_watch_mode(args):
    total_enriched = read_counter(args.count_file)
    log_message(
        "Starting Zscaler enrichment service: "
        f"db_file={args.db_file}, start_id={args.start_id}, "
        f"scan_interval_seconds={args.scan_interval_seconds}, "
        f"enrichment_delay_seconds={args.enrichment_delay_seconds}, "
        f"skip_clickhouse={args.skip_clickhouse}, dry_run={args.dry_run}, "
        f"total_enriched_by_script={total_enriched}",
        args.log_file,
    )

    while True:
        try:
            rows = load_unenriched_rows_from_id(args.db_file, args.start_id)
            log_message(
                f"Scan found {len(rows)} unenriched Zscaler row(s) "
                f"with SQLite id >= {args.start_id}",
                args.log_file,
            )
            for index, row in enumerate(rows, start=1):
                try:
                    did_enrich = process_row(
                        row,
                        args.db_file,
                        args.skip_clickhouse,
                        args.dry_run,
                        args.log_file,
                    )
                except (
                    urllib.error.HTTPError,
                    urllib.error.URLError,
                    TimeoutError,
                    RuntimeError,
                    ValueError,
                ) as error:
                    log_message(
                        f"Failed SQLite row id={row['id']} "
                        f"alert_id={row['alert_id']}: {error}",
                        args.log_file,
                    )
                    did_enrich = False

                if did_enrich and not args.dry_run:
                    total_enriched += 1
                    write_counter(args.count_file, total_enriched)
                    log_message(
                        f"Enriched SQLite row id={row['id']} "
                        f"alert_id={row['alert_id']}; "
                        f"total_enriched_by_script={total_enriched}",
                        args.log_file,
                    )

                if index < len(rows):
                    time.sleep(args.enrichment_delay_seconds)
        except Exception as error:
            log_message(f"Scan failed: {error}", args.log_file)

        time.sleep(args.scan_interval_seconds)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Enrich existing Zscaler SQLite rows by alert_id and update the "
            "matching ClickHouse cleaned alert rows."
        )
    )
    parser.add_argument(
        "alert_id",
        nargs="?",
        help="Zscaler alert ID to enrich. If omitted, the script prompts for it.",
    )
    parser.add_argument(
        "--db-file",
        default=webhook_receiver.DB_FILE,
        help=f"SQLite database path. Default: {webhook_receiver.DB_FILE}",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Re-enrich all rows for the alert_id, including rows that already have all three fields.",
    )
    parser.add_argument(
        "--skip-clickhouse",
        action="store_true",
        help="Update SQLite only.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch enrichment and show planned updates without writing changes.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously scan SQLite for unenriched Zscaler rows.",
    )
    parser.add_argument(
        "--start-id",
        type=int,
        default=428,
        help="In watch mode, only scan SQLite rows with id >= this value. Default: 428.",
    )
    parser.add_argument(
        "--scan-interval-seconds",
        type=int,
        default=900,
        help="In watch mode, delay between scans. Default: 900.",
    )
    parser.add_argument(
        "--enrichment-delay-seconds",
        type=int,
        default=60,
        help="In watch mode, delay between enrichment attempts. Default: 60.",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_SERVICE_LOG_FILE,
        help=f"Service log file. Default: {DEFAULT_SERVICE_LOG_FILE}",
    )
    parser.add_argument(
        "--count-file",
        default=DEFAULT_SERVICE_COUNT_FILE,
        help=f"Persistent service counter file. Default: {DEFAULT_SERVICE_COUNT_FILE}",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.watch:
        run_watch_mode(args)
        return 0

    alert_id = args.alert_id or input("Alert ID: ").strip()
    if is_blank(alert_id):
        print("alert_id is required", file=sys.stderr)
        return 2

    rows = load_alert_rows(args.db_file, alert_id)
    if not rows:
        print(f"No matching rows found for alert_id={alert_id}")
        return 1

    updated = 0
    clickhouse_updated = 0
    skipped = 0
    planned = 0
    for row in rows:
        if row_is_enriched(row) and not args.all:
            skipped += 1
            print(
                f"Skipping SQLite row id={row['id']} status={row['status']}: "
                "already enriched"
            )
            continue

        planned += 1
        try:
            did_enrich = process_row(
                row,
                args.db_file,
                args.skip_clickhouse,
                args.dry_run,
                force=args.all,
            )
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            RuntimeError,
            ValueError,
        ) as error:
            print(f"Failed to enrich row id={row['id']}: {error}", file=sys.stderr)
            return 1

        if did_enrich and not args.dry_run:
            updated += 1
            if not args.skip_clickhouse:
                clickhouse_updated += 1

    if args.dry_run:
        print(
            f"Dry run complete. {planned} row(s) would be updated; "
            f"{skipped} already enriched row(s) skipped."
        )
        return 0

    print(f"Updated {updated} SQLite row(s).")
    print(f"Skipped {skipped} already enriched row(s).")
    if args.skip_clickhouse:
        print("Skipped ClickHouse update.")
    else:
        print(f"Submitted {clickhouse_updated} ClickHouse cleaned alert update(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
