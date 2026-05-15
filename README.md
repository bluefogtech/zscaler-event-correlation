# Webhook Receiver

Standalone Python webhook receiver for Zscaler ZDX alerts.

## Run

```bash
python3 /home/ubuntu/webhook_receiver.py
```

The receiver listens on port `8080`, appends request details to
`/home/ubuntu/receiver.log`, and stores every received request in
`/home/ubuntu/alerts.sqlite`.

Webhook payloads are also written unchanged to the ClickHouse table
`aiops.alert_payloads`. By default the receiver sends these writes to the
remote ClickHouse Cloud HTTPS endpoint configured in `webhook_receiver.py`.
The destination can be overridden with `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`,
`CLICKHOUSE_SECURE`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`,
`CLICKHOUSE_HTTP_URL`, and `CLICKHOUSE_ALERT_PAYLOADS_TABLE`.

For non-Fortinet POST alerts, the receiver uses the stored Zscaler OAuth bearer
token from `/home/ubuntu/zscaler_bearer_token.txt` to enrich the alert before
storing it. If that token is missing or expired, it requests a new token from
`https://esoczscalerlab.zslogin.net/oauth2/v1/token` and writes the received
token back to `/home/ubuntu/zscaler_bearer_token.txt`.

The enrichment calls:

```text
https://api.zsapi.net/zdx/v1/alerts/{alert_id}
https://api.zsapi.net/zdx/v1/alerts/{alert_id}/affected_devices
```

The receiver stores `locations[0].name` as `location`,
`devices[0].name` as `device_name`, and `devices[0].userName` as
`user_name`. The same values are also added to the stored `payload_json`.

## View Alerts

Browser table:

```text
http://SERVER:8080/alerts
```

Machine-readable exports:

```text
http://SERVER:8080/alerts.json
http://SERVER:8080/alerts.csv
```

Local terminal table:

```bash
python3 /home/ubuntu/webhook_receiver.py --list --limit 25
```

## SQLite Table

Zscaler alert data is stored in `webhook_alerts`. Common fields such as
`alert_id`, `status`, `severity`, `rule_name`, `location`, `device_name`,
`user_name`, impact counts, and `criteria_string` are stored as queryable
columns. Request method, request path, and the structured payload `url` field
are not stored as table columns.

The complete request headers and raw payload are also retained as JSON/text
columns so the same records can be sent to Elasticsearch later without losing
fields.

Fortinet FortiAnalyzer notifications are stored separately in `fortinet_alerts`
when the payload contains `fortianalyzer_notification`. The notification fields
and each `data` item are stored as queryable columns, and the complete
notification and alert item JSON are retained.

Fortinet views:

```text
http://SERVER:8080/fortinet
http://SERVER:8080/fortinet.json
http://SERVER:8080/fortinet.csv
```

Local terminal table:

```bash
python3 /home/ubuntu/webhook_receiver.py --list-fortinet --limit 25
```
