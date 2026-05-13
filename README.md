# Webhook Receiver

Standalone Python webhook receiver for Zscaler ZDX alerts.

## Run

```bash
python3 /home/ubuntu/webhook_receiver.py
```

The receiver listens on port `8080`, appends request details to
`/home/ubuntu/receiver.log`, and stores every received request in
`/home/ubuntu/alerts.sqlite`.

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
`alert_id`, `status`, `severity`, `rule_name`, impact counts, and
`criteria_string` are stored as queryable columns. Request method, request path,
and the structured payload `url` field are not stored as table columns.

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
