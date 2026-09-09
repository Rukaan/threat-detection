# Streaming threat detection — single source of truth

Synthetic cyberattack simulation on Confluent Cloud. Two Datagen connectors produce
a login log and a DB query audit log; Flink SQL runs four deterministic detections
across both; only what those flag is sent to Amazon Bedrock for triage.

    datagen ─► access_logs_raw ─┐
                                ├─ Flink R1..R4 ─► security_signals ─ ML_PREDICT ─► threat_alerts
    datagen ─► query_logs_raw  ─┘

Rules run on every event. The model runs only on rule hits — that split is the
whole cost story. All data is synthetic; no real accounts or customer data.

## Live coordinates (verified 2026-09-09)

| | |
|---|---|
| Confluent account | the hackathon org (separate from the corporate org) |
| Environment | `workshop-kyc-nbo` — `env-1k5jk5` |
| Kafka cluster | `kyc_nbo_cluster` — `lkc-w72kxd5`, AWS **ap-southeast-1** |
| Flink compute pool | `lfcp-387dpvm`, ap-southeast-1, PROVISIONED |
| Service account | `threat-sim-sa` — `sa-w5rvz59` |
| Connectors | `lcc-6kgyv36` access, `lcc-zm6kvgz` query — both RUNNING, AVRO |

Note: the `security` cluster (`lkc-387dj6o`) is in **ap-southeast-3**, which has no
Bedrock. Everything here uses `kyc_nbo_cluster` in ap-southeast-1 instead, which is
also where the compute pool already lives.

In the Flink workspace: **Use catalog** = `workshop-kyc-nbo`,
**Use database** = `kyc_nbo_cluster`.

---

# STEP 0 — clean slate — DONE

Completed via CLI on 2026-09-09:

- deleted connectors `datagen_access_log` (lcc-q2p6x07, JSON_SR, PAUSED) and
  `DatagenSourceConnector_accessLogs` (lcc-w72k8n5, JSON_SR, RUNNING)
- deleted topics `access_logs_raw`, `query_logs_raw`
- permanently deleted subjects `access_logs_raw-value`, `query_logs_raw-value`

The five KYC/NBO workshop connectors (Customers, Customers_2, Transactions,
Products, DatagenSourceConnector_6) were left untouched.

---

# STEP 1 — the two Datagen connectors — DONE

Both created via CLI with `kafka.auth.mode=SERVICE_ACCOUNT` (no API secrets in the
config) and `output.data.format=AVRO`. Verified: subject `access_logs_raw-value` is
schema id 100010, **Type: AVRO**.

Do NOT create these topics or tables yourself — the connector owns them and Flink
auto-maps them. The settings and schemas below are recorded for rebuilds.

|                          | connector 1        | connector 2       |
|--------------------------|--------------------|-------------------|
| Topic                    | `access_logs_raw`  | `query_logs_raw`  |
| Output record value format | **AVRO**         | **AVRO**          |
| Max interval (ms)        | `300`              | `400`             |
| Tasks                    | `1`                | `1`               |
| schema.keyfield (advanced, optional) | `user_id` | `user_id`     |

AVRO matters. Picking JSON_SR here is what causes
`Incompatible because of different schema type` later.

Paste into **JSON-encoded Avro Schema** — the schema object only, nothing else.

### connector 1 schema

```json
{
  "namespace": "sim.security",
  "name": "AccessLog",
  "type": "record",
  "fields": [
    {"name": "event_time", "type": {"type": "long", "format_as_time": "unix_long",
      "arg.properties": {"iteration": {"start": 1}}}},
    {"name": "user_id", "type": {"type": "string", "arg.properties": {"options": [
      "svc_batch","svc_etl","analyst_01","analyst_02","analyst_03","analyst_04",
      "ops_01","ops_02","dba_01","dba_02","contractor_07"]}}},
    {"name": "source_ip", "type": {"type": "string", "arg.properties": {"options": [
      "10.12.4.11","10.12.4.12","10.12.4.19","10.12.8.31","10.12.8.44",
      "172.16.3.7","172.16.3.9","203.0.113.44"]}}},
    {"name": "auth_result", "type": {"type": "string", "arg.properties": {"options": [
      "SUCCESS","SUCCESS","SUCCESS","SUCCESS","SUCCESS",
      "SUCCESS","SUCCESS","SUCCESS","SUCCESS","FAILURE"]}}},
    {"name": "auth_method", "type": {"type": "string", "arg.properties": {"options": [
      "password","password","mfa","sso","api_key"]}}},
    {"name": "service", "type": {"type": "string", "arg.properties": {"options": [
      "vpn","jumphost","warehouse","admin_console","api_gateway"]}}},
    {"name": "geo_country", "type": {"type": "string", "arg.properties": {"options": [
      "ID","ID","ID","ID","ID","SG","MY"]}}},
    {"name": "user_agent", "type": {"type": "string", "arg.properties": {"options": [
      "Mozilla/5.0 (Macintosh)","Mozilla/5.0 (Windows NT 10.0)","psql/15.3",
      "python-requests/2.31","curl/8.4.0"]}}}
  ]
}
```

### connector 2 schema

```json
{
  "namespace": "sim.security",
  "name": "QueryLog",
  "type": "record",
  "fields": [
    {"name": "event_time", "type": {"type": "long", "format_as_time": "unix_long",
      "arg.properties": {"iteration": {"start": 1}}}},
    {"name": "user_id", "type": {"type": "string", "arg.properties": {"options": [
      "svc_batch","svc_etl","analyst_01","analyst_02","analyst_03","analyst_04",
      "ops_01","ops_02","dba_01","dba_02","contractor_07"]}}},
    {"name": "session_id", "type": {"type": "string", "arg.properties": {"options": [
      "sess-1a2b3c4d","sess-2b3c4d5e","sess-3c4d5e6f","sess-4d5e6f70",
      "sess-5e6f7081","sess-6f708192","sess-708192a3","sess-8192a3b4",
      "sess-92a3b4c5","sess-a3b4c5d6","sess-b4c5d6e7","sess-c5d6e7f8"]}}},
    {"name": "client_ip", "type": {"type": "string", "arg.properties": {"options": [
      "10.12.4.11","10.12.4.12","10.12.4.19","10.12.8.31","10.12.8.44",
      "172.16.3.7","172.16.3.9","203.0.113.44"]}}},
    {"name": "db_name", "type": {"type": "string", "arg.properties": {"options": [
      "billing","crm","network_inventory","reporting"]}}},
    {"name": "sql_text", "type": {"type": "string", "arg.properties": {"options": [
      "SELECT count(*) FROM invoices WHERE period = '2026-08'",
      "SELECT status, count(*) FROM tickets GROUP BY status",
      "SELECT site_id, region FROM cell_sites WHERE region = 'JKT'",
      "UPDATE tickets SET status = 'closed' WHERE id = 4821",
      "SELECT plan_code, count(*) FROM subscriptions GROUP BY plan_code",
      "SELECT * FROM reporting.daily_rollup LIMIT 100"]}}},
    {"name": "rows_returned", "type": {"type": "int", "arg.properties": {
      "range": {"min": 0, "max": 900}}}},
    {"name": "duration_ms", "type": {"type": "int", "arg.properties": {
      "range": {"min": 3, "max": 2400}}}}
  ]
}
```

Both share the same `user_id` and IP pools — that is what lets rule R4 correlate
the two streams. `auth_result` is weighted 9:1 success/failure so the baseline sits
just under R1's threshold and the injected attack is what pushes it over.

The field is named `sql_text`, not `statement`: `statement` is a reserved word in
Flink SQL and would fail the moment you query the table.

**Check it works:** Topics → `access_logs_raw` → Messages. Rows within ~30s.
If nothing arrives, the connector tile shows why. Fix that before going on.

---

# STEP 2 — Flink compute pool — DONE

`lfcp-387dpvm` already exists in ap-southeast-1, PROVISIONED, max 50 CFU — same
region as the cluster. Open a workspace on it and set
**Use catalog** = `workshop-kyc-nbo`, **Use database** = `kyc_nbo_cluster`.

---

# STEP 3 — the SQL

One cell per block, in order.

### Cell 1 — the connector topics should already be tables
```sql
SHOW TABLES;
```

### Cell 2 — confirm the inferred columns
```sql
DESCRIBE access_logs_raw;
```

### Cell 3 — output: rule hits
```sql
CREATE TABLE security_signals (
  signal_id     STRING,
  detected_at   TIMESTAMP_LTZ(3),
  rule_id       STRING,
  severity_hint STRING,
  user_id       STRING,
  source_ip     STRING,
  evidence      STRING,
  PRIMARY KEY (signal_id) NOT ENFORCED
) DISTRIBUTED BY HASH(signal_id) INTO 2 BUCKETS
WITH ('changelog.mode' = 'upsert',
      'key.format'     = 'avro-registry',
      'value.format'   = 'avro-registry');
```

### Cell 4 — output: AI-triaged alerts
```sql
CREATE TABLE threat_alerts (
  signal_id   STRING,
  detected_at TIMESTAMP_LTZ(3),
  rule_id     STRING,
  user_id     STRING,
  source_ip   STRING,
  evidence    STRING,
  triage      STRING,
  PRIMARY KEY (signal_id) NOT ENFORCED
) DISTRIBUTED BY HASH(signal_id) INTO 2 BUCKETS
WITH ('changelog.mode' = 'upsert',
      'key.format'     = 'avro-registry',
      'value.format'   = 'avro-registry');
```

The bucketing key must be the leading column — that is why `signal_id` is first.

### Cell 5 — R1 brute force: 5+ failed logins per user+IP in 1 minute
```sql
INSERT INTO security_signals
SELECT
  'R1-' || user_id || '-' || source_ip || '-' || CAST(window_start AS STRING),
  window_end, 'R1_BRUTE_FORCE', 'HIGH', user_id, source_ip,
  'failed_logins=' || CAST(SUM(CASE WHEN auth_result = 'FAILURE' THEN 1 ELSE 0 END) AS STRING)
    || '; successes=' || CAST(SUM(CASE WHEN auth_result = 'SUCCESS' THEN 1 ELSE 0 END) AS STRING)
    || '; window=1min; service=' || MAX(service) || '; method=' || MAX(auth_method)
FROM TABLE(TUMBLE(TABLE access_logs_raw, DESCRIPTOR(`$rowtime`), INTERVAL '1' MINUTE))
GROUP BY window_start, window_end, user_id, source_ip
HAVING SUM(CASE WHEN auth_result = 'FAILURE' THEN 1 ELSE 0 END) >= 5;
```

### Cell 6 — R2 SQL-injection shaped statements
```sql
INSERT INTO security_signals
SELECT
  'R2-' || session_id || '-' || CAST(`$rowtime` AS STRING),
  `$rowtime`, 'R2_SQLI_PATTERN', 'CRITICAL', user_id, client_ip,
  'db=' || db_name || '; rows=' || CAST(rows_returned AS STRING)
    || '; sql=' || SUBSTRING(sql_text FROM 1 FOR 300)
FROM query_logs_raw
WHERE REGEXP(UPPER(sql_text),
  '(UNION\s+(ALL\s+)?SELECT|OR\s+1\s*=\s*1|;\s*DROP\s+|;\s*DELETE\s+FROM|XP_CMDSHELL|INFORMATION_SCHEMA\.|PG_SLEEP\s*\(|BENCHMARK\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)');
```

### Cell 7 — R3 bulk read: 20k+ rows per user in 5 minutes
```sql
INSERT INTO security_signals
SELECT
  'R3-' || user_id || '-' || CAST(window_start AS STRING),
  window_end, 'R3_BULK_EXFIL', 'HIGH', user_id, MAX(client_ip),
  'rows_5min=' || CAST(SUM(rows_returned) AS STRING)
    || '; queries=' || CAST(COUNT(*) AS STRING)
    || '; distinct_dbs=' || CAST(COUNT(DISTINCT db_name) AS STRING)
    || '; max_single_query_rows=' || CAST(MAX(rows_returned) AS STRING)
FROM TABLE(TUMBLE(TABLE query_logs_raw, DESCRIPTOR(`$rowtime`), INTERVAL '5' MINUTE))
GROUP BY window_start, window_end, user_id
HAVING SUM(rows_returned) > 20000;
```

### Cell 8 — R4 correlation: non-MFA login, then a heavy query within 10 min
```sql
INSERT INTO security_signals
SELECT
  'R4-' || a.user_id || '-' || CAST(q.`$rowtime` AS STRING),
  q.`$rowtime`, 'R4_SUSPICIOUS_SESSION', 'CRITICAL', a.user_id, a.source_ip,
  'login_service=' || a.service || '; auth_method=' || a.auth_method
    || '; geo=' || a.geo_country || '; agent=' || a.user_agent
    || '; then_query_db=' || q.db_name
    || '; rows=' || CAST(q.rows_returned AS STRING)
    || '; sql=' || SUBSTRING(q.sql_text FROM 1 FOR 200)
FROM access_logs_raw a
JOIN query_logs_raw q
  ON a.user_id = q.user_id
 AND q.`$rowtime` BETWEEN a.`$rowtime` AND a.`$rowtime` + INTERVAL '10' MINUTE
WHERE a.auth_result = 'SUCCESS'
  AND a.auth_method <> 'mfa'
  AND q.rows_returned > 5000;
```

This is the one worth demoing: neither log produces this signal alone.

### Cell 9 — Bedrock connection
Fill in region, model id, and your own keys. Use an IAM user scoped to
`bedrock:InvokeModel` and nothing else. Get the model id with:
`aws bedrock list-foundation-models --region ap-southeast-1 --query 'modelSummaries[?contains(modelId,\`claude\`)].modelId' --output table`
(APAC cross-region inference profiles carry an `apac.` prefix.)

```sql
CREATE CONNECTION `bedrock-threat-conn`
WITH (
  'type'           = 'bedrock',
  'endpoint'       = 'https://bedrock-runtime.ap-southeast-1.amazonaws.com/model/<MODEL_ID>/invoke',
  'aws-access-key' = '<AWS_ACCESS_KEY_ID>',
  'aws-secret-key' = '<AWS_SECRET_ACCESS_KEY>'
);
```

### Cell 10 — register the model
```sql
CREATE MODEL threat_triage
INPUT  (prompt STRING)
OUTPUT (response STRING)
WITH (
  'provider'                   = 'bedrock',
  'task'                       = 'text_generation',
  'bedrock.connection'         = 'bedrock-threat-conn',
  'bedrock.PARAMS.max_tokens'  = '400',
  'bedrock.PARAMS.temperature' = '0',
  'bedrock.system_prompt'      = 'You are a SOC tier-2 analyst. You receive one security signal from a streaming detection pipeline over synthetic logs. Reply with ONLY a JSON object, no prose, with keys: severity (INFO|LOW|MEDIUM|HIGH|CRITICAL), confidence (0.0-1.0), mitre_technique (ATT&CK id and name, or "none"), rationale (max 30 words), recommended_action (max 20 words), likely_false_positive (true|false). Judge only on the evidence given; do not invent facts.'
);
```

### Cell 11 — inference, over signals only
```sql
INSERT INTO threat_alerts
SELECT
  s.signal_id, s.detected_at, s.rule_id, s.user_id, s.source_ip, s.evidence,
  p.response
FROM security_signals AS s,
LATERAL TABLE(ML_PREDICT('threat_triage',
  'Security signal for triage.' || CHR(10) ||
  'rule: '               || s.rule_id       || CHR(10) ||
  'rule_severity_hint: ' || s.severity_hint || CHR(10) ||
  'user: '               || s.user_id       || CHR(10) ||
  'source_ip: '          || s.source_ip     || CHR(10) ||
  'detected_at: '        || CAST(s.detected_at AS STRING) || CHR(10) ||
  'evidence: '           || s.evidence
)) AS p;
```

Never point this at the raw topics. Signals arrive a few per minute; raw logs
arrive hundreds per second.

---

# STEP 4 — run the attack

Cells 5–8 must be running first. `event_time` is BIGINT here because the Avro
schema declares a long — the rules window on `$rowtime` (the Kafka record
timestamp), so these are windowed by when you run the cell.

### Cell 12 — password spray, then it lands with no MFA. Trips R1, arms R4.
```sql
INSERT INTO access_logs_raw VALUES
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','SUCCESS','password','vpn','SG','python-requests/2.31');
```

### Cell 13 — enumeration, injection, then a staged 36k-row pull. Trips R2, R3, R4.
```sql
INSERT INTO query_logs_raw VALUES
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm',
  'SELECT table_name FROM information_schema.tables',412,180),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm',
  'SELECT * FROM subscribers WHERE 1=1 UNION SELECT null,null,card_hash FROM billing.payment_tokens',48210,7400),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000',9000,3100),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000 OFFSET 9000',9000,3050),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000 OFFSET 18000',9000,3220),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000 OFFSET 27000',9000,2980);
```

### Cell 14 — CONTROL CASE: real user mistypes, then logs in with MFA
```sql
INSERT INTO access_logs_raw VALUES
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','SUCCESS','mfa','warehouse','ID','Mozilla/5.0 (Macintosh)');
```

R1 fires, R4 must not. Bedrock should return `likely_false_positive: true`.
This is the test of whether the model earns its cost over the rules alone.

### Cell 15 — the payoff
```sql
SELECT
  detected_at, rule_id, user_id, source_ip,
  JSON_VALUE(triage, '$.severity')              AS severity,
  JSON_VALUE(triage, '$.mitre_technique')       AS mitre,
  JSON_VALUE(triage, '$.likely_false_positive') AS false_positive,
  JSON_VALUE(triage, '$.rationale')             AS rationale,
  JSON_VALUE(triage, '$.recommended_action')    AS recommended_action
FROM threat_alerts;
```

Expect `contractor_07` at CRITICAL across R1/R2/R3/R4, and `analyst_02` at R1 only,
flagged as a probable false positive.

---

# STEP 5 — tear down

The compute pool and both connectors bill by the hour.

    confluent connect cluster delete <connector-id> --force
    confluent flink compute-pool delete <lfcp-id> --force

---

# Deployed state (2026-09-09)

Everything below is live except the Bedrock steps.

| Statement | Purpose | Status |
|---|---|---|
| `ts-create-signals` | security_signals table | COMPLETED |
| `ts-create-alerts` | threat_alerts table | COMPLETED |
| `ts-r1` .. `ts-r4` | the four detections | **RUNNING** |
| `ts-a1`,`ts-a2`,`ts-a3` | attack + control injection | COMPLETED |

Still to do, and only you can do it: cell 9 (`CREATE CONNECTION`) and cell 10
(`CREATE MODEL`), then cell 11 to start inference. Cell 9 needs AWS credentials,
which I do not handle.

# Gotchas already hit

- Connector output format must be **AVRO**. JSON_SR against a topic that already
  has an Avro subject gives `Incompatible because of different schema type` (40901).
- Do not `CREATE TABLE` the source topics. The connectors own them; Flink maps
  them automatically. Creating both is what caused that collision.
- `statement` is reserved in Flink SQL. The column is `sql_text`.
- `DISTRIBUTED BY` columns must be the leading columns of the schema, in order.
- `DROP TABLE` deletes the topic and all its schema versions permanently.
- `Error while deserializing value ... offset 0` means the declared table schema
  does not match the records. Cause is a hand-written `CREATE TABLE` for a source
  topic, or stale records from an earlier format. Check with
  `SHOW CREATE TABLE access_logs_raw;` — if it lists columns you wrote, drop it and
  let Flink infer the table from Schema Registry instead.
- Never pre-create a source topic before its connector. Flink infers the table the
  moment the topic exists; if there is no schema yet it caches the value as raw
  bytes and every later read fails with `Error while deserializing`, even after the
  connector registers a correct Avro schema. Let the connector create the topic.
  To recover: delete the connector, `DROP TABLE <topic>` in Flink (clears topic,
  schema and cached metadata), then recreate the connector alone.
- Datagen writes a message key (`schema.keyfield`) with no key schema, so the
  inferred table has a leading `key BYTES` column. `INSERT INTO t VALUES (...)`
  then fails with `Different number of columns`. Use an explicit column list:
  `INSERT INTO access_logs_raw (event_time,user_id,...) VALUES (...)`.
- The managed Datagen connector rejects the `regex` annotation
  (`Regex annotation is disallowed in the schema`). Only `options`, `range` and
  `iteration` are accepted, so `session_id` uses a fixed `options` pool.
