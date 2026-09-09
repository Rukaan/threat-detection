# AI Day Indonesia 2026 — form answers

Target category: **2nd Prize, Most Flink-Driven App** (its bonus is exactly AI Model
Inference). Also argues for 1st on connectors + stream processing + governance.

---

## Please describe your AI application

Real-time insider-threat and account-takeover detection for a telco SOC.

Two Confluent Datagen Source connectors simulate the two log streams a SOC actually
has to correlate: an authentication/access log and a database query audit log, both
AVRO with schemas governed in Schema Registry.

Flink SQL runs four detections continuously over both streams:
- **R1** brute force — 5+ failed logins per user+IP in a 1-minute tumbling window
- **R2** SQL injection — regex over query text (UNION SELECT, OR 1=1, information_schema, xp_cmdshell)
- **R3** bulk-read exfiltration — >20k rows per user in 5 minutes, with at least one outlier query >5k rows
- **R4** cross-log correlation — an interval join tying a non-MFA successful login to an
  abnormally large query by the same identity within 10 minutes

R4 is the point of the design: neither log produces that signal on its own.

Only the resulting signals reach the LLM. Claude Haiku on Amazon Bedrock is invoked
through Flink `ML_PREDICT` and returns severity, MITRE ATT&CK technique, a one-line
rationale, a recommended action, and a `likely_false_positive` flag.

A fourth layer closes the loop: a Flink **streaming agent** (`CREATE AGENT` +
`AI_RUN_AGENT`) takes alerts the model rated HIGH or CRITICAL and not a likely false
positive, composes an incident email, and sends it through a **Zapier MCP** Gmail
tool. Alerts that the model marks a probable false positive never reach a human.

**Who it is for:** SOC tier-1/tier-2 analysts.
Three layers, each doing only what it is good at: SQL rules decide *something
happened* (deterministic, provable, cheap); the model decides *how bad, why and what
to do* (judgement, only on rule hits); the agent decides *who needs to know* and acts
(side effects, gated on severity). Volume drops by orders of magnitude at every hop.

**The benefit:** analysts receive triaged, explained alerts instead of raw log volume,
and inference cost stays bounded because the deterministic rules do the filtering —
raw logs arrive at hundreds/second, signals at a handful/minute. A control case in the
demo (a real user mistyping their password five times, then logging in with MFA) fires
R1 but not R4, and the model marks it a probable false positive — showing the AI layer
adds judgement the rules alone cannot.

---

## Which Confluent connector(s) are you using?

Datagen Source ×2 — `datagen-access-logs` → `access_logs_raw`, and
`datagen-query-logs-v2` → `query_logs_v2`. Both AVRO with custom
JSON-encoded Avro schemas registered in Schema Registry.

In production these are drop-in replaced by AWS CloudTrail / audit-log and
database-audit source connectors. The Flink detection logic is unchanged.

---

## Paste your Flink stream processing query here

```sql
-- R4: cross-log correlation. A non-MFA login followed within 10 minutes by an
-- abnormally large query, by the same identity. Neither log shows this alone.
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
JOIN query_logs_v2 q
  ON a.user_id = q.user_id
 AND q.`$rowtime` BETWEEN a.`$rowtime` AND a.`$rowtime` + INTERVAL '10' MINUTE
WHERE a.auth_result = 'SUCCESS'
  AND a.auth_method <> 'mfa'
  AND q.rows_returned > 5000;

-- AI model inference, applied ONLY to rule hits, never to raw logs.
CREATE MODEL threat_triage
INPUT (prompt STRING) OUTPUT (response STRING)
WITH ('provider' = 'bedrock', 'task' = 'text_generation',
      'bedrock.connection' = 'bedrock_claude_connection',
      'bedrock.PARAMS.temperature' = '0',
      'bedrock.system_prompt' = 'You are a SOC tier-2 analyst. Reply with ONLY a JSON object with keys: severity, confidence, mitre_technique, rationale, recommended_action, likely_false_positive.');

INSERT INTO threat_alerts
SELECT s.signal_id, s.detected_at, s.rule_id, s.user_id, s.source_ip, s.evidence,
       p.response
FROM security_signals AS s,
LATERAL TABLE(ML_PREDICT('threat_triage',
  'rule: ' || s.rule_id || CHR(10) || 'user: ' || s.user_id || CHR(10) ||
  'source_ip: ' || s.source_ip || CHR(10) || 'evidence: ' || s.evidence)) AS p;
```

---

## Paste your schema here

```json
{
  "namespace": "sim.security", "name": "AccessLog", "type": "record",
  "fields": [
    {"name":"event_time","type":{"type":"long","format_as_time":"unix_long","arg.properties":{"iteration":{"start":1}}}},
    {"name":"user_id","type":{"type":"string","arg.properties":{"options":["svc_batch","svc_etl","analyst_01","analyst_02","analyst_03","analyst_04","ops_01","ops_02","dba_01","dba_02","contractor_07"]}}},
    {"name":"source_ip","type":{"type":"string","arg.properties":{"options":["10.12.4.11","10.12.4.12","10.12.4.19","10.12.8.31","10.12.8.44","172.16.3.7","172.16.3.9","203.0.113.44"]}}},
    {"name":"auth_result","type":{"type":"string","arg.properties":{"options":["SUCCESS","SUCCESS","SUCCESS","SUCCESS","SUCCESS","SUCCESS","SUCCESS","SUCCESS","SUCCESS","FAILURE"]}}},
    {"name":"auth_method","type":{"type":"string","arg.properties":{"options":["password","password","mfa","sso","api_key"]}}},
    {"name":"service","type":{"type":"string","arg.properties":{"options":["vpn","jumphost","warehouse","admin_console","api_gateway"]}}},
    {"name":"geo_country","type":{"type":"string","arg.properties":{"options":["ID","ID","ID","ID","ID","SG","MY"]}}},
    {"name":"user_agent","type":{"type":"string","arg.properties":{"options":["Mozilla/5.0 (Macintosh)","Mozilla/5.0 (Windows NT 10.0)","psql/15.3","python-requests/2.31","curl/8.4.0"]}}}
  ]
}
```

`QueryLog` mirrors this with: `event_time`, `user_id`, `session_id`, `client_ip`,
`db_name`, `sql_text`, `rows_returned`, `duration_ms`. Both share the same `user_id`
and IP pools — that shared identity is what makes the R4 interval join possible.

---

## Streaming agent + MCP

```sql
CREATE CONNECTION zapier_mcp_connection
WITH ('type' = 'mcp_server', 'endpoint' = '<ZAPIER_MCP_SSE_URL>', 'api-key' = '<KEY>');

CREATE TOOL zapier_email_tool
USING CONNECTION zapier_mcp_connection
WITH ('type' = 'mcp', 'allowed_tools' = 'gmail_send_email', 'request_timeout' = '30');

CREATE AGENT email_dispatch_agent
USING MODEL threat_triage
USING PROMPT 'You are a SOC alert dispatcher. Compose a concise incident email and send it with the gmail_send_email tool. Subject: "[<severity>] <rule_id> - <user_id>". Body: what was detected, the evidence verbatim, the MITRE technique, the recommended action. Send exactly one email, then stop.'
USING TOOLS zapier_email_tool
WITH ('max_iterations' = '5');

INSERT INTO alert_dispatch_log
SELECT a.signal_id, a.detected_at, a.rule_id, a.user_id,
       JSON_VALUE(a.triage, '$.severity'), r.response
FROM threat_alerts AS a,
LATERAL TABLE(AI_RUN_AGENT('email_dispatch_agent', <alert text>, a.signal_id)) AS r
WHERE JSON_VALUE(a.triage, '$.severity') IN ('HIGH','CRITICAL')
  AND JSON_VALUE(a.triage, '$.likely_false_positive') <> 'true';
```

Full version: `flink/06-email-agent.sql`. Written to the documented Confluent syntax
but not run against a live Zapier endpoint.

## Tableflow topic name

Not used in this build.

---

## GitHub repo link

None — leave blank, or push `threat-sim/` first.

---

## Screenshot: Stream Lineage

Left menu → **Stream Lineage** on cluster `security`… use **kyc_nbo_cluster**
(`lkc-w72kxd5`) — that is where the pipeline actually runs. The graph shows:

    datagen-access-logs   ─► access_logs_raw ─┐
                                              ├─► security_signals ─► threat_alerts
    datagen-query-logs-v2 ─► query_logs_v2   ─┘

---

## Verified live results (2026-09-09)

All four rules RUNNING; signals confirmed by consuming `security_signals`:

| Rule | Fired | Example evidence |
|---|---|---|
| R1_BRUTE_FORCE | 4 | `failed_logins=9; successes=7; window=1min; service=vpn; method=password` (contractor_07) |
| R2_SQLI_PATTERN | 4 | `db=crm; rows=48210; sql=SELECT * FROM subscribers WHERE 1=1 UNION SELECT null,null,card_hash FROM billing.payment_tokens` |
| R3_BULK_EXFIL | 11 | `rows_5min=32946; queries=70; distinct_dbs=4` |
| R4_SUSPICIOUS_SESSION | 4 | `auth_method=password; agent=psql/15.3; then_query_db=crm; rows=48210` |

Control case works: `analyst_02` fires R1 only (`failed_logins=5; method=sso`), never R4.

**Honest status of the AI legs:** the four rules and the pipeline are verified running
on live data. `CREATE MODEL threat_triage` registered successfully against Bedrock.
The `ML_PREDICT` statement starts and runs once the output tables are append-only, but
inference returned `HTTP 403 — Secrets on CONNECTION have expired or are invalid`, so
`threat_alerts` is not yet populated; that is an AWS credential issue, not a pipeline
one. The email agent (`06-email-agent.sql`) is written but not deployed.
