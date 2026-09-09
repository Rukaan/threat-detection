# Streaming threat detection on Confluent Cloud

Real-time insider-threat and account-takeover detection. Two Datagen connectors feed
an authentication log and a database query audit log; Flink SQL runs four detections
across both streams; only rule hits are sent to Claude on Amazon Bedrock via
`ML_PREDICT` for triage.

    datagen ─► access_logs_raw ─┐
                                ├─ Flink R1..R4 ─► security_signals
    datagen ─► query_logs_v2   ─┘                        │
                                                  ML_PREDICT (Bedrock)
                                                         ▼
                                                   threat_alerts
                                                         │  HIGH/CRITICAL
                                                         │  and not a false positive
                                                  AI_RUN_AGENT + Zapier MCP
                                                         ▼
                                                  alert_dispatch_log ─► email

    Tableflow: security_signals + threat_alerts also materialize as Apache Iceberg
    tables on managed storage, queryable from Athena / Trino / Snowflake.

Rules run on every event; the model runs only on what the rules flag. Raw logs arrive
at hundreds/second, signals at a handful/minute — that split is what keeps inference
affordable.

**R4** is the rule worth reading: an interval join tying a non-MFA login to an
abnormally large query by the same identity within 10 minutes. Neither log produces
that signal alone.

## Layout

    connectors/
      datagen-access-logs.json     Datagen Source config -> access_logs_raw
      datagen-query-logs-v2.json   Datagen Source config -> query_logs_v2
      access_log.avsc              Avro schema, standalone (paste into the connector UI)
      query_log.avsc
    flink/
      01-output-tables.sql         security_signals + threat_alerts
      02-detections.sql            R1..R4, one statement each
      03-bedrock-inference.sql     CREATE CONNECTION, CREATE MODEL, ML_PREDICT
      04-attack.sql                the simulated attack + a benign control case
      05-verify.sql                what fired, and how the model triaged it
      06-email-agent.sql           streaming agent + Zapier MCP email dispatch
                                   (written, NOT deployed — see the file header)

## Docs

- [THREAT-SIM.md](THREAT-SIM.md) — full runbook, live resource ids, and the gotchas
  hit while building this (schema-type collisions, reserved keywords, why you must
  never hand-create a connector-owned topic)
- [SUBMISSION.md](SUBMISSION.md) — AI Day Indonesia 2026 answers and verified results

## Order of operations

1. Create the two Datagen connectors from `connectors/` (output format **AVRO**).
   Let them create their own topics — do not pre-create them.
2. `flink/01-output-tables.sql`
3. `flink/02-detections.sql` — four separate statements, leave them running
4. `flink/03-bedrock-inference.sql` — needs your AWS credentials
5. `flink/04-attack.sql`, then `flink/05-verify.sql`
6. `flink/06-email-agent.sql` — optional email leg. Untested; needs a Zapier MCP
   URL, its API key, and a recipient address.

Three layers, each doing only what it is good at: **SQL rules** decide *something
happened* (deterministic, provable, cheap). **The model** decides *how bad, why, and
what to do* (judgement, applied only to rule hits). **The agent** decides *who needs
to know* and acts (side effects, gated on severity). Volume drops by orders of
magnitude at every hop, which is what makes the expensive layers affordable.

All data is synthetic. No real accounts, hosts, or customer data.
