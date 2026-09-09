-- Output tables. The two SOURCE tables are NOT created here: the Datagen
-- connectors own those topics and Confluent Flink infers them from Schema
-- Registry. Creating them by hand breaks every reader (see THREAT-SIM.md).
--
-- Both are changelog.mode='append' with NO primary key, and that is load-bearing.
-- ML_PREDICT and AI_RUN_AGENT are non-deterministic, and Flink refuses to run a
-- non-deterministic function over a changelog that can retract and re-emit rows:
--   'can not satisfy the determinism requirement for correctly processing
--    update message'
-- Signals are immutable events, so append is also the correct model.

CREATE TABLE security_signals (
  signal_id     STRING,
  detected_at   TIMESTAMP_LTZ(3),
  rule_id       STRING,
  severity_hint STRING,
  user_id       STRING,
  source_ip     STRING,
  evidence      STRING
) DISTRIBUTED BY HASH(signal_id) INTO 2 BUCKETS
WITH ('changelog.mode' = 'append', 'value.format' = 'avro-registry');

CREATE TABLE threat_alerts (
  signal_id   STRING,
  detected_at TIMESTAMP_LTZ(3),
  rule_id     STRING,
  user_id     STRING,
  source_ip   STRING,
  evidence    STRING,
  triage      STRING
) DISTRIBUTED BY HASH(signal_id) INTO 2 BUCKETS
WITH ('changelog.mode' = 'append', 'value.format' = 'avro-registry');
