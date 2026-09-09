-- Output tables. The two SOURCE tables are NOT created here: the Datagen
-- connectors own those topics and Confluent Flink infers them from Schema
-- Registry. Creating them by hand breaks every reader (see THREAT-SIM.md).

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
