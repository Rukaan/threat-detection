-- AI model inference. Run after 01 and 02 are up.
--
-- Fill in <MODEL_ID> and your own AWS credentials. Use an IAM user scoped to
-- bedrock:InvokeModel and nothing else. Confluent redacts these values when the
-- workspace is reloaded, but they are still live keys typed into a browser.
--
-- Model id comes from:
--   aws bedrock list-foundation-models --region ap-southeast-1 \
--     --query 'modelSummaries[?contains(modelId,`claude`)].modelId' --output table
-- APAC cross-region inference profiles carry an `apac.` or `global.` prefix.

CREATE CONNECTION bedrock_claude_connection
WITH (
  'type'           = 'bedrock',
  'endpoint'       = 'https://bedrock-runtime.ap-southeast-1.amazonaws.com/model/<MODEL_ID>/invoke',
  'aws-access-key' = '<AWS_ACCESS_KEY_ID>',
  'aws-secret-key' = '<AWS_SECRET_ACCESS_KEY>'
);

-- verify
SHOW CONNECTIONS;

CREATE MODEL threat_triage
INPUT  (prompt STRING)
OUTPUT (response STRING)
WITH (
  'provider'                   = 'bedrock',
  'task'                       = 'text_generation',
  'bedrock.connection'         = 'bedrock_claude_connection',
  'bedrock.PARAMS.max_tokens'  = '400',
  'bedrock.PARAMS.temperature' = '0',
  'bedrock.system_prompt'      = 'You are a SOC tier-2 analyst. You receive one security signal from a streaming detection pipeline over synthetic logs. Reply with ONLY a JSON object, no prose, with keys: severity (INFO|LOW|MEDIUM|HIGH|CRITICAL), confidence (0.0-1.0), mitre_technique (ATT&CK id and name, or "none"), rationale (max 30 words), recommended_action (max 20 words), likely_false_positive (true|false). Judge only on the evidence given; do not invent facts.'
);

-- Inference runs ONLY over security_signals, never the raw topics. The rules cut
-- hundreds of events/sec down to a handful of signals/min before the model is called.
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
