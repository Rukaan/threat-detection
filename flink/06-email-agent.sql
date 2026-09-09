-- =====================================================================
-- Email dispatch via a streaming agent + Zapier MCP.
--
-- STATUS: WRITTEN, NOT DEPLOYED. Nothing in this file has been run.
-- It follows the documented Confluent syntax for CREATE CONNECTION
-- ('mcp_server'), CREATE TOOL ('mcp'), CREATE AGENT and AI_RUN_AGENT,
-- but it is untested against a live Zapier MCP endpoint.
--
-- Three placeholders must be filled before it can work:
--   <ZAPIER_MCP_SSE_URL>  your Zapier MCP server URL (…/sse)
--   <ZAPIER_MCP_API_KEY>  the key Zapier issues with that URL
--   <SOC_INBOX>           who receives the mail
-- And confirm the real Gmail tool name your Zapier MCP server exposes;
-- 'gmail_send_email' is the usual one but it varies per configuration.
--
-- Runs AFTER 03-bedrock-inference.sql, and reads threat_alerts — so mail
-- is only ever sent for something the rules flagged AND the model rated.
-- =====================================================================

-- 1. Connection to the Zapier MCP server.
CREATE CONNECTION zapier_mcp_connection
WITH (
  'type'     = 'mcp_server',
  'endpoint' = '<ZAPIER_MCP_SSE_URL>',
  'api-key'  = '<ZAPIER_MCP_API_KEY>'
);

-- 2. Expose only the one tool the agent is allowed to call. Keep this list
--    minimal: an agent can call anything you grant it.
CREATE TOOL zapier_email_tool
USING CONNECTION zapier_mcp_connection
COMMENT 'Sends SOC alert email via Gmail through Zapier MCP'
WITH (
  'type'            = 'mcp',
  'allowed_tools'   = 'gmail_send_email',
  'request_timeout' = '30'
);

-- 3. The agent. Reuses the same Bedrock model already registered in 03.
CREATE AGENT email_dispatch_agent
USING MODEL threat_triage
USING PROMPT 'You are a SOC alert dispatcher. You receive one triaged security alert. Compose a concise incident email and send it with the gmail_send_email tool to <SOC_INBOX>. Subject line format: "[<severity>] <rule_id> - <user_id>". Body: what was detected, the evidence verbatim, the MITRE technique, and the recommended action, in that order, under 150 words. Send exactly one email, then stop. Do not invent details beyond the alert you were given.'
USING TOOLS zapier_email_tool
WITH ('max_iterations' = '5', 'max_consecutive_failures' = '2');

-- 4. Where dispatch outcomes land, so there is an audit trail of what was sent.
CREATE TABLE alert_dispatch_log (
  signal_id   STRING,
  detected_at TIMESTAMP_LTZ(3),
  rule_id     STRING,
  user_id     STRING,
  severity    STRING,
  dispatch    STRING       -- the agent's own account of what it did
) DISTRIBUTED BY HASH(signal_id) INTO 2 BUCKETS
WITH ('changelog.mode' = 'append', 'value.format' = 'avro-registry');

-- 5. Dispatch. The WHERE clause is the point: mail goes out only for HIGH or
--    CRITICAL alerts that the model did NOT mark a likely false positive.
--    Without this gate the benign control case (analyst_02 mistyping a
--    password, then logging in with MFA) would page a human every time.
INSERT INTO alert_dispatch_log
SELECT
  a.signal_id,
  a.detected_at,
  a.rule_id,
  a.user_id,
  JSON_VALUE(a.triage, '$.severity'),
  r.response
FROM threat_alerts AS a,
LATERAL TABLE(AI_RUN_AGENT(
  'email_dispatch_agent',
  'Triaged security alert.'  || CHR(10) ||
  'rule: '        || a.rule_id   || CHR(10) ||
  'user: '        || a.user_id   || CHR(10) ||
  'source_ip: '   || a.source_ip || CHR(10) ||
  'detected_at: ' || CAST(a.detected_at AS STRING) || CHR(10) ||
  'evidence: '    || a.evidence  || CHR(10) ||
  'severity: '           || JSON_VALUE(a.triage, '$.severity')           || CHR(10) ||
  'mitre_technique: '    || JSON_VALUE(a.triage, '$.mitre_technique')    || CHR(10) ||
  'rationale: '          || JSON_VALUE(a.triage, '$.rationale')          || CHR(10) ||
  'recommended_action: ' || JSON_VALUE(a.triage, '$.recommended_action'),
  a.signal_id
)) AS r
WHERE JSON_VALUE(a.triage, '$.severity') IN ('HIGH', 'CRITICAL')
  AND JSON_VALUE(a.triage, '$.likely_false_positive') <> 'true';

-- 6. Verify what was dispatched.
-- SELECT detected_at, rule_id, user_id, severity, dispatch FROM alert_dispatch_log;
