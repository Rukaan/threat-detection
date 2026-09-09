-- What the rules caught, before the model sees it.
SELECT rule_id, user_id, source_ip, evidence FROM security_signals;

-- The triaged output.
SELECT
  detected_at, rule_id, user_id, source_ip,
  JSON_VALUE(triage, '$.severity')              AS severity,
  JSON_VALUE(triage, '$.mitre_technique')       AS mitre,
  JSON_VALUE(triage, '$.likely_false_positive') AS false_positive,
  JSON_VALUE(triage, '$.rationale')             AS rationale,
  JSON_VALUE(triage, '$.recommended_action')    AS recommended_action
FROM threat_alerts;
