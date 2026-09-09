-- Four deterministic detections. Each runs as its own long-running statement.
-- Run these BEFORE injecting the attack (04) so the windows are live.

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

INSERT INTO security_signals
SELECT
  'R2-' || session_id || '-' || CAST(`$rowtime` AS STRING),
  `$rowtime`, 'R2_SQLI_PATTERN', 'CRITICAL', user_id, client_ip,
  'db=' || db_name || '; rows=' || CAST(rows_returned AS STRING)
    || '; sql=' || SUBSTRING(sql_text FROM 1 FOR 300)
FROM query_logs_v2
WHERE REGEXP(UPPER(sql_text), '(UNION\s+(ALL\s+)?SELECT|OR\s+1\s*=\s*1|;\s*DROP\s+|;\s*DELETE\s+FROM|XP_CMDSHELL|INFORMATION_SCHEMA\.|PG_SLEEP\s*\(|BENCHMARK\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE)');

INSERT INTO security_signals
SELECT
  'R3-' || user_id || '-' || CAST(window_start AS STRING),
  window_end, 'R3_BULK_EXFIL', 'HIGH', user_id, MAX(client_ip),
  'rows_5min=' || CAST(SUM(rows_returned) AS STRING)
    || '; queries=' || CAST(COUNT(*) AS STRING)
    || '; distinct_dbs=' || CAST(COUNT(DISTINCT db_name) AS STRING)
    || '; max_single_query_rows=' || CAST(MAX(rows_returned) AS STRING)
FROM TABLE(TUMBLE(TABLE query_logs_v2, DESCRIPTOR(`$rowtime`), INTERVAL '5' MINUTE))
GROUP BY window_start, window_end, user_id
HAVING SUM(rows_returned) > 20000 AND MAX(rows_returned) > 5000;

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
