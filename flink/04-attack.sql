-- Attack simulation. Run each block separately, a few seconds apart.
-- Explicit column lists are required: the inferred tables carry a leading
-- 'key BYTES' column from the connector's message key.

INSERT INTO access_logs_raw (event_time,user_id,source_ip,auth_result,auth_method,service,geo_country,user_agent) VALUES
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','FAILURE','password','vpn','SG','python-requests/2.31'),
 (UNIX_TIMESTAMP()*1000,'contractor_07','203.0.113.44','SUCCESS','password','vpn','SG','python-requests/2.31');

INSERT INTO query_logs_v2 (event_time,user_id,session_id,client_ip,db_name,sql_text,rows_returned,duration_ms) VALUES
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT table_name FROM information_schema.tables',412,180),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM subscribers WHERE 1=1 UNION SELECT null,null,card_hash FROM billing.payment_tokens',48210,7400),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000',9000,3100),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000 OFFSET 9000',9000,3050),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000 OFFSET 18000',9000,3220),
 (UNIX_TIMESTAMP()*1000,'contractor_07','sess-deadbeef','203.0.113.44','crm','SELECT * FROM crm.subscribers LIMIT 9000 OFFSET 27000',9000,2980);

INSERT INTO access_logs_raw (event_time,user_id,source_ip,auth_result,auth_method,service,geo_country,user_agent) VALUES
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','FAILURE','password','warehouse','ID','Mozilla/5.0 (Macintosh)'),
 (UNIX_TIMESTAMP()*1000,'analyst_02','10.12.4.12','SUCCESS','mfa','warehouse','ID','Mozilla/5.0 (Macintosh)');
