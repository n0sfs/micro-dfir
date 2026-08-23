PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'analyst');
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME NOT NULL, source_ip TEXT, hostname TEXT, app_name TEXT, facility TEXT, severity TEXT, message TEXT NOT NULL, raw_json TEXT, entity_type TEXT);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE TABLE IF NOT EXISTS live_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME NOT NULL, host TEXT, app TEXT, severity TEXT, event_id TEXT, username TEXT, source_ip TEXT, destination_ip TEXT, message TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_live_logs_timestamp ON live_logs(timestamp);
CREATE TABLE IF NOT EXISTS sigma_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, rule_yaml TEXT NOT NULL, enabled BOOLEAN DEFAULT 0, source TEXT DEFAULT 'sigma', sigma_uuid TEXT, cloned_from INTEGER, created_by TEXT, created_at DATETIME, updated_by TEXT, updated_at DATETIME, severity_override TEXT, compliance_tags TEXT);
CREATE TABLE IF NOT EXISTS sigma_rule_history (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL, changed_by TEXT, changed_at DATETIME DEFAULT CURRENT_TIMESTAMP, old_yaml TEXT, new_yaml TEXT);
CREATE INDEX IF NOT EXISTS idx_sigma_rule_history_rule ON sigma_rule_history(rule_id);
CREATE TABLE IF NOT EXISTS rule_exclusions (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL, field TEXT NOT NULL, operator TEXT NOT NULL DEFAULT 'contains', value TEXT NOT NULL, description TEXT, enabled BOOLEAN DEFAULT 1, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_rule_exclusions_rule ON rule_exclusions(rule_id);
CREATE TABLE IF NOT EXISTS yara_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, rule_text TEXT NOT NULL, enabled BOOLEAN DEFAULT 1);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, rule_id INTEGER, event_id INTEGER, rule_name TEXT, host TEXT, message TEXT, severity TEXT, acknowledged BOOLEAN DEFAULT 0, username TEXT, source_ip TEXT, destination_ip TEXT, log_event_id TEXT, log_app TEXT, FOREIGN KEY(rule_id) REFERENCES sigma_rules(id), FOREIGN KEY(event_id) REFERENCES live_logs(id));
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE TABLE IF NOT EXISTS drop_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, field TEXT NOT NULL, operator TEXT NOT NULL, value TEXT NOT NULL, description TEXT, enabled BOOLEAN DEFAULT 1);
CREATE TABLE IF NOT EXISTS stix_indicators (stix_id TEXT PRIMARY KEY, type TEXT NOT NULL, ioc_type TEXT, name TEXT, description TEXT, pattern TEXT NOT NULL, valid_from DATETIME, revoked BOOLEAN DEFAULT 0, inserted_at DATETIME DEFAULT CURRENT_TIMESTAMP, feed_id INTEGER);
CREATE INDEX IF NOT EXISTS idx_stix_pattern ON stix_indicators(pattern);
CREATE TABLE IF NOT EXISTS ti_feeds (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, feed_type TEXT NOT NULL, discovery_url TEXT, collection_id TEXT, username TEXT, password TEXT, api_key TEXT, sync_interval_minutes INTEGER, enabled BOOLEAN DEFAULT 1, last_sync DATETIME, last_status TEXT, last_count INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO ti_feeds (id, name, feed_type, enabled) VALUES (1, 'ThreatFox Recent (Public)', 'threatfox', 1);
CREATE TABLE IF NOT EXISTS agent_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL, label TEXT NOT NULL, script TEXT NOT NULL, status TEXT DEFAULT 'pending', queued_by TEXT, queued_at DATETIME DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME, exit_code INTEGER, stdout TEXT, stderr TEXT);
CREATE INDEX IF NOT EXISTS idx_agent_commands_host_status ON agent_commands(hostname, status);
CREATE TABLE IF NOT EXISTS ueba_exclusions (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, description TEXT, enabled BOOLEAN DEFAULT 1, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_ueba_exclusions_entity ON ueba_exclusions(entity_type, entity_id);
CREATE TABLE IF NOT EXISTS ueba_entity_baselines (entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, current_count INTEGER, baseline_avg REAL, baseline_stddev REAL, threshold REAL, is_anomalous BOOLEAN DEFAULT 0, excluded BOOLEAN DEFAULT 0, days_seen INTEGER, baseline_mode TEXT, computed_at DATETIME, PRIMARY KEY (entity_type, entity_id));
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, username TEXT, role TEXT, ip_address TEXT, action TEXT NOT NULL, target_type TEXT, target_id TEXT, details TEXT);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE TABLE IF NOT EXISTS risk_score_events (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, indicator TEXT NOT NULL, points INTEGER NOT NULL, detail TEXT, source_table TEXT, source_id TEXT, rule_id INTEGER, computed_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_risk_score_events_entity ON risk_score_events(entity_type, entity_id, computed_at);
CREATE INDEX IF NOT EXISTS idx_risk_score_events_rule ON risk_score_events(rule_id);
CREATE TABLE IF NOT EXISTS anomaly_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, source TEXT NOT NULL, entity_field TEXT NOT NULL, entity_type TEXT NOT NULL, points INTEGER NOT NULL, first_time_bonus_points INTEGER, enabled BOOLEAN DEFAULT 1, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_by TEXT, updated_at DATETIME);
-- A rule's conditions combine left-to-right via each condition's own logic (AND/OR,
-- default AND; the first condition's logic is stored but ignored, nothing precedes it)
-- -- mirrors rule_exclusions' own rule_id/field/operator/value shape above, the same
-- one-to-many-conditions pattern already established for Sigma rule exclusions, reused
-- here instead of inventing a new one.
CREATE TABLE IF NOT EXISTS anomaly_rule_conditions (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL, field TEXT NOT NULL, operator TEXT NOT NULL DEFAULT 'equals', value TEXT NOT NULL, logic TEXT NOT NULL DEFAULT 'AND', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_anomaly_rule_conditions_rule ON anomaly_rule_conditions(rule_id);
