-- Rev3 v1. Apply only to a dedicated, empty schema. No runtime activation.
-- MySQL 8.4 / MariaDB 10.4 compatible InnoDB; all timestamps are UTC.
-- DDL commits implicitly. Apply schema separately from transactional data import.
SET NAMES utf8mb4;
SET SESSION sql_mode='STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';
SET time_zone='+00:00';

CREATE TABLE sdr_schema_migrations (
  version INT NOT NULL PRIMARY KEY,
  applied_at DATETIME(6) NOT NULL,
  description VARCHAR(255) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE sdr_migration_batches (
  snapshot_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  captured_at DATETIME(6) NOT NULL,
  expected_files INT UNSIGNED NOT NULL,
  traffic_records BIGINT UNSIGNED NOT NULL,
  state VARCHAR(16) NOT NULL DEFAULT 'staged',
  CHECK (state = 'staged')
) ENGINE=InnoDB;

-- Private compatibility archive: exact bytes for reconciliation and rollback.
-- No .env, API login, private key, bootstrap bundle or router secrets are imported.
-- This is never a runtime JSON backend or an authorization to use these records.
CREATE TABLE sdr_migration_files (
  snapshot_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  file_name VARCHAR(192) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  byte_count BIGINT UNSIGNED NOT NULL,
  sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  expected_chunks INT UNSIGNED NOT NULL,
  PRIMARY KEY (snapshot_id, file_name),
  FOREIGN KEY (snapshot_id) REFERENCES sdr_migration_batches(snapshot_id)
) ENGINE=InnoDB;

CREATE TABLE sdr_migration_chunks (
  snapshot_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  file_name VARCHAR(192) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  chunk_number INT UNSIGNED NOT NULL,
  byte_count INT UNSIGNED NOT NULL,
  sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  payload MEDIUMBLOB NOT NULL,
  PRIMARY KEY (snapshot_id,file_name,chunk_number),
  FOREIGN KEY (snapshot_id,file_name) REFERENCES sdr_migration_files(snapshot_id,file_name),
  CHECK (byte_count BETWEEN 1 AND 131072 AND OCTET_LENGTH(payload) = byte_count)
) ENGINE=InnoDB;

CREATE TABLE sdr_routers (
  router_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
  display_name VARCHAR(128) NOT NULL,
  management_address VARCHAR(45) NULL,
  controller_auth_ref VARCHAR(64) NULL,
  monitoring_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at DATETIME(6) NOT NULL,
  CHECK (monitoring_enabled IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_router_sources (
  router_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
  source_address VARCHAR(45) NOT NULL,
  PRIMARY KEY (router_id, source_address),
  FOREIGN KEY (router_id) REFERENCES sdr_routers(router_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_link_pairs (
  pair_id VARCHAR(64) NOT NULL PRIMARY KEY,
  display_name VARCHAR(128) NOT NULL,
  site_a VARCHAR(128) NOT NULL,
  site_b VARCHAR(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_links (
  link_id VARCHAR(64) NOT NULL PRIMARY KEY,
  pair_id VARCHAR(64) NOT NULL,
  router_id VARCHAR(128) NOT NULL,
  tx_interface VARCHAR(128) NOT NULL,
  capacity_bps BIGINT UNSIGNED NULL,
  minimum_cost SMALLINT UNSIGNED NULL,
  normal_cost SMALLINT UNSIGNED NULL,
  maximum_cost SMALLINT UNSIGNED NULL,
  FOREIGN KEY (pair_id) REFERENCES sdr_link_pairs(pair_id),
  FOREIGN KEY (router_id) REFERENCES sdr_routers(router_id),
  CHECK (capacity_bps IS NULL OR capacity_bps > 0),
  CHECK ((minimum_cost IS NULL AND normal_cost IS NULL AND maximum_cost IS NULL)
    OR (minimum_cost IS NOT NULL AND normal_cost IS NOT NULL AND maximum_cost IS NOT NULL
      AND minimum_cost > 0 AND minimum_cost <= normal_cost AND normal_cost <= maximum_cost))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_ospf_resources (
  resource_id VARCHAR(64) NOT NULL PRIMARY KEY,
  link_id VARCHAR(64) NOT NULL,
  router_id VARCHAR(128) NOT NULL,
  resource_kind VARCHAR(16) NOT NULL,
  resource_selector VARCHAR(128) NOT NULL,
  routeros_version VARCHAR(32) NOT NULL,
  scope_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (link_id, router_id),
  FOREIGN KEY (link_id) REFERENCES sdr_links(link_id),
  FOREIGN KEY (router_id) REFERENCES sdr_routers(router_id),
  CHECK (resource_kind IN ('interface','template')),
  CHECK (scope_confirmed IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_staff (
  staff_id VARCHAR(64) NOT NULL PRIMARY KEY,
  login_name VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role_name VARCHAR(16) NOT NULL,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  CHECK (role_name IN ('viewer','operator','administrator')),
  CHECK (active IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_policy_versions (
  policy_version VARCHAR(64) NOT NULL PRIMARY KEY,
  created_at DATETIME(6) NOT NULL,
  created_by VARCHAR(64) NOT NULL,
  mode_name VARCHAR(16) NOT NULL DEFAULT 'Test',
  interval_seconds INT NOT NULL,
  definition LONGTEXT NOT NULL,
  FOREIGN KEY (created_by) REFERENCES sdr_staff(staff_id),
  CHECK (mode_name IN ('Test','Manual','Automatic')),
  CHECK (interval_seconds IN (300,600,900)),
  CHECK (JSON_VALID(definition))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_link_thresholds (
  policy_version VARCHAR(64) NOT NULL,
  link_id VARCHAR(64) NOT NULL,
  utilization_percent DECIMAL(12,6) NOT NULL,
  latency_ms DECIMAL(18,6) NOT NULL,
  jitter_ms DECIMAL(18,6) NOT NULL,
  PRIMARY KEY (policy_version,link_id),
  FOREIGN KEY (policy_version) REFERENCES sdr_policy_versions(policy_version),
  FOREIGN KEY (link_id) REFERENCES sdr_links(link_id),
  CHECK (utilization_percent > 0 AND latency_ms >= 0 AND jitter_ms >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_measurement_checks (
  check_id VARCHAR(64) NOT NULL PRIMARY KEY,
  policy_version VARCHAR(64) NOT NULL,
  scheduled_at DATETIME(6) NOT NULL,
  completed_at DATETIME(6) NULL,
  status_name VARCHAR(16) NOT NULL,
  UNIQUE (policy_version,scheduled_at),
  FOREIGN KEY (policy_version) REFERENCES sdr_policy_versions(policy_version),
  CHECK (status_name IN ('pending','completed','unknown'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_measurements (
  measurement_id VARCHAR(64) NOT NULL PRIMARY KEY,
  check_id VARCHAR(64) NOT NULL,
  link_id VARCHAR(64) NOT NULL,
  observed_at DATETIME(6) NOT NULL,
  tx_octets BIGINT UNSIGNED NULL,
  tx_mbps DECIMAL(24,9) NULL,
  utilization_percent DECIMAL(18,6) NULL,
  latency_ms DECIMAL(18,6) NULL,
  jitter_ms DECIMAL(18,6) NULL,
  status_name VARCHAR(16) NOT NULL,
  provenance LONGTEXT NOT NULL,
  UNIQUE (check_id,link_id),
  FOREIGN KEY (check_id) REFERENCES sdr_measurement_checks(check_id),
  FOREIGN KEY (link_id) REFERENCES sdr_links(link_id),
  CHECK (status_name IN ('healthy','congested','unknown')),
  CHECK (tx_mbps IS NULL OR tx_mbps >= 0),
  CHECK (utilization_percent IS NULL OR utilization_percent >= 0),
  CHECK (latency_ms IS NULL OR latency_ms >= 0),
  CHECK (jitter_ms IS NULL OR jitter_ms >= 0),
  CHECK (status_name = 'unknown' OR (tx_mbps IS NOT NULL AND utilization_percent IS NOT NULL
    AND latency_ms IS NOT NULL AND jitter_ms IS NOT NULL)),
  CHECK (JSON_VALID(provenance)),
  INDEX sdr_measurements_daily (link_id,observed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_confirmation_state (
  link_id VARCHAR(64) NOT NULL,
  policy_version VARCHAR(64) NOT NULL,
  last_check_id VARCHAR(64) NOT NULL,
  congested_checks TINYINT UNSIGNED NOT NULL DEFAULT 0,
  healthy_checks TINYINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (link_id,policy_version),
  FOREIGN KEY (link_id) REFERENCES sdr_links(link_id),
  FOREIGN KEY (policy_version) REFERENCES sdr_policy_versions(policy_version),
  FOREIGN KEY (last_check_id) REFERENCES sdr_measurement_checks(check_id),
  CHECK (congested_checks <= 2 AND healthy_checks <= 2),
  CHECK (congested_checks = 0 OR healthy_checks = 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_decisions (
  decision_id VARCHAR(64) NOT NULL PRIMARY KEY,
  check_id VARCHAR(64) NOT NULL,
  pair_id VARCHAR(64) NOT NULL,
  policy_version VARCHAR(64) NOT NULL,
  decided_at DATETIME(6) NOT NULL,
  reason_code VARCHAR(64) NOT NULL,
  evidence LONGTEXT NOT NULL,
  UNIQUE (check_id,pair_id),
  FOREIGN KEY (check_id) REFERENCES sdr_measurement_checks(check_id),
  FOREIGN KEY (pair_id) REFERENCES sdr_link_pairs(pair_id),
  FOREIGN KEY (policy_version) REFERENCES sdr_policy_versions(policy_version),
  CHECK (JSON_VALID(evidence))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_proposed_costs (
  decision_id VARCHAR(64) NOT NULL,
  link_id VARCHAR(64) NOT NULL,
  proposed_cost SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (decision_id,link_id),
  FOREIGN KEY (decision_id) REFERENCES sdr_decisions(decision_id),
  FOREIGN KEY (link_id) REFERENCES sdr_links(link_id),
  CHECK (proposed_cost > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_approvals (
  approval_id VARCHAR(64) NOT NULL PRIMARY KEY,
  decision_id VARCHAR(64) NOT NULL,
  policy_version VARCHAR(64) NOT NULL,
  staff_id VARCHAR(64) NOT NULL,
  proposal_sha256 CHAR(64) CHARACTER SET ascii NOT NULL,
  approved_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  FOREIGN KEY (decision_id) REFERENCES sdr_decisions(decision_id),
  FOREIGN KEY (policy_version) REFERENCES sdr_policy_versions(policy_version),
  FOREIGN KEY (staff_id) REFERENCES sdr_staff(staff_id),
  CHECK (expires_at > approved_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_releases (
  release_id VARCHAR(64) NOT NULL PRIMARY KEY,
  pair_id VARCHAR(64) NOT NULL,
  policy_version VARCHAR(64) NOT NULL,
  decision_id VARCHAR(64) NULL,
  approval_id VARCHAR(64) NULL,
  mode_name VARCHAR(16) NOT NULL,
  issued_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  FOREIGN KEY (pair_id) REFERENCES sdr_link_pairs(pair_id),
  FOREIGN KEY (policy_version) REFERENCES sdr_policy_versions(policy_version),
  FOREIGN KEY (decision_id) REFERENCES sdr_decisions(decision_id),
  FOREIGN KEY (approval_id) REFERENCES sdr_approvals(approval_id),
  CHECK (mode_name IN ('Test','Manual','Automatic')),
  CHECK (mode_name <> 'Manual' OR approval_id IS NOT NULL),
  CHECK (expires_at > issued_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_released_costs (
  release_id VARCHAR(64) NOT NULL,
  resource_id VARCHAR(64) NOT NULL,
  released_cost SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (release_id,resource_id),
  FOREIGN KEY (release_id) REFERENCES sdr_releases(release_id),
  FOREIGN KEY (resource_id) REFERENCES sdr_ospf_resources(resource_id),
  CHECK (released_cost > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_router_checkins (
  checkin_id VARCHAR(64) NOT NULL PRIMARY KEY,
  router_id VARCHAR(128) NOT NULL,
  protocol_name VARCHAR(16) NOT NULL,
  request_id VARCHAR(64) NOT NULL,
  received_at DATETIME(6) NOT NULL,
  source_address VARCHAR(45) NOT NULL,
  release_id VARCHAR(64) NULL,
  UNIQUE (router_id,protocol_name,request_id),
  FOREIGN KEY (router_id) REFERENCES sdr_routers(router_id),
  FOREIGN KEY (release_id) REFERENCES sdr_releases(release_id),
  INDEX sdr_checkins_daily (router_id,received_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_application_reports (
  report_id VARCHAR(64) NOT NULL PRIMARY KEY,
  router_id VARCHAR(128) NOT NULL,
  release_id VARCHAR(64) NOT NULL,
  resource_id VARCHAR(64) NOT NULL,
  reported_at DATETIME(6) NOT NULL,
  actual_cost SMALLINT UNSIGNED NULL,
  result_name VARCHAR(16) NOT NULL,
  FOREIGN KEY (router_id) REFERENCES sdr_routers(router_id),
  FOREIGN KEY (release_id) REFERENCES sdr_releases(release_id),
  FOREIGN KEY (resource_id) REFERENCES sdr_ospf_resources(resource_id),
  CHECK (result_name IN ('applied','not_applied','rejected','failed')),
  CHECK (result_name <> 'applied' OR (actual_cost IS NOT NULL AND actual_cost > 0)),
  INDEX sdr_reports_daily (router_id,reported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_alerts (
  alert_id VARCHAR(64) NOT NULL PRIMARY KEY,
  deduplication_key VARCHAR(192) NOT NULL UNIQUE,
  alert_kind VARCHAR(32) NOT NULL,
  opened_at DATETIME(6) NOT NULL,
  resolved_at DATETIME(6) NULL,
  CHECK (alert_kind IN ('measurement_failure','missing_checkin','cost_mismatch'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE sdr_audit_events (
  event_id VARCHAR(64) NOT NULL PRIMARY KEY,
  recorded_at DATETIME(6) NOT NULL,
  actor_id VARCHAR(128) NOT NULL,
  event_kind VARCHAR(64) NOT NULL,
  subject_id VARCHAR(128) NULL,
  details LONGTEXT NOT NULL,
  CHECK (JSON_VALID(details)),
  INDEX sdr_audit_daily (recorded_at,event_kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO sdr_schema_migrations (version,applied_at,description)
VALUES (1,UTC_TIMESTAMP(6),'Rev3 staging archive and relational foundation; runtime remains JSON');
