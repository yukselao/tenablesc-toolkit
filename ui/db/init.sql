-- Schema for the Nessus Compare UI.
-- Loaded automatically by MariaDB on first container start.
-- (Db::ensureSchema() also creates/updates these on connect, so pre-existing
--  volumes are migrated without a hard reset.)

CREATE TABLE IF NOT EXISTS analyses (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source         VARCHAR(16) NOT NULL DEFAULT 'file',   -- 'file' | 'sc'
    first_filename VARCHAR(255) NOT NULL,
    last_filename  VARCHAR(255) NOT NULL,
    first_hosts    INT NOT NULL DEFAULT 0,
    last_hosts     INT NOT NULL DEFAULT 0,
    new_hosts      INT NOT NULL DEFAULT 0,
    new_ports      INT NOT NULL DEFAULT 0,
    unreachable    INT NOT NULL DEFAULT 0,
    result_json    LONGTEXT,
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security Center connection settings + cache meta (key/value).
CREATE TABLE IF NOT EXISTS settings (
    k VARCHAR(64) PRIMARY KEY,
    v TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Local cache of SC scan results (filled by "Fetch All Scan Results").
CREATE TABLE IF NOT EXISTS sc_scan_results (
    id          INT PRIMARY KEY,
    name        VARCHAR(512) NOT NULL,
    status      VARCHAR(32),
    result_type VARCHAR(32),
    finish_time BIGINT NOT NULL DEFAULT 0,
    start_time  BIGINT NOT NULL DEFAULT 0,
    scanned_ips VARCHAR(32),
    repository  VARCHAR(255),
    can_use     TINYINT(1) NOT NULL DEFAULT 1,
    owner       VARCHAR(255),
    synced_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name(191)),
    INDEX idx_finish (finish_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
