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

-- Security Center connection settings (key/value).
CREATE TABLE IF NOT EXISTS settings (
    k VARCHAR(64) PRIMARY KEY,
    v TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
