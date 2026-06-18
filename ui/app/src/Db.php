<?php
/**
 * Db — thin MariaDB (PDO) helper used to persist analysis history.
 *
 * The app degrades gracefully when the database is unavailable: the comparison
 * itself never depends on the DB, only the history sidebar does.
 */
class Db
{
    private static ?PDO $pdo = null;
    private static ?string $error = null;

    public static function pdo(): ?PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }
        $host = getenv('DB_HOST') ?: 'db';
        $name = getenv('DB_NAME') ?: 'nessus_compare';
        $user = getenv('DB_USER') ?: 'nessus';
        $pass = getenv('DB_PASS') ?: 'nessus';
        try {
            self::$pdo = new PDO(
                "mysql:host=$host;dbname=$name;charset=utf8mb4",
                $user,
                $pass,
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_TIMEOUT            => 3,
                ]
            );
            self::ensureSchema(self::$pdo);
            return self::$pdo;
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return null;
        }
    }

    public static function error(): ?string
    {
        return self::$error;
    }

    /** Create tables / columns if missing (handles pre-existing DB volumes). */
    private static function ensureSchema(PDO $pdo): void
    {
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS analyses (
                id             INT AUTO_INCREMENT PRIMARY KEY,
                created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source         VARCHAR(16) NOT NULL DEFAULT "file",
                first_filename VARCHAR(255) NOT NULL,
                last_filename  VARCHAR(255) NOT NULL,
                first_hosts    INT NOT NULL DEFAULT 0,
                last_hosts     INT NOT NULL DEFAULT 0,
                new_hosts      INT NOT NULL DEFAULT 0,
                new_ports      INT NOT NULL DEFAULT 0,
                unreachable    INT NOT NULL DEFAULT 0,
                result_json    LONGTEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
        // `source` may be missing on an older volume — add it defensively.
        try {
            $pdo->exec('ALTER TABLE analyses ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT "file"');
        } catch (Throwable $e) {
            // column already exists — ignore
        }
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS settings (
                k VARCHAR(64) PRIMARY KEY,
                v TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
        // Local cache of SC scan results (synced on demand, not per page load).
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS sc_scan_results (
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
    }

    // ---- SC scan-result cache ----------------------------------------------

    /** Replace the cache with a fresh full sync. Returns rows stored. */
    public static function syncScanResults(array $rows): int
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return 0;
        }
        try {
            // DELETE (not TRUNCATE) — TRUNCATE forces an implicit commit inside a
            // transaction, which would break the trailing commit + meta save.
            $pdo->beginTransaction();
            $pdo->exec('DELETE FROM sc_scan_results');
            $stmt = $pdo->prepare(
                'INSERT INTO sc_scan_results
                  (id, name, status, result_type, finish_time, start_time,
                   scanned_ips, repository, can_use, owner)
                 VALUES (?,?,?,?,?,?,?,?,?,?)'
            );
            $n = 0;
            foreach ($rows as $r) {
                $id = (int) ($r['id'] ?? 0);
                if ($id <= 0) {
                    continue;
                }
                $stmt->execute([
                    $id,
                    (string) ($r['name'] ?? ''),
                    (string) ($r['status'] ?? ''),
                    (string) ($r['resultType'] ?? ''),
                    (int) ($r['finishTime'] ?? 0),
                    (int) ($r['startTime'] ?? 0),
                    (string) ($r['scannedIPs'] ?? ''),
                    (string) ($r['repository']['name'] ?? ''),
                    (($r['canUse'] ?? 'true') !== 'false') ? 1 : 0,
                    (string) ($r['owner']['username'] ?? ''),
                ]);
                $n++;
            }
            $pdo->commit();
            self::saveSettings(['sc_last_sync' => date('Y-m-d H:i:s'), 'sc_result_count' => (string) $n]);
            return $n;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            self::$error = $e->getMessage();
            return 0;
        }
    }

    /** Number of distinct scan-name groups (optionally filtered). */
    public static function countGroups(string $q): int
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return 0;
        }
        try {
            $sql = 'SELECT COUNT(*) FROM (SELECT name FROM sc_scan_results';
            $params = [];
            if ($q !== '') {
                $sql .= ' WHERE name LIKE ?';
                $params[] = '%' . $q . '%';
            }
            $sql .= ' GROUP BY name) t';
            $st = $pdo->prepare($sql);
            $st->execute($params);
            return (int) $st->fetchColumn();
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return 0;
        }
    }

    /**
     * One page of scan groups (by name). Each group carries its earliest
     * (first) and latest (last) scan — the two the user compares.
     */
    public static function groupsPage(string $q, int $limit, int $offset): array
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return [];
        }
        try {
            $sql = 'SELECT name, COUNT(*) cnt, MIN(finish_time) mn, MAX(finish_time) mx
                    FROM sc_scan_results';
            $params = [];
            if ($q !== '') {
                $sql .= ' WHERE name LIKE ?';
                $params[] = '%' . $q . '%';
            }
            $sql .= ' GROUP BY name ORDER BY name LIMIT ' . (int) $limit . ' OFFSET ' . (int) $offset;
            $st = $pdo->prepare($sql);
            $st->execute($params);
            $aggs = $st->fetchAll();
            if (!$aggs) {
                return [];
            }

            // Fetch only the boundary rows (earliest/latest) for these groups — bounded.
            $cond = [];
            $bp = [];
            foreach ($aggs as $a) {
                $cond[] = '(name = ? AND finish_time = ?)';
                $bp[] = $a['name'];
                $bp[] = $a['mn'];
                $cond[] = '(name = ? AND finish_time = ?)';
                $bp[] = $a['name'];
                $bp[] = $a['mx'];
            }
            $st2 = $pdo->prepare(
                'SELECT name, id, finish_time, status, scanned_ips, can_use, repository
                 FROM sc_scan_results WHERE ' . implode(' OR ', $cond) . '
                 ORDER BY name, finish_time, id'
            );
            $st2->execute($bp);
            $byName = [];
            foreach ($st2->fetchAll() as $r) {
                $byName[$r['name']][] = $r;
            }

            $out = [];
            foreach ($aggs as $a) {
                $scans = $byName[$a['name']] ?? [];
                if (!$scans) {
                    continue;
                }
                $first = $scans[0];
                $last  = $scans[count($scans) - 1];
                $out[] = [
                    'name'       => $a['name'],
                    'count'      => (int) $a['cnt'],
                    'first'      => $first,
                    'last'       => $last,
                    'repository' => $last['repository'],
                ];
            }
            return $out;
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return [];
        }
    }

    /**
     * All cached scans of one group (name), oldest→newest, capped at $limit
     * (latest kept). Returns ['scans'=>[...], 'total'=>int] so the caller can
     * note when a very large group was truncated.
     */
    public static function scansOfGroup(string $name, int $limit = 500): array
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return ['scans' => [], 'total' => 0];
        }
        try {
            $cnt = $pdo->prepare('SELECT COUNT(*) FROM sc_scan_results WHERE name = ?');
            $cnt->execute([$name]);
            $total = (int) $cnt->fetchColumn();

            $st = $pdo->prepare(
                'SELECT id, finish_time, status, scanned_ips, can_use, repository
                 FROM sc_scan_results WHERE name = ?
                 ORDER BY finish_time DESC, id DESC LIMIT ' . (int) $limit
            );
            $st->execute([$name]);
            $rows = $st->fetchAll();
            // Display oldest → newest.
            usort($rows, fn($a, $b) => ((int) $a['finish_time'] <=> (int) $b['finish_time'])
                ?: ((int) $a['id'] <=> (int) $b['id']));
            return ['scans' => $rows, 'total' => $total];
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return ['scans' => [], 'total' => 0];
        }
    }

    /** A single cached scan row (for labels at analyze time). */
    public static function cachedScan(int $id): ?array
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return null;
        }
        try {
            $st = $pdo->prepare('SELECT * FROM sc_scan_results WHERE id = ?');
            $st->execute([$id]);
            return $st->fetch() ?: null;
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return null;
        }
    }

    /** Persist SC connection settings (k/v). */
    public static function saveSettings(array $kv): bool
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return false;
        }
        try {
            $stmt = $pdo->prepare(
                'INSERT INTO settings (k, v) VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE v = VALUES(v)'
            );
            foreach ($kv as $k => $v) {
                $stmt->execute([$k, $v]);
            }
            return true;
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return false;
        }
    }

    /** @return array<string,string> */
    public static function getSettings(): array
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return [];
        }
        try {
            $rows = $pdo->query('SELECT k, v FROM settings')->fetchAll();
            $out = [];
            foreach ($rows as $r) {
                $out[$r['k']] = $r['v'];
            }
            return $out;
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return [];
        }
    }

    /** Persist one analysis run; returns inserted id or null on failure. */
    public static function saveAnalysis(
        string $firstFile,
        string $lastFile,
        array $result,
        string $source = 'file'
    ): ?int {
        $pdo = self::pdo();
        if (!$pdo) {
            return null;
        }
        try {
            $s = $result['summary'];
            $stmt = $pdo->prepare(
                'INSERT INTO analyses
                  (source, first_filename, last_filename, first_hosts, last_hosts,
                   new_hosts, new_ports, unreachable, result_json)
                 VALUES (?,?,?,?,?,?,?,?,?)'
            );
            $stmt->execute([
                $source,
                $firstFile,
                $lastFile,
                $s['first_hosts'],
                $s['last_hosts'],
                $s['new_hosts'],
                $s['new_ports'],
                $s['unreachable'],
                json_encode($result, JSON_UNESCAPED_SLASHES),
            ]);
            return (int) $pdo->lastInsertId();
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return null;
        }
    }

    /** Recent analyses for the sidebar history. */
    public static function recentAnalyses(int $limit = 10): array
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return [];
        }
        try {
            $stmt = $pdo->query(
                'SELECT id, source, first_filename, last_filename, new_hosts, new_ports,
                        unreachable, created_at
                 FROM analyses ORDER BY id DESC LIMIT ' . (int) $limit
            );
            return $stmt->fetchAll();
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return [];
        }
    }

    /** Fetch a single analysis (with decoded result) for export. */
    public static function getAnalysis(int $id): ?array
    {
        $pdo = self::pdo();
        if (!$pdo) {
            return null;
        }
        try {
            $stmt = $pdo->prepare('SELECT * FROM analyses WHERE id = ?');
            $stmt->execute([$id]);
            $row = $stmt->fetch();
            return $row ?: null;
        } catch (Throwable $e) {
            self::$error = $e->getMessage();
            return null;
        }
    }
}
