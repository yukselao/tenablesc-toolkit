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
