<?php
/**
 * ScClient — minimal Tenable Security Center REST client (API-key auth).
 *
 * Mirrors the working Python toolkit:
 *   header  X-APIKey: accesskey=<ak>; secretkey=<sk>
 *   list    GET  /rest/scanResult
 *   download POST /rest/scanResult/{id}/download   (returns a ZIP with the .nessus)
 */
class ScClient
{
    private string $url;

    public function __construct(
        string $url,
        private string $accessKey,
        private string $secretKey
    ) {
        $this->url = rtrim(trim($url), '/');
    }

    private function headers(bool $json = false): array
    {
        $h = [
            'Accept: application/json',
            'X-APIKey: accesskey=' . $this->accessKey . '; secretkey=' . $this->secretKey,
        ];
        if ($json) {
            $h[] = 'Content-Type: application/json';
        }
        return $h;
    }

    /** @return array{0:int,1:string} [httpCode, rawBody] */
    private function request(string $method, string $path, ?string $body = null): array
    {
        $ch = curl_init($this->url . $path);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST   => $method,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_SSL_VERIFYPEER  => false,
            CURLOPT_SSL_VERIFYHOST  => false,
            CURLOPT_HTTPHEADER      => $this->headers($body !== null),
            CURLOPT_CONNECTTIMEOUT  => 10,
            CURLOPT_TIMEOUT         => 180,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $resp = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        if ($resp === false) {
            throw new RuntimeException("Security Center'a bağlanılamadı: $err");
        }
        return [$code, $resp];
    }

    /** Pull SC's own error_msg/error_code out of a JSON error body, if present. */
    private static function scError(string $resp): string
    {
        $j = json_decode($resp, true);
        if (is_array($j)) {
            $msg = trim((string) ($j['error_msg'] ?? ''));
            $code = $j['error_code'] ?? null;
            if ($msg !== '') {
                $msg = preg_replace('/\s+/', ' ', $msg);
                return $code !== null ? "$msg (error_code $code)" : $msg;
            }
        }
        return '';
    }

    /** Verify the connection; returns the authenticated username. */
    public function testConnection(): string
    {
        [$code, $resp] = $this->request('GET', '/rest/currentUser');
        if ($code !== 200) {
            throw new RuntimeException("Kimlik doğrulama başarısız (HTTP $code). URL ve API anahtarlarını kontrol edin.");
        }
        $j = json_decode($resp, true);
        return $j['response']['username'] ?? 'unknown';
    }

    /**
     * List all usable+manageable scan results, newest first.
     * @return list<array> each: id, name, status, finishTime, scannedIPs, totalIPs, repository, downloadAvailable
     */
    public function listScanResults(): array
    {
        $fields = implode(',', [
            'name', 'status', 'finishTime', 'startTime', 'createdTime',
            'downloadAvailable', 'scannedIPs', 'totalIPs', 'repository',
            'resultType', 'importStatus', 'canUse', 'canManage', 'owner',
        ]);
        // Without an explicit time window SC applies a default filter and hides
        // older results — pass a wide window so ALL scan results are returned.
        $query = '/rest/scanResult?startTime=0&endTime=9999999999&fields=' . $fields;
        [$code, $resp] = $this->request('GET', $query);
        if ($code !== 200) {
            throw new RuntimeException("Scan result listesi alınamadı (HTTP $code)." .
                (($d = self::scError($resp)) !== '' ? " SC: $d" : ''));
        }
        $j = json_decode($resp, true);
        $resp = $j['response'] ?? [];
        $rows = array_merge($resp['usable'] ?? [], $resp['manageable'] ?? []);

        // Dedupe by id, keep richest record.
        $byId = [];
        foreach ($rows as $r) {
            $id = $r['id'] ?? null;
            if ($id !== null) {
                $byId[$id] = $r;
            }
        }
        $out = array_values($byId);

        // Newest finished first.
        usort($out, function ($a, $b) {
            return (int) ($b['finishTime'] ?? 0) <=> (int) ($a['finishTime'] ?? 0);
        });
        return $out;
    }

    /** Build a helpful message for a failed individual-analysis query. */
    private static function analysisError(int $scanId, int $code, string $resp, $errCode): string
    {
        $detail = self::scError($resp);
        $base = "Scan #$scanId bulguları alınamadı (HTTP $code)";

        // error_code 143 = "Unable to process Vuln Query": the scan result has no
        // queryable *individual* data (partial/expired/zero-host scan), NOT a permission issue.
        if ((string) $errCode === '143' || str_contains($detail, 'Unable to process Vuln Query')) {
            return "$base. Bu scan result için bireysel (individual) bulgu verisi sorgulanamıyor — "
                 . "büyük ihtimalle tarama yarım kalmış (Partial), veri içermiyor (0 host) ya da "
                 . "individual veri dizini süresi dolmuş. Lütfen **Completed** ve veri içeren bir "
                 . "scan result seçin." . ($detail !== '' ? " [SC: $detail]" : '');
        }
        if ($code === 403) {
            return "$base. API kullanıcısı bu scan result'ı analiz etme yetkisine sahip olmayabilir "
                 . "(farklı kullanıcı/organizasyon ya da yetersiz rol)."
                 . ($detail !== '' ? " [SC: $detail]" : '');
        }
        return "$base." . ($detail !== '' ? " SC: $detail" : '');
    }

    /**
     * List every individual finding of a scan result via /rest/analysis
     * (tool=listvuln). Paginated. Each row carries ip/port/protocol plus host
     * metadata — exactly what the host/port diff needs.
     *
     * @return list<array>
     */
    public function listFindings(int $scanId, int $pageSize = 1000): array
    {
        $all = [];
        $offset = 0;
        do {
            $payload = json_encode([
                'query' => [
                    'name' => '', 'description' => '', 'context' => '',
                    'status' => -1, 'createdTime' => 0, 'modifiedTime' => 0,
                    'groups' => [], 'type' => 'vuln',
                    'tool' => 'listvuln', 'sourceType' => 'individual',
                    'startOffset' => $offset, 'endOffset' => $offset + $pageSize,
                    'filters' => [], 'vulnTool' => 'listvuln',
                    'scanID' => (string) $scanId, 'view' => 'all',
                ],
                'sourceType' => 'individual',
                'scanID'     => (string) $scanId,
                'columns'    => [],
                'type'       => 'vuln',
            ]);
            [$code, $resp] = $this->request('POST', '/rest/analysis', $payload);
            $j = json_decode($resp, true);
            $errCode = is_array($j) ? ($j['error_code'] ?? null) : null;

            // SC may signal failure via HTTP status OR an embedded error_code (even on HTTP 200).
            if ($code !== 200 || !empty($errCode)) {
                throw new RuntimeException(self::analysisError($scanId, $code, $resp, $errCode));
            }
            $r = is_array($j['response'] ?? null) ? $j['response'] : [];
            $results = $r['results'] ?? [];
            foreach ($results as $row) {
                $all[] = $row;
            }
            $total    = (int) ($r['totalRecords'] ?? 0);
            $returned = count($results);
            $offset  += $pageSize;
            if ($returned < $pageSize) {
                break;
            }
        } while ($offset < $total);

        return $all;
    }

    /**
     * Fold listvuln rows into the same host map NessusParser produces, so the
     * comparison engine is shared between file and scan-result modes.
     *
     * @return array{report:string, hosts: array<string,array>}
     */
    public static function findingsToHosts(array $rows, string $label = ''): array
    {
        $hosts = [];
        foreach ($rows as $row) {
            $ip = (string) ($row['ip'] ?? ($row['dnsName'] ?? ''));
            if ($ip === '') {
                continue;
            }
            if (!isset($hosts[$ip])) {
                $hosts[$ip] = [
                    'name'  => $ip,
                    'ip'    => $ip,
                    'fqdn'  => (string) ($row['dnsName'] ?? ''),
                    'os'    => (string) ($row['operatingSystem'] ?? ''),
                    'mac'   => (string) ($row['macAddress'] ?? ''),
                    'ports' => [],
                ];
            }
            if (empty($hosts[$ip]['os']) && !empty($row['operatingSystem'])) {
                $hosts[$ip]['os'] = (string) $row['operatingSystem'];
            }
            if (empty($hosts[$ip]['mac']) && !empty($row['macAddress'])) {
                $hosts[$ip]['mac'] = (string) $row['macAddress'];
            }
            $port  = (string) ($row['port'] ?? '0');
            $proto = (string) ($row['protocol'] ?? 'tcp') ?: 'tcp';
            if ($port !== '' && $port !== '0') {
                $hosts[$ip]['ports'][$port . '/' . $proto] = true;
            }
        }

        foreach ($hosts as &$h) {
            $pl = array_keys($h['ports']);
            usort($pl, fn($a, $b) => (int) $a <=> (int) $b);
            $h['ports']      = $pl;
            $h['port_count'] = count($pl);
        }
        unset($h);

        return ['report' => $label, 'hosts' => $hosts];
    }
}
