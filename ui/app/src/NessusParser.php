<?php
/**
 * NessusParser — parse a Nessus v2 (.nessus) export into a host->ports map
 * and diff two scans for the "Compare Nessus Scans" report.
 *
 * Open ports are derived from two sources inside each <ReportHost>:
 *   1. HostProperties tags named  enumerated-ports-<port>-<proto>  (Host Discovery scans)
 *   2. <ReportItem port="..." protocol="..."> with a non-zero port (full scans)
 */
class NessusParser
{
    /**
     * Parse a .nessus file.
     *
     * @return array{report:string, hosts: array<string, array>}
     *         hosts keyed by host name/IP, each: ports(list "port/proto"), os, mac, fqdn, mac, port_count
     * @throws RuntimeException on malformed XML
     */
    public static function parse(string $path): array
    {
        if (!is_readable($path)) {
            throw new RuntimeException("Dosya okunamadı: $path");
        }
        return self::parseString(file_get_contents($path));
    }

    /**
     * Parse a .nessus document from an in-memory string (used for scan
     * results downloaded from Security Center).
     */
    public static function parseString(string $content): array
    {
        $prev = libxml_use_internal_errors(true);
        $xml = simplexml_load_string($content);
        libxml_use_internal_errors($prev);

        if ($xml === false || $xml->getName() !== 'NessusClientData_v2') {
            throw new RuntimeException("Geçersiz Nessus dosyası (NessusClientData_v2 bekleniyor).");
        }

        $reportName = '';
        $hosts = [];

        foreach ($xml->Report as $report) {
            $reportName = (string) $report['name'];
            foreach ($report->ReportHost as $rh) {
                $name  = (string) $rh['name'];
                $ports = [];
                $props = [];

                if (isset($rh->HostProperties)) {
                    foreach ($rh->HostProperties->tag as $tag) {
                        $tname = (string) $tag['name'];
                        $props[$tname] = (string) $tag;
                        if (preg_match('/^enumerated-ports-(\d+)-(tcp|udp)$/', $tname, $m)) {
                            $ports[$m[1] . '/' . $m[2]] = true;
                        }
                    }
                }

                foreach ($rh->ReportItem as $ri) {
                    $port  = (string) $ri['port'];
                    $proto = (string) $ri['protocol'] ?: 'tcp';
                    if ($port !== '' && $port !== '0') {
                        $ports[$port . '/' . $proto] = true;
                    }
                }

                $portList = array_keys($ports);
                usort($portList, function ($a, $b) {
                    return (int) $a <=> (int) $b;
                });

                $hosts[$name] = [
                    'name'       => $name,
                    'ip'         => $props['host-ip'] ?? $name,
                    'fqdn'       => $props['host-fqdns'] ?? ($props['host-rdns'] ?? ''),
                    'os'         => $props['operating-system'] ?? ($props['os'] ?? ''),
                    'mac'        => $props['mac-address'] ?? '',
                    'ports'      => $portList,
                    'port_count' => count($portList),
                ];
            }
        }

        return ['report' => $reportName, 'hosts' => $hosts];
    }

    /**
     * Diff a "first" scan against a "last" scan.
     *
     * @return array{
     *   new_hosts: list<array>,        hosts in last but not first
     *   new_ports: list<array>,        hosts in both with extra ports in last
     *   unreachable: list<array>,      hosts in first but not last
     *   summary: array
     * }
     */
    public static function compare(array $first, array $last): array
    {
        $firstHosts = $first['hosts'];
        $lastHosts  = $last['hosts'];

        $newHosts = [];
        $newPorts = [];
        $unreachable = [];

        // Newly detected hosts: present in last, absent in first.
        foreach ($lastHosts as $ip => $h) {
            if (!isset($firstHosts[$ip])) {
                $newHosts[] = [
                    'host'       => $ip,
                    'os'         => self::shortOs($h['os']),
                    'mac'        => $h['mac'],
                    'port_count' => $h['port_count'],
                    'ports'      => $h['ports'],
                ];
            }
        }

        // Unreachable hosts: present in first, absent in last.
        foreach ($firstHosts as $ip => $h) {
            if (!isset($lastHosts[$ip])) {
                $unreachable[] = [
                    'host'       => $ip,
                    'os'         => self::shortOs($h['os']),
                    'mac'        => $h['mac'],
                    'port_count' => $h['port_count'],
                    'ports'      => $h['ports'],
                ];
            }
        }

        // New detected ports: host in both, ports appearing only in last.
        foreach ($lastHosts as $ip => $h) {
            if (!isset($firstHosts[$ip])) {
                continue;
            }
            $before = $firstHosts[$ip]['ports'];
            $added  = array_values(array_diff($h['ports'], $before));
            if (!empty($added)) {
                usort($added, fn($a, $b) => (int) $a <=> (int) $b);
                $newPorts[] = [
                    'host'        => $ip,
                    'os'          => self::shortOs($h['os']),
                    'new_ports'   => $added,
                    'prev_count'  => count($before),
                    'curr_count'  => $h['port_count'],
                ];
            }
        }

        // Stable ordering by IP (natural) for the report.
        $byHost = fn($a, $b) => strnatcmp($a['host'], $b['host']);
        usort($newHosts, $byHost);
        usort($newPorts, $byHost);
        usort($unreachable, $byHost);

        return [
            'new_hosts'   => $newHosts,
            'new_ports'   => $newPorts,
            'unreachable' => $unreachable,
            'summary'     => [
                'first_hosts' => count($firstHosts),
                'last_hosts'  => count($lastHosts),
                'new_hosts'   => count($newHosts),
                'new_ports'   => count($newPorts),
                'unreachable' => count($unreachable),
            ],
        ];
    }

    private static function shortOs(string $os): string
    {
        $os = trim($os);
        if ($os === '' || strtolower($os) === 'other') {
            return '—';
        }
        // operating-system tag can hold multiple newline-separated guesses
        $first = strtok($os, "\n");
        return $first !== false ? $first : $os;
    }
}
