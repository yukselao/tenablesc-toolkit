<?php
require __DIR__ . '/src/Db.php';

$id = (int) ($_GET['id'] ?? 0);
$format = strtolower($_GET['format'] ?? 'csv');

$row = $id > 0 ? Db::getAnalysis($id) : null;
if (!$row) {
    http_response_code(404);
    echo 'Analiz bulunamadı.';
    exit;
}

$result = json_decode($row['result_json'] ?? '', true);
if (!is_array($result)) {
    http_response_code(500);
    echo 'Analiz verisi okunamadı.';
    exit;
}

$first = $row['first_filename'];
$last  = $row['last_filename'];
$when  = $row['created_at'];
$base  = 'nessus-compare-' . $id;

if ($format === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $base . '.csv"');
    $out = fopen('php://output', 'w');
    fprintf($out, "\xEF\xBB\xBF"); // UTF-8 BOM for Excel

    fputcsv($out, ['Nessus Compare Report']);
    fputcsv($out, ['First', $first]);
    fputcsv($out, ['Last', $last]);
    fputcsv($out, ['Source', $row['source']]);
    fputcsv($out, ['Generated', $when]);
    fputcsv($out, []);

    $s = $result['summary'];
    fputcsv($out, ['[Summary]']);
    fputcsv($out, ['First Scan Hosts', $s['first_hosts']]);
    fputcsv($out, ['Last Scan Hosts', $s['last_hosts']]);
    fputcsv($out, ['Newly Detected Hosts', $s['new_hosts']]);
    fputcsv($out, ['New Detected Ports (hosts)', $s['new_ports']]);
    fputcsv($out, ['Unreachable Hosts', $s['unreachable']]);
    fputcsv($out, []);

    fputcsv($out, ['[Newly Detected Hosts]']);
    fputcsv($out, ['Host', 'OS', 'MAC', 'Open Ports']);
    foreach ($result['new_hosts'] as $r) {
        fputcsv($out, [$r['host'], $r['os'], $r['mac'], implode(' ', $r['ports'])]);
    }
    fputcsv($out, []);

    fputcsv($out, ['[New Detected Ports]']);
    fputcsv($out, ['Host', 'OS', 'New Ports', 'Prev Port Count', 'Curr Port Count']);
    foreach ($result['new_ports'] as $r) {
        fputcsv($out, [$r['host'], $r['os'], implode(' ', $r['new_ports']), $r['prev_count'], $r['curr_count']]);
    }
    fputcsv($out, []);

    fputcsv($out, ['[Unreachable Hosts]']);
    fputcsv($out, ['Host', 'OS', 'MAC', 'Previous Ports']);
    foreach ($result['unreachable'] as $r) {
        fputcsv($out, [$r['host'], $r['os'], $r['mac'], implode(' ', $r['ports'])]);
    }

    fclose($out);
    exit;
}

if ($format === 'html') {
    require __DIR__ . '/src/view.php';
    header('Content-Type: text/html; charset=utf-8');
    ?>
    <!doctype html>
    <html lang="tr" data-bs-theme="dark">
    <head>
        <meta charset="utf-8">
        <title>Nessus Compare Report #<?= $id ?></title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
        <link href="assets/style.css" rel="stylesheet">
    </head>
    <body>
        <main class="content" style="max-width:1100px;margin:0 auto;">
            <header class="page-head">
                <h1><i class="bi bi-file-earmark-bar-graph text-primary"></i> Nessus Compare Report #<?= $id ?></h1>
                <p class="text-secondary">
                    <strong>Kaynak:</strong> <?= h($row['source']) ?> ·
                    <strong>Oluşturma:</strong> <?= h($when) ?>
                </p>
            </header>
            <?php render_report($result, $first, $last); ?>
        </main>
    </body>
    </html>
    <?php
    exit;
}

http_response_code(400);
echo 'Geçersiz format. csv veya html kullanın.';
