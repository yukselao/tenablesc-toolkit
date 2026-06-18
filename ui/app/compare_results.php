<?php
require __DIR__ . '/src/NessusParser.php';
require __DIR__ . '/src/Db.php';
require __DIR__ . '/src/ScClient.php';
require __DIR__ . '/src/view.php';

$settings = Db::getSettings();
$haveSc = !empty($settings['sc_url']) && !empty($settings['sc_access_key']) && !empty($settings['sc_secret_key']);

$scanResults = [];
$scError = null;
$client = null;

if ($haveSc) {
    $client = new ScClient($settings['sc_url'], $settings['sc_access_key'], $settings['sc_secret_key']);
    try {
        $scanResults = $client->listScanResults();
    } catch (Throwable $e) {
        $scError = $e->getMessage();
    }
}

$result = null;
$error = null;
$firstLabel = '';
$lastLabel = '';
$analysisId = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'analyze' && $client) {
    try {
        $firstId = (int) ($_POST['first_id'] ?? 0);
        $lastId  = (int) ($_POST['last_id'] ?? 0);
        if ($firstId <= 0 || $lastId <= 0) {
            throw new RuntimeException('Lütfen First ve Last için birer scan result seçin.');
        }
        if ($firstId === $lastId) {
            throw new RuntimeException('First ve Last için farklı scan result seçmelisiniz.');
        }

        $nameById = [];
        foreach ($scanResults as $s) {
            $nameById[(int) $s['id']] = $s['name'] ?? ('Scan #' . $s['id']);
        }
        $firstLabel = ($nameById[$firstId] ?? "Scan #$firstId") . " (#$firstId)";
        $lastLabel  = ($nameById[$lastId] ?? "Scan #$lastId") . " (#$lastId)";

        $firstRows = $client->listFindings($firstId);
        $lastRows  = $client->listFindings($lastId);

        $first = ScClient::findingsToHosts($firstRows, $firstLabel);
        $last  = ScClient::findingsToHosts($lastRows, $lastLabel);
        $result = NessusParser::compare($first, $last);

        $analysisId = Db::saveAnalysis($firstLabel, $lastLabel, $result, 'sc');
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

function fmt_time($ts): string
{
    $ts = (int) $ts;
    return $ts > 0 ? date('Y-m-d H:i', $ts) : '—';
}

$history = Db::recentAnalyses();

render_head('Compare Scan Results');
render_sidebar('results', $history);
?>
    <main class="content">
        <header class="page-head">
            <h1><i class="bi bi-cloud-download text-primary"></i> Compare Scan Results</h1>
            <p class="text-secondary">
                Security Center'daki scan result'ların bulgularını (<code>/rest/analysis</code>) çekip
                ikisini karşılaştırın. Dosya yüklemeden, doğrudan SC üzerinden analiz.
            </p>
        </header>

        <?php if (!$haveSc): ?>
            <div class="alert alert-warning d-flex align-items-center">
                <i class="bi bi-gear-fill me-2"></i>
                Önce <a href="settings.php" class="alert-link ms-1">Security Center Settings</a>
                bölümünden bağlantı bilgilerini girin.
            </div>
        <?php else: ?>

            <?php if ($scError): ?>
                <div class="alert alert-danger d-flex align-items-center">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    Scan result listesi alınamadı: <?= h($scError) ?>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="alert alert-danger d-flex align-items-center">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i> <?= h($error) ?>
                </div>
            <?php endif; ?>

            <section class="card upload-card no-print">
                <form method="post" class="card-body">
                    <input type="hidden" name="action" value="analyze">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <strong><?= count($scanResults) ?></strong> scan result bulundu.
                            <span class="text-muted small ms-2">First ve Last için birer satır seçin.</span>
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="bi bi-cpu"></i> Analyze</button>
                    </div>
                    <div class="table-responsive scan-picker">
                        <table class="table table-hover align-middle mb-0">
                            <thead>
                                <tr>
                                    <th class="text-center">First</th>
                                    <th class="text-center">Last</th>
                                    <th>ID</th><th>Name</th><th>Status</th>
                                    <th>Finished</th><th class="text-end">Scanned IPs</th><th>Repository</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php if (empty($scanResults)): ?>
                                <tr><td colspan="8" class="empty-row">Kullanılabilir scan result yok.</td></tr>
                            <?php else: foreach ($scanResults as $s): $id = (int) $s['id'];
                                $canUse = ($s['canUse'] ?? 'true') !== 'false';
                                $dis = $canUse ? '' : 'disabled';
                            ?>
                                <tr class="<?= $canUse ? '' : 'opacity-50' ?>">
                                    <td class="text-center"><input class="form-check-input" type="radio" name="first_id" value="<?= $id ?>" <?= $dis ?>></td>
                                    <td class="text-center"><input class="form-check-input" type="radio" name="last_id" value="<?= $id ?>" <?= $dis ?>></td>
                                    <td class="text-muted">#<?= $id ?></td>
                                    <td>
                                        <?= h($s['name'] ?? '') ?>
                                        <?php if (!$canUse): ?>
                                            <span class="badge text-bg-danger ms-1" title="API kullanıcısı bu sonucu analiz edemez">no access</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><span class="badge text-bg-<?= ($s['status'] ?? '') === 'Completed' ? 'success' : 'secondary' ?>"><?= h($s['status'] ?? '—') ?></span></td>
                                    <td class="small"><?= fmt_time($s['finishTime'] ?? 0) ?></td>
                                    <td class="text-end font-monospace small"><?= h($s['scannedIPs'] ?? '—') ?></td>
                                    <td class="small"><?= h($s['repository']['name'] ?? '—') ?></td>
                                </tr>
                            <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </form>
            </section>

            <?php if ($result): ?>
                <?php render_export_bar($analysisId); ?>
                <?php render_report($result, $firstLabel, $lastLabel); ?>
            <?php endif; ?>

        <?php endif; ?>
    </main>
<?php
render_foot();
