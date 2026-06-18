<?php
require __DIR__ . '/src/Db.php';
require __DIR__ . '/src/ScClient.php';
require __DIR__ . '/src/view.php';

$notice = null;
$noticeType = 'success';
$testResult = null;

$current = Db::getSettings();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $url = trim($_POST['sc_url'] ?? '');
    $ak  = trim($_POST['sc_access_key'] ?? '');
    $sk  = trim($_POST['sc_secret_key'] ?? '');

    // Keep the stored secret if the field was left blank.
    if ($sk === '' && !empty($current['sc_secret_key'])) {
        $sk = $current['sc_secret_key'];
    }

    if ($action === 'save' || $action === 'test') {
        if ($url === '' || $ak === '' || $sk === '') {
            $notice = 'URL, Access Key and Secret Key are required.';
            $noticeType = 'danger';
        } else {
            if ($action === 'save') {
                if (Db::saveSettings([
                    'sc_url' => $url, 'sc_access_key' => $ak, 'sc_secret_key' => $sk,
                ])) {
                    $notice = 'Security Center settings saved.';
                    $current = Db::getSettings();
                } else {
                    $notice = 'Could not save settings (DB error: ' . h(Db::error()) . ').';
                    $noticeType = 'danger';
                }
            }
            // Always test the supplied/saved credentials.
            try {
                $client = new ScClient($url, $ak, $sk);
                $user = $client->testConnection();
                $testResult = ['ok' => true, 'msg' => "Connection OK — user: $user"];
            } catch (Throwable $e) {
                $testResult = ['ok' => false, 'msg' => $e->getMessage()];
            }
        }
    }
}

$history = Db::recentAnalyses();
$secretSet = !empty($current['sc_secret_key']);

render_head('Security Center Settings');
render_sidebar('settings', $history);
?>
    <main class="content">
        <header class="page-head">
            <h1><i class="bi bi-gear text-primary"></i> Security Center Settings</h1>
            <p class="text-secondary">
                Enter the Tenable Security Center connection details used to fetch scan results.
                Values are stored in the database (lab use, no authentication).
            </p>
        </header>

        <?php if ($notice): ?>
            <div class="alert alert-<?= $noticeType ?>"><?= h($notice) ?></div>
        <?php endif; ?>

        <?php if ($testResult): ?>
            <div class="alert alert-<?= $testResult['ok'] ? 'success' : 'danger' ?> d-flex align-items-center">
                <i class="bi <?= $testResult['ok'] ? 'bi-check-circle-fill' : 'bi-x-circle-fill' ?> me-2"></i>
                <?= h($testResult['msg']) ?>
            </div>
        <?php endif; ?>

        <section class="card" style="max-width:720px;">
            <form method="post" class="card-body">
                <div class="mb-3">
                    <label class="form-label">Security Center URL</label>
                    <input type="text" name="sc_url" class="form-control" placeholder="https://192.168.1.62:8443"
                           value="<?= h($current['sc_url'] ?? '') ?>" required>
                    <div class="form-text">e.g. <code>https://&lt;host&gt;:8443</code> or <code>https://&lt;host&gt;</code></div>
                    <div class="form-text text-warning">
                        <i class="bi bi-info-circle"></i>
                        Under Docker Desktop (Mac/Windows), if SC runs on this machine/loopback,
                        use <code>https://host.docker.internal:8443</code> instead of the IP so the container can reach it.
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label">Access Key</label>
                    <input type="text" name="sc_access_key" class="form-control font-monospace"
                           value="<?= h($current['sc_access_key'] ?? '') ?>" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Secret Key</label>
                    <input type="password" name="sc_secret_key" class="form-control font-monospace"
                           placeholder="<?= $secretSet ? '•••••••• (saved — enter a new value to change)' : '' ?>"
                           <?= $secretSet ? '' : 'required' ?>>
                    <?php if ($secretSet): ?>
                        <div class="form-text text-success"><i class="bi bi-check2"></i> Secret key is saved.</div>
                    <?php endif; ?>
                </div>
                <div class="d-flex gap-2 mt-4">
                    <button type="submit" name="action" value="save" class="btn btn-primary">
                        <i class="bi bi-save"></i> Save
                    </button>
                    <button type="submit" name="action" value="test" class="btn btn-outline-light">
                        <i class="bi bi-plug"></i> Test Connection
                    </button>
                </div>
            </form>
        </section>
    </main>
<?php
render_foot();
