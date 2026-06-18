<?php
require __DIR__ . '/src/NessusParser.php';
require __DIR__ . '/src/Db.php';
require __DIR__ . '/src/view.php';

$result = null;
$error = null;
$firstName = '';
$lastName = '';
$analysisId = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'analyze') {
    try {
        if (empty($_FILES['first_scan']['tmp_name']) || empty($_FILES['last_scan']['tmp_name'])) {
            throw new RuntimeException('Please choose both a First Scan and a Last Scan file.');
        }
        foreach (['first_scan', 'last_scan'] as $field) {
            if ($_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
                throw new RuntimeException("Upload error: {$field} (code {$_FILES[$field]['error']})");
            }
        }
        $firstName = $_FILES['first_scan']['name'];
        $lastName  = $_FILES['last_scan']['name'];

        $first = NessusParser::parse($_FILES['first_scan']['tmp_name']);
        $last  = NessusParser::parse($_FILES['last_scan']['tmp_name']);
        $result = NessusParser::compare($first, $last);

        $analysisId = Db::saveAnalysis($firstName, $lastName, $result, 'file');
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$history = Db::recentAnalyses();

render_head('Compare Nessus Scans');
render_sidebar('nessus', $history);
?>
    <main class="content">
        <header class="page-head">
            <h1><i class="bi bi-arrow-left-right text-primary"></i> Compare Nessus Scans</h1>
            <p class="text-secondary">
                Compare two Nessus scan files (<code>.nessus</code>) and report newly detected
                hosts, newly opened ports, and unreachable hosts.
            </p>
        </header>

        <?php if ($error): ?>
            <div class="alert alert-danger d-flex align-items-center">
                <i class="bi bi-exclamation-triangle-fill me-2"></i> <?= h($error) ?>
            </div>
        <?php endif; ?>

        <section class="card upload-card no-print">
            <form method="post" enctype="multipart/form-data" class="card-body">
                <input type="hidden" name="action" value="analyze">
                <div class="row g-4">
                    <div class="col-md-6">
                        <label class="form-label"><span class="step-dot bg-primary">1</span> First Scan File</label>
                        <input type="file" name="first_scan" accept=".nessus,.xml" class="form-control" required>
                        <div class="form-text">Earlier / baseline scan (.nessus)</div>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label"><span class="step-dot bg-info">2</span> Last Scan File</label>
                        <input type="file" name="last_scan" accept=".nessus,.xml" class="form-control" required>
                        <div class="form-text">Later / current scan (.nessus)</div>
                    </div>
                </div>
                <div class="mt-4">
                    <button type="submit" class="btn btn-primary btn-lg px-4"><i class="bi bi-cpu"></i> Analyze</button>
                </div>
            </form>
        </section>

        <?php if ($result): ?>
            <?php render_export_bar($analysisId); ?>
            <?php render_report($result, $firstName, $lastName); ?>
        <?php else: ?>
            <section class="empty-state">
                <i class="bi bi-cloud-arrow-up"></i>
                <p>Upload two <code>.nessus</code> files and click <strong>Analyze</strong>.</p>
                <p class="small text-muted">
                    For testing, use <code>first-scan.nessus</code> and <code>last-scan.nessus</code>
                    under <code>sample-data/compare-scenarios/</code>.
                </p>
            </section>
        <?php endif; ?>
    </main>
<?php
render_foot();
