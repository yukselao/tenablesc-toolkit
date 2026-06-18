<?php
require __DIR__ . '/src/NessusParser.php';
require __DIR__ . '/src/Db.php';
require __DIR__ . '/src/ScClient.php';
require __DIR__ . '/src/view.php';

const GROUPS_PER_PAGE = 25;
const GROUP_SCANS_CAP = 500;

$settings = Db::getSettings();
$haveSc = !empty($settings['sc_url']) && !empty($settings['sc_access_key']) && !empty($settings['sc_secret_key']);
$client = $haveSc ? new ScClient($settings['sc_url'], $settings['sc_access_key'], $settings['sc_secret_key']) : null;

function fmt_time($ts): string
{
    $ts = (int) $ts;
    return $ts > 0 ? date('Y-m-d H:i', $ts) : '—';
}

// ---- AJAX: scans of one group (loaded on demand when a group is expanded) ---
if (($_GET['ajax'] ?? '') === 'group_scans') {
    header('Content-Type: text/html; charset=utf-8');
    $name = (string) ($_GET['name'] ?? '');
    $data = Db::scansOfGroup($name, GROUP_SCANS_CAP);
    $scans = $data['scans'];
    $total = $data['total'];
    if (!$scans) {
        echo '<div class="p-3 text-muted small">No scans found for this group.</div>';
        exit;
    }
    $firstDefault = (int) $scans[0]['id'];
    $lastDefault  = (int) $scans[count($scans) - 1]['id'];
    ?>
    <form method="post" class="group-pick">
        <input type="hidden" name="action" value="analyze">
        <?php if ($total > count($scans)): ?>
            <div class="pick-note">Showing the latest <?= count($scans) ?> of <?= $total ?> scans.
                The quick “First ↔ Last” uses the true earliest/latest.</div>
        <?php endif; ?>
        <div class="table-responsive group-scans">
            <table class="table table-hover table-sm align-middle mb-0">
                <thead>
                    <tr>
                        <th class="text-center">First</th>
                        <th class="text-center">Last</th>
                        <th>ID</th><th>Finished</th><th>Status</th><th class="text-end">Scanned IPs</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($scans as $s): $id = (int) $s['id'];
                    $usable = (int) ($s['can_use'] ?? 1) === 1;
                    $dis = $usable ? '' : 'disabled';
                ?>
                    <tr class="<?= $usable ? '' : 'opacity-50' ?>">
                        <td class="text-center">
                            <input class="form-check-input" type="radio" name="first_id" value="<?= $id ?>"
                                   <?= $id === $firstDefault ? 'checked' : '' ?> <?= $dis ?>>
                        </td>
                        <td class="text-center">
                            <input class="form-check-input" type="radio" name="last_id" value="<?= $id ?>"
                                   <?= $id === $lastDefault ? 'checked' : '' ?> <?= $dis ?>>
                        </td>
                        <td class="text-muted">#<?= $id ?></td>
                        <td class="small"><?= fmt_time($s['finish_time']) ?></td>
                        <td><span class="badge text-bg-<?= ($s['status'] ?? '') === 'Completed' ? 'success' : 'secondary' ?>"><?= h($s['status'] ?? '—') ?></span></td>
                        <td class="text-end font-monospace small"><?= h($s['scanned_ips'] ?? '—') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="pick-actions">
            <button type="submit" class="btn btn-primary btn-sm"><i class="bi bi-cpu"></i> Compare Selected</button>
        </div>
    </form>
    <?php
    exit;
}

$notice = null;
$noticeType = 'success';
$result = null;
$error = null;
$firstLabel = '';
$lastLabel = '';
$analysisId = null;

// ---- POST actions -----------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $client) {
    $action = $_POST['action'] ?? '';

    if ($action === 'sync') {
        try {
            $rows = $client->listScanResults();
            $n = Db::syncScanResults($rows);
            $notice = "Fetched and cached $n scan results.";
        } catch (Throwable $e) {
            $notice = 'Fetch failed: ' . $e->getMessage();
            $noticeType = 'danger';
        }
    } elseif ($action === 'analyze') {
        try {
            $firstId = (int) ($_POST['first_id'] ?? 0);
            $lastId  = (int) ($_POST['last_id'] ?? 0);
            if ($firstId <= 0 || $lastId <= 0) {
                throw new RuntimeException('Select both a First and a Last scan to compare.');
            }
            if ($firstId === $lastId) {
                throw new RuntimeException('First and Last must be two different scans.');
            }
            $fRow = Db::cachedScan($firstId);
            $lRow = Db::cachedScan($lastId);
            $firstLabel = ($fRow['name'] ?? 'Scan') . ' — ' . fmt_time($fRow['finish_time'] ?? 0) . " (#$firstId)";
            $lastLabel  = ($lRow['name'] ?? 'Scan') . ' — ' . fmt_time($lRow['finish_time'] ?? 0) . " (#$lastId)";

            // Download each result as .nessus and parse with the SAME engine as the
            // file-upload mode, so both modes yield identical host/port results.
            $first = NessusParser::parseString($client->downloadNessus($firstId));
            $last  = NessusParser::parseString($client->downloadNessus($lastId));
            $result = NessusParser::compare($first, $last);
            $analysisId = Db::saveAnalysis($firstLabel, $lastLabel, $result, 'sc');
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
    }
}

// ---- list state (GET) -------------------------------------------------------
$q = trim($_GET['q'] ?? '');
$page = max(1, (int) ($_GET['p'] ?? 1));
$totalGroups = Db::countGroups($q);
$totalPages = max(1, (int) ceil($totalGroups / GROUPS_PER_PAGE));
$page = min($page, $totalPages);
$offset = ($page - 1) * GROUPS_PER_PAGE;
$groups = $totalGroups > 0 ? Db::groupsPage($q, GROUPS_PER_PAGE, $offset) : [];

$lastSync = $settings['sc_last_sync'] ?? null;
$cachedCount = (int) ($settings['sc_result_count'] ?? 0);
$cacheEmpty = ($lastSync === null);

$history = Db::recentAnalyses();

function page_url(string $q, int $p): string
{
    $params = ['p' => $p];
    if ($q !== '') {
        $params['q'] = $q;
    }
    return 'compare_results.php?' . http_build_query($params);
}

render_head('Compare Scan Results');
render_sidebar('results', $history);
?>
    <main class="content">
        <header class="page-head">
            <h1><i class="bi bi-cloud-download text-primary"></i> Compare Scan Results</h1>
            <p class="text-secondary">
                Fetch the Security Center scan results once and cache them, then compare the
                <strong>first</strong> and <strong>last</strong> scan of a name group — or expand a
                group to pick any two scans. The list is served from the local cache, so SC is not
                queried on every page load.
            </p>
        </header>

        <?php if (!$haveSc): ?>
            <div class="alert alert-warning d-flex align-items-center">
                <i class="bi bi-gear-fill me-2"></i>
                First configure the connection under
                <a href="settings.php" class="alert-link ms-1">Security Center Settings</a>.
            </div>
        <?php else: ?>

            <?php if ($notice): ?>
                <div class="alert alert-<?= $noticeType ?>"><?= h($notice) ?></div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="alert alert-danger d-flex align-items-center">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i> <?= h($error) ?>
                </div>
            <?php endif; ?>

            <!-- Cache / fetch bar -->
            <section class="card cache-bar no-print">
                <div class="card-body d-flex justify-content-between align-items-center flex-wrap gap-3">
                    <div class="cache-info">
                        <?php if ($cacheEmpty): ?>
                            <i class="bi bi-database-x text-warning"></i>
                            <span>Cache is empty — fetch the scan results.</span>
                        <?php else: ?>
                            <i class="bi bi-database-check text-success"></i>
                            <span>
                                <strong><?= $cachedCount ?></strong> scan results cached
                                · last fetched: <strong><?= h($lastSync) ?></strong>
                            </span>
                        <?php endif; ?>
                    </div>
                    <form method="post" class="m-0">
                        <input type="hidden" name="action" value="sync">
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-arrow-repeat"></i> Fetch All Scan Results
                        </button>
                    </form>
                </div>
            </section>

            <?php if (!$cacheEmpty): ?>
                <!-- Search -->
                <form method="get" class="search-form no-print">
                    <div class="search-wrap">
                        <i class="bi bi-search"></i>
                        <input type="text" name="q" class="form-control" value="<?= h($q) ?>"
                               placeholder="Search by name…" autocomplete="off">
                    </div>
                    <?php if ($q !== ''): ?>
                        <a href="compare_results.php" class="btn btn-outline-light"><i class="bi bi-x-lg"></i></a>
                    <?php endif; ?>
                    <span class="text-muted small ms-auto">
                        <strong><?= $totalGroups ?></strong> group<?= $totalGroups === 1 ? '' : 's' ?><?= $q !== '' ? ' (filtered)' : '' ?>
                    </span>
                </form>

                <!-- Grouped list -->
                <?php if (empty($groups)): ?>
                    <div class="empty-state"><i class="bi bi-search"></i><p>No matching groups.</p></div>
                <?php else: ?>
                    <div class="group-list">
                    <?php foreach ($groups as $g):
                        $first = $g['first'];
                        $last  = $g['last'];
                        $multi = ($g['count'] >= 2) && ((int) $first['id'] !== (int) $last['id']);
                        $canQuick = $multi
                            && (int) ($first['can_use'] ?? 1) === 1
                            && (int) ($last['can_use'] ?? 1) === 1;
                    ?>
                        <div class="group-card">
                            <div class="group-row">
                                <div class="group-main">
                                    <div class="group-name" title="<?= h($g['name']) ?>"><?= h($g['name']) ?></div>
                                    <div class="group-sub">
                                        <span class="badge text-bg-secondary"><?= $g['count'] ?> scans</span>
                                        <span class="repo"><i class="bi bi-hdd-stack"></i> <?= h($g['repository'] ?: '—') ?></span>
                                    </div>
                                </div>
                                <div class="group-range">
                                    <div class="ep">
                                        <span class="ep-label">First</span>
                                        <span class="ep-date"><?= fmt_time($first['finish_time']) ?></span>
                                        <span class="ep-id">#<?= (int) $first['id'] ?></span>
                                    </div>
                                    <i class="bi bi-arrow-right ep-arrow"></i>
                                    <div class="ep">
                                        <span class="ep-label">Last</span>
                                        <span class="ep-date"><?= fmt_time($last['finish_time']) ?></span>
                                        <span class="ep-id">#<?= (int) $last['id'] ?></span>
                                    </div>
                                </div>
                                <div class="group-action">
                                    <?php if ($canQuick): ?>
                                        <form method="post" class="m-0">
                                            <input type="hidden" name="action" value="analyze">
                                            <input type="hidden" name="first_id" value="<?= (int) $first['id'] ?>">
                                            <input type="hidden" name="last_id" value="<?= (int) $last['id'] ?>">
                                            <button type="submit" class="btn btn-primary btn-sm">
                                                <i class="bi bi-cpu"></i> First ↔ Last
                                            </button>
                                        </form>
                                    <?php elseif (!$multi): ?>
                                        <span class="badge text-bg-dark" title="At least two scans are required to compare">single scan</span>
                                    <?php endif; ?>
                                    <?php if ($multi): ?>
                                        <button type="button" class="btn btn-outline-light btn-sm group-toggle"
                                                data-name="<?= h($g['name']) ?>">
                                            <i class="bi bi-sliders"></i> Customize
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="group-panel"></div>
                        </div>
                    <?php endforeach; ?>
                    </div>

                    <!-- Pagination -->
                    <?php if ($totalPages > 1): ?>
                        <nav class="pager no-print">
                            <a class="btn btn-outline-light btn-sm <?= $page <= 1 ? 'disabled' : '' ?>"
                               href="<?= page_url($q, $page - 1) ?>"><i class="bi bi-chevron-left"></i></a>
                            <span class="pager-info">Page <strong><?= $page ?></strong> / <?= $totalPages ?></span>
                            <a class="btn btn-outline-light btn-sm <?= $page >= $totalPages ? 'disabled' : '' ?>"
                               href="<?= page_url($q, $page + 1) ?>"><i class="bi bi-chevron-right"></i></a>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($result): ?>
                <?php render_export_bar($analysisId); ?>
                <?php render_report($result, $firstLabel, $lastLabel); ?>
            <?php endif; ?>

            <script>
            document.querySelectorAll('.group-toggle').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var card = btn.closest('.group-card');
                    var panel = card.querySelector('.group-panel');
                    if (panel.dataset.loaded === '1') {
                        panel.classList.toggle('open');
                        return;
                    }
                    panel.innerHTML = '<div class="p-3 text-muted small">Loading…</div>';
                    panel.classList.add('open');
                    fetch('compare_results.php?ajax=group_scans&name=' + encodeURIComponent(btn.dataset.name))
                        .then(function (r) { return r.text(); })
                        .then(function (html) { panel.innerHTML = html; panel.dataset.loaded = '1'; })
                        .catch(function () { panel.innerHTML = '<div class="p-3 text-danger small">Failed to load.</div>'; });
                });
            });
            </script>

        <?php endif; ?>
    </main>
<?php
render_foot();
