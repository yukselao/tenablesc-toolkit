<?php
/**
 * Shared view helpers + layout (sidebar, head/foot, report renderer).
 * Used by every page so the chrome stays consistent.
 */

function h($s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

/** Render a list of "port/proto" strings as compact badges. */
function port_badges(array $ports, string $variant = 'secondary'): string
{
    if (empty($ports)) {
        return '<span class="text-muted small">—</span>';
    }
    $out = '';
    foreach ($ports as $p) {
        $out .= '<span class="badge rounded-pill text-bg-' . $variant . ' me-1 mb-1 font-monospace">' . h($p) . '</span>';
    }
    return $out;
}

function render_head(string $title): void
{
    ?>
<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($title) ?> · Nessus Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="assets/style.css" rel="stylesheet">
</head>
<body>
<div class="layout">
    <?php
}

/**
 * @param string $active  one of: nessus | results | settings
 */
function render_sidebar(string $active, array $history = []): void
{
    $sections = [
        'Nessus File' => [
            'nessus' => ['index.php', 'bi-arrow-left-right', 'Compare Nessus Scans'],
        ],
        'Tenable Security Center' => [
            'results'  => ['compare_results.php', 'bi-cloud-download', 'Compare Scan Results'],
            'settings' => ['settings.php',        'bi-gear',           'Security Center Settings'],
        ],
    ];
    ?>
    <aside class="sidebar">
        <div class="brand">
            <i class="bi bi-shield-shaded"></i>
            <div>
                <div class="brand-title">Nessus Toolkit</div>
                <div class="brand-sub">Security Center</div>
            </div>
        </div>
        <nav class="nav flex-column px-2">
            <?php foreach ($sections as $section => $items): ?>
                <div class="nav-section-title"><?= h($section) ?></div>
                <?php foreach ($items as $key => [$href, $icon, $label]): ?>
                    <a class="nav-link <?= $active === $key ? 'active' : '' ?>" href="<?= $href ?>">
                        <i class="bi <?= $icon ?>"></i> <?= h($label) ?>
                    </a>
                <?php endforeach; ?>
            <?php endforeach; ?>
        </nav>

        <?php if ($history): ?>
        <div class="sidebar-section">
            <div class="sidebar-heading">Recent Analyses</div>
            <ul class="history">
                <?php foreach ($history as $hrow): ?>
                    <li>
                        <div class="history-files" title="<?= h($hrow['first_filename']) ?> → <?= h($hrow['last_filename']) ?>">
                            <i class="bi <?= ($hrow['source'] ?? 'file') === 'sc' ? 'bi-cloud' : 'bi-file-earmark' ?>"></i>
                            <?= h($hrow['first_filename']) ?> → <?= h($hrow['last_filename']) ?>
                        </div>
                        <div class="history-meta">
                            <span class="text-success">+<?= (int) $hrow['new_hosts'] ?> host</span>
                            <span class="text-warning"><?= (int) $hrow['new_ports'] ?> port</span>
                            <span class="text-danger"><?= (int) $hrow['unreachable'] ?> down</span>
                        </div>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>

        <div class="sidebar-foot">
            <span class="text-muted small">tenablesc-toolkit · ui</span>
        </div>
    </aside>
    <?php
}

function render_foot(): void
{
    ?>
</div>
</body>
</html>
    <?php
}

/** Export / print toolbar shown above a report. */
function render_export_bar(?int $analysisId): void
{
    ?>
    <div class="export-bar no-print">
        <?php if ($analysisId): ?>
            <a class="btn btn-outline-success btn-sm" href="export.php?id=<?= (int) $analysisId ?>&format=csv">
                <i class="bi bi-filetype-csv"></i> Export CSV
            </a>
            <a class="btn btn-outline-info btn-sm" href="export.php?id=<?= (int) $analysisId ?>&format=html" target="_blank">
                <i class="bi bi-filetype-html"></i> Export HTML
            </a>
        <?php endif; ?>
        <button type="button" class="btn btn-outline-light btn-sm" onclick="window.print()">
            <i class="bi bi-printer"></i> Print / PDF
        </button>
    </div>
    <?php
}

/** Render the summary cards + 3 comparison tables. */
function render_report(array $result, string $firstLabel, string $lastLabel): void
{
    $s = $result['summary'];
    ?>
    <section class="summary-grid">
        <div class="stat-card">
            <div class="stat-num"><?= $s['first_hosts'] ?></div>
            <div class="stat-label">First Scan Hosts</div>
        </div>
        <div class="stat-card">
            <div class="stat-num"><?= $s['last_hosts'] ?></div>
            <div class="stat-label">Last Scan Hosts</div>
        </div>
        <div class="stat-card accent-success">
            <div class="stat-num"><?= $s['new_hosts'] ?></div>
            <div class="stat-label"><i class="bi bi-plus-circle"></i> Newly Detected</div>
        </div>
        <div class="stat-card accent-warning">
            <div class="stat-num"><?= $s['new_ports'] ?></div>
            <div class="stat-label"><i class="bi bi-ethernet"></i> New Ports (hosts)</div>
        </div>
        <div class="stat-card accent-danger">
            <div class="stat-num"><?= $s['unreachable'] ?></div>
            <div class="stat-label"><i class="bi bi-x-circle"></i> Unreachable</div>
        </div>
    </section>

    <div class="report-meta">
        <span><i class="bi bi-file-earmark-text"></i> <strong>First:</strong> <?= h($firstLabel) ?></span>
        <span><i class="bi bi-file-earmark-text"></i> <strong>Last:</strong> <?= h($lastLabel) ?></span>
    </div>

    <!-- Newly Detected Hosts -->
    <section class="card report-card">
        <div class="card-header accent-success">
            <i class="bi bi-plus-circle-fill"></i> Newly Detected Hosts
            <span class="count-pill"><?= count($result['new_hosts']) ?></span>
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead><tr><th>#</th><th>Host</th><th>Operating System</th><th>MAC</th><th>Open Ports</th></tr></thead>
                <tbody>
                <?php if (empty($result['new_hosts'])): ?>
                    <tr><td colspan="5" class="empty-row">No hosts that appear in the last scan but not the first.</td></tr>
                <?php else: $i = 1; foreach ($result['new_hosts'] as $r): ?>
                    <tr>
                        <td class="text-muted"><?= $i++ ?></td>
                        <td><span class="host-chip"><?= h($r['host']) ?></span></td>
                        <td><?= h($r['os']) ?></td>
                        <td class="font-monospace small"><?= h($r['mac'] ?: '—') ?></td>
                        <td><?= port_badges($r['ports'], 'success') ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <!-- New Detected Ports -->
    <section class="card report-card">
        <div class="card-header accent-warning">
            <i class="bi bi-ethernet"></i> New Detected Ports
            <span class="count-pill"><?= count($result['new_ports']) ?></span>
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead><tr><th>#</th><th>Host</th><th>Operating System</th><th>New Ports</th><th>Port Count</th></tr></thead>
                <tbody>
                <?php if (empty($result['new_ports'])): ?>
                    <tr><td colspan="5" class="empty-row">No newly opened ports on hosts present in both scans.</td></tr>
                <?php else: $i = 1; foreach ($result['new_ports'] as $r): ?>
                    <tr>
                        <td class="text-muted"><?= $i++ ?></td>
                        <td><span class="host-chip"><?= h($r['host']) ?></span></td>
                        <td><?= h($r['os']) ?></td>
                        <td><?= port_badges($r['new_ports'], 'warning') ?></td>
                        <td class="small text-secondary"><?= $r['prev_count'] ?> &rarr; <?= $r['curr_count'] ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <!-- Unreachable Hosts -->
    <section class="card report-card">
        <div class="card-header accent-danger">
            <i class="bi bi-x-circle-fill"></i> Unreachable Hosts
            <span class="count-pill"><?= count($result['unreachable']) ?></span>
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead><tr><th>#</th><th>Host</th><th>Operating System</th><th>MAC</th><th>Previous Ports</th></tr></thead>
                <tbody>
                <?php if (empty($result['unreachable'])): ?>
                    <tr><td colspan="5" class="empty-row">No hosts that appear in the first scan but not the last.</td></tr>
                <?php else: $i = 1; foreach ($result['unreachable'] as $r): ?>
                    <tr>
                        <td class="text-muted"><?= $i++ ?></td>
                        <td><span class="host-chip"><?= h($r['host']) ?></span></td>
                        <td><?= h($r['os']) ?></td>
                        <td class="font-monospace small"><?= h($r['mac'] ?: '—') ?></td>
                        <td><?= port_badges($r['ports'], 'secondary') ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </section>
    <?php
}
