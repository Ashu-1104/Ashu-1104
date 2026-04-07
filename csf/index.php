<?php
/**
 * CSF Firewall PHP Fork - Main Entry Point
 * ConfigServer Firewall translated to PHP for Webuzo integration
 * Version: 14.0.0-PHP
 * 
 * This file serves as the main interface for CSF operations
 * It can be used for web UI, API endpoints, or command-line operations
 */

// Load CSF core
require_once __DIR__ . '/includes/csf.core.php';

// Initialize CSF
csf_init(false);

// Check if this is an API request
$path = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '/';

if (strpos($path, '/api/') === 0) {
    // Route to API handler
    $response = csf_api_route($_REQUEST);
    exit;
}

// Otherwise, show status page or dashboard
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSF Control Panel - PHP Fork</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
    <style>
        body { background-color: #f5f5f5; }
        .navbar { background-color: #2c3e50; color: white; }
        .card { box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card { border-left: 4px solid #3498db; }
        .stat-card.danger { border-left-color: #e74c3c; }
        .stat-card.success { border-left-color: #27ae60; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">CSF Firewall - PHP Fork</span>
            <span class="text-white">v<?php echo CSF_VERSION; ?></span>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="row">
            <div class="col-md-12">
                <h2 class="mb-4">Firewall Status</h2>
            </div>
        </div>

        <div class="row">
            <?php
            $status = csf_stats_get_status();
            $blocks = csf_stats_get_blocks();
            ?>
            
            <div class="col-md-3 mb-4">
                <div class="card stat-card">
                    <div class="card-body">
                        <h6 class="card-title text-muted">Firewall Status</h6>
                        <h4><?php echo $status['firewall_enabled'] ? 'ENABLED' : 'DISABLED'; ?></h4>
                    </div>
                </div>
            </div>

            <div class="col-md-3 mb-4">
                <div class="card stat-card danger">
                    <div class="card-body">
                        <h6 class="card-title text-muted">Blocked IPs</h6>
                        <h4><?php echo $status['blocked_ips']; ?></h4>
                    </div>
                </div>
            </div>

            <div class="col-md-3 mb-4">
                <div class="card stat-card success">
                    <div class="card-body">
                        <h6 class="card-title text-muted">Allowed IPs</h6>
                        <h4><?php echo $status['allowed_ips']; ?></h4>
                    </div>
                </div>
            </div>

            <div class="col-md-3 mb-4">
                <div class="card stat-card">
                    <div class="card-body">
                        <h6 class="card-title text-muted">LFD Status</h6>
                        <h4><?php echo $status['lfd_enabled'] ? 'RUNNING' : 'STOPPED'; ?></h4>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Block Statistics</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>Total Blocks:</strong> <?php echo $blocks['total_blocks']; ?></p>
                        <p><strong>Today:</strong> <?php echo $blocks['blocks_today']; ?></p>
                        <p><strong>This Week:</strong> <?php echo $blocks['blocks_this_week']; ?></p>
                        <p><strong>This Month:</strong> <?php echo $blocks['blocks_this_month']; ?></p>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Features</h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between">
                                <span>Port Scanning Detection</span>
                                <span><?php echo $status['port_scan_enabled'] ? '✓' : '✗'; ?></span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between">
                                <span>DDoS Protection</span>
                                <span><?php echo $status['ddos_protection_enabled'] ? '✓' : '✗'; ?></span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between">
                                <span>GeoIP Blocking</span>
                                <span><?php echo $status['geoip_enabled'] ? '✓' : '✗'; ?></span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="alert alert-info">
                    <strong>API Available:</strong> Use <code>/csf/api/</code> endpoint for REST API access
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
