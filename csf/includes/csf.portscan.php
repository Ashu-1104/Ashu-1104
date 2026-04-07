<?php
/**
 * CSF Port Scan Detection Module
 * Detects and blocks port scanning attempts
 */

/**
 * Initialize port scan detection
 * 
 * @return bool
 */
function csf_portscan_init() {
    $config = csf_config_get();
    
    if (empty($config['PT_ENABLE']) || $config['PT_ENABLE'] != 1) {
        return false;
    }
    
    // Ensure port scan data directory exists
    $ps_dir = CSF_VAR_DIR . '/portscan';
    if (!is_dir($ps_dir)) {
        @mkdir($ps_dir, 0755, true);
    }
    
    return true;
}

/**
 * Log port scan attempt
 * 
 * @param string $ip IP address attempting scan
 * @param int $port Port being scanned
 * @param string $protocol TCP/UDP
 * @return bool
 */
function csf_portscan_log_attempt($ip, $port, $protocol = 'TCP') {
    if (!csf_validate_ip($ip) || !is_numeric($port) || $port < 1 || $port > 65535) {
        return false;
    }
    
    $protocol = strtoupper($protocol);
    if ($protocol !== 'TCP' && $protocol !== 'UDP') {
        $protocol = 'TCP';
    }
    
    $ip_file = CSF_VAR_DIR . '/portscan/' . md5($ip) . '.json';
    $scan_data = array();
    
    // Load existing scan data
    if (csf_file_exists($ip_file)) {
        $content = csf_file_read($ip_file);
        $scan_data = json_decode($content, true);
        if (!is_array($scan_data)) {
            $scan_data = array();
        }
    }
    
    // Add new port scan entry
    $now = time();
    if (!isset($scan_data['ports'])) {
        $scan_data['ports'] = array();
    }
    
    $scan_data['ports'][] = array(
        'port' => (int)$port,
        'protocol' => $protocol,
        'timestamp' => $now
    );
    
    // Keep only recent scans (last hour)
    $scan_data['ports'] = array_filter($scan_data['ports'], function($entry) use ($now) {
        return ($now - $entry['timestamp']) < 3600;
    });
    
    $scan_data['last_scan'] = $now;
    $scan_data['scan_count'] = count($scan_data['ports']);
    
    // Write updated scan data
    $result = csf_file_write($ip_file, json_encode($scan_data, JSON_PRETTY_PRINT));
    
    if (!$result) {
        return false;
    }
    
    // Check if threshold exceeded
    $config = csf_config_get();
    $threshold = isset($config['PT_LIMIT']) ? (int)$config['PT_LIMIT'] : 10;
    
    if ($scan_data['scan_count'] >= $threshold) {
        csf_portscan_block_ip($ip, $scan_data['scan_count']);
    }
    
    return true;
}

/**
 * Block IP for port scanning
 * 
 * @param string $ip IP address to block
 * @param int $port_count Number of ports scanned
 * @return bool
 */
function csf_portscan_block_ip($ip, $port_count = 0) {
    $config = csf_config_get();
    
    if (empty($config['PT_BLOCK']) || $config['PT_BLOCK'] != 1) {
        return false;
    }
    
    // Check if already blocked
    if (csf_iptables_ip_exists($ip, 'BLOCK')) {
        return true;
    }
    
    $reason = 'Port scan detected (' . $port_count . ' ports scanned)';
    
    if (csf_iptables_add_ip($ip, 'BLOCK', $reason)) {
        csf_log('Blocked IP ' . $ip . ' for port scanning: ' . $reason, 'PORTSCAN');
        csf_lfd_send_command('PT_BLOCK', $ip);
        return true;
    }
    
    return false;
}

/**
 * Check for suspicious port scan patterns
 * 
 * @param string $ip IP address
 * @return array Scan statistics
 */
function csf_portscan_get_statistics($ip) {
    if (!csf_validate_ip($ip)) {
        return array();
    }
    
    $ip_file = CSF_VAR_DIR . '/portscan/' . md5($ip) . '.json';
    
    if (!csf_file_exists($ip_file)) {
        return array(
            'ip' => $ip,
            'scans' => 0,
            'ports' => array(),
            'last_scan' => 0
        );
    }
    
    $content = csf_file_read($ip_file);
    $scan_data = json_decode($content, true);
    
    if (!is_array($scan_data)) {
        return array(
            'ip' => $ip,
            'scans' => 0,
            'ports' => array(),
            'last_scan' => 0
        );
    }
    
    return array(
        'ip' => $ip,
        'scans' => isset($scan_data['scan_count']) ? $scan_data['scan_count'] : 0,
        'ports' => isset($scan_data['ports']) ? $scan_data['ports'] : array(),
        'last_scan' => isset($scan_data['last_scan']) ? $scan_data['last_scan'] : 0
    );
}

/**
 * Get list of IPs attempting port scans
 * 
 * @param int $limit Maximum number of results
 * @return array
 */
function csf_portscan_get_active_scanners($limit = 100) {
    $ps_dir = CSF_VAR_DIR . '/portscan';
    $scanners = array();
    
    if (!is_dir($ps_dir)) {
        return array();
    }
    
    $files = scandir($ps_dir);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        
        if (!is_file($ps_dir . '/' . $file)) {
            continue;
        }
        
        $content = csf_file_read($ps_dir . '/' . $file);
        $scan_data = json_decode($content, true);
        
        if (!is_array($scan_data) || empty($scan_data['ports'])) {
            continue;
        }
        
        // Clean old entries
        $now = time();
        $scan_data['ports'] = array_filter($scan_data['ports'], function($entry) use ($now) {
            return ($now - $entry['timestamp']) < 86400; // Last 24 hours
        });
        
        if (empty($scan_data['ports'])) {
            continue;
        }
        
        // Extract unique ports
        $ports = array_unique(array_column($scan_data['ports'], 'port'));
        
        $scanners[] = array(
            'ip' => $scan_data['ip'] ?? 'unknown',
            'port_count' => count($scan_data['ports']),
            'unique_ports' => count($ports),
            'ports' => array_values($ports),
            'last_scan' => $scan_data['last_scan'] ?? 0
        );
    }
    
    // Sort by port count (descending)
    usort($scanners, function($a, $b) {
        return $b['port_count'] - $a['port_count'];
    });
    
    return array_slice($scanners, 0, $limit);
}

/**
 * Clear port scan history for IP
 * 
 * @param string $ip IP address
 * @return bool
 */
function csf_portscan_clear_history($ip) {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $ip_file = CSF_VAR_DIR . '/portscan/' . md5($ip) . '.json';
    
    if (!csf_file_exists($ip_file)) {
        return true;
    }
    
    return @unlink($ip_file);
}

/**
 * Reset port scan detection for all IPs
 * 
 * @return int Number of cleared entries
 */
function csf_portscan_reset_all() {
    $ps_dir = CSF_VAR_DIR . '/portscan';
    $cleared = 0;
    
    if (!is_dir($ps_dir)) {
        return 0;
    }
    
    $files = scandir($ps_dir);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        
        if (@unlink($ps_dir . '/' . $file)) {
            $cleared++;
        }
    }
    
    if ($cleared > 0) {
        csf_log('Reset port scan detection for ' . $cleared . ' IPs', 'PORTSCAN');
    }
    
    return $cleared;
}

/**
 * Analyze port scan pattern
 * 
 * @param string $ip IP address
 * @return array Pattern analysis
 */
function csf_portscan_analyze_pattern($ip) {
    $stats = csf_portscan_get_statistics($ip);
    
    if (empty($stats['ports'])) {
        return array(
            'ip' => $ip,
            'pattern' => 'none',
            'severity' => 'low',
            'description' => 'No port scan activity'
        );
    }
    
    $ports = array_column($stats['ports'], 'port');
    $port_count = count($ports);
    
    // Sequential scan pattern
    sort($ports);
    $is_sequential = true;
    for ($i = 1; $i < count($ports); $i++) {
        if ($ports[$i] - $ports[$i-1] != 1) {
            $is_sequential = false;
            break;
        }
    }
    
    if ($is_sequential && $port_count > 10) {
        return array(
            'ip' => $ip,
            'pattern' => 'sequential',
            'severity' => 'critical',
            'description' => 'Sequential port scan detected'
        );
    }
    
    // High volume scan
    if ($port_count > 100) {
        return array(
            'ip' => $ip,
            'pattern' => 'bulk_scan',
            'severity' => 'critical',
            'description' => 'High volume port scan'
        );
    }
    
    // Targeted scan
    if ($port_count >= 10) {
        return array(
            'ip' => $ip,
            'pattern' => 'targeted',
            'severity' => 'high',
            'description' => 'Targeted port scan'
        );
    }
    
    // Low volume
    return array(
        'ip' => $ip,
        'pattern' => 'low_volume',
        'severity' => 'medium',
        'description' => 'Low volume port scanning'
    );
}
