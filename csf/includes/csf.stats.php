<?php
/**
 * CSF Statistics Module
 * Collects and reports firewall statistics
 */

/**
 * Get firewall status
 * 
 * @return array Firewall status information
 */
function csf_stats_get_status() {
    $config = csf_config_get();
    
    $blocked_ips = csf_iptables_get_blocked_ips();
    $allowed_ips = csf_iptables_get_allowed_ips();
    $whitelist = csf_file_read(CSF_CONFIG_DIR . '/csf.allow');
    $blacklist = csf_file_read(CSF_CONFIG_DIR . '/csf.deny');
    
    return array(
        'firewall_enabled' => (int)$config['ENABLED'],
        'lfd_enabled' => (int)$config['LFD_ENABLE'],
        'blocked_ips' => count($blocked_ips),
        'allowed_ips' => count($allowed_ips),
        'whitelist_entries' => count(array_filter(explode("\n", $whitelist))),
        'blacklist_entries' => count(array_filter(explode("\n", $blacklist))),
        'port_scan_enabled' => (int)$config['PT_ENABLE'],
        'ddos_protection_enabled' => (int)$config['DDOS_ENABLE'],
        'geoip_enabled' => !empty($config['GEOIP_ENABLE'])
    );
}

/**
 * Get block statistics
 * 
 * @return array Block statistics
 */
function csf_stats_get_blocks() {
    $stats_file = CSF_VAR_DIR . '/stats/blocks.json';
    
    if (!csf_file_exists($stats_file)) {
        return array(
            'total_blocks' => 0,
            'blocks_today' => 0,
            'blocks_this_week' => 0,
            'blocks_this_month' => 0,
            'blocks_by_type' => array()
        );
    }
    
    $content = csf_file_read($stats_file);
    $data = json_decode($content, true);
    
    if (!is_array($data)) {
        return array(
            'total_blocks' => 0,
            'blocks_today' => 0,
            'blocks_this_week' => 0,
            'blocks_this_month' => 0,
            'blocks_by_type' => array()
        );
    }
    
    return $data;
}

/**
 * Record block event
 * 
 * @param string $ip IP address
 * @param string $type Block type (port_scan, ddos, login_attempt, etc.)
 * @return bool
 */
function csf_stats_record_block($ip, $type = 'manual') {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $stats_file = CSF_VAR_DIR . '/stats/blocks.json';
    $stats = csf_stats_get_blocks();
    
    $stats['total_blocks']++;
    
    $now = time();
    $today_start = strtotime('today');
    $week_start = strtotime('-7 days');
    $month_start = strtotime('-30 days');
    
    if ($now > $today_start) {
        $stats['blocks_today']++;
    }
    
    if ($now > $week_start) {
        $stats['blocks_this_week']++;
    }
    
    if ($now > $month_start) {
        $stats['blocks_this_month']++;
    }
    
    if (!isset($stats['blocks_by_type'])) {
        $stats['blocks_by_type'] = array();
    }
    
    if (!isset($stats['blocks_by_type'][$type])) {
        $stats['blocks_by_type'][$type] = 0;
    }
    
    $stats['blocks_by_type'][$type]++;
    
    return csf_file_write($stats_file, json_encode($stats, JSON_PRETTY_PRINT));
}

/**
 * Get connection statistics
 * 
 * @param int $limit Number of results
 * @return array Connection statistics
 */
function csf_stats_get_connections($limit = 100) {
    $conn_file = CSF_VAR_DIR . '/stats/connections.json';
    
    if (!csf_file_exists($conn_file)) {
        return array();
    }
    
    $content = csf_file_read($conn_file);
    $connections = json_decode($content, true);
    
    if (!is_array($connections)) {
        return array();
    }
    
    // Sort by count (descending)
    usort($connections, function($a, $b) {
        return $b['count'] - $a['count'];
    });
    
    return array_slice($connections, 0, $limit);
}

/**
 * Record connection
 * 
 * @param string $ip IP address
 * @param int $port Port number
 * @param string $protocol Protocol (TCP/UDP)
 * @return bool
 */
function csf_stats_record_connection($ip, $port, $protocol = 'TCP') {
    if (!csf_validate_ip($ip) || !is_numeric($port)) {
        return false;
    }
    
    $conn_file = CSF_VAR_DIR . '/stats/connections.json';
    $connections = csf_stats_get_connections(1000);
    
    $key = $ip . ':' . $port . '/' . $protocol;
    
    // Find existing connection
    $found = false;
    foreach ($connections as &$conn) {
        if ($conn['key'] === $key) {
            $conn['count']++;
            $conn['last_seen'] = time();
            $found = true;
            break;
        }
    }
    
    if (!$found) {
        $connections[] = array(
            'key' => $key,
            'ip' => $ip,
            'port' => (int)$port,
            'protocol' => $protocol,
            'count' => 1,
            'first_seen' => time(),
            'last_seen' => time()
        );
    }
    
    return csf_file_write($conn_file, json_encode($connections, JSON_PRETTY_PRINT));
}

/**
 * Get system statistics
 * 
 * @return array System statistics
 */
function csf_stats_get_system() {
    $load = function_exists('sys_getloadavg') ? sys_getloadavg() : array(0, 0, 0);
    $uptime = @shell_exec('uptime 2>/dev/null');
    
    return array(
        'load_average' => array(
            '1min' => round($load[0], 2),
            '5min' => round($load[1], 2),
            '15min' => round($load[2], 2)
        ),
        'memory_usage' => array(
            'used' => round(memory_get_usage() / 1024 / 1024, 2),
            'peak' => round(memory_get_peak_usage() / 1024 / 1024, 2)
        ),
        'php_version' => phpversion(),
        'uptime' => trim($uptime) ?: 'unknown'
    );
}

/**
 * Get log statistics
 * 
 * @return array Log statistics
 */
function csf_stats_get_log_stats() {
    $log_file = CSF_VAR_DIR . '/log/csf.log';
    
    $stats = array(
        'total_entries' => 0,
        'file_size' => 0,
        'entries_by_type' => array()
    );
    
    if (!csf_file_exists($log_file)) {
        return $stats;
    }
    
    $stats['file_size'] = filesize($log_file);
    
    $handle = @fopen($log_file, 'r');
    if (!$handle) {
        return $stats;
    }
    
    $line_count = 0;
    while (!feof($handle)) {
        $line = fgets($handle);
        if (!empty(trim($line))) {
            $line_count++;
            
            // Extract type from log line
            if (preg_match('/\[(.*?)\]/', $line, $matches)) {
                $type = $matches[1];
                if (!isset($stats['entries_by_type'][$type])) {
                    $stats['entries_by_type'][$type] = 0;
                }
                $stats['entries_by_type'][$type]++;
            }
        }
    }
    fclose($handle);
    
    $stats['total_entries'] = $line_count;
    
    return $stats;
}

/**
 * Generate daily report
 * 
 * @return array Daily report
 */
function csf_stats_generate_report($days = 1) {
    $cutoff = time() - ($days * 86400);
    
    return array(
        'period' => $days . ' day(s)',
        'period_start' => date('Y-m-d H:i:s', $cutoff),
        'period_end' => date('Y-m-d H:i:s'),
        'status' => csf_stats_get_status(),
        'blocks' => csf_stats_get_blocks(),
        'top_blocked_ips' => csf_stats_get_connections(10),
        'system' => csf_stats_get_system(),
        'logs' => csf_stats_get_log_stats()
    );
}

/**
 * Export statistics to file
 * 
 * @param string $format Format (json, csv, txt)
 * @return string|bool File path or false
 */
function csf_stats_export($format = 'json') {
    $report = csf_stats_generate_report();
    
    if ($format === 'json') {
        $filename = 'csf_stats_' . date('Y-m-d_His') . '.json';
        $content = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } elseif ($format === 'csv') {
        $filename = 'csf_stats_' . date('Y-m-d_His') . '.csv';
        $content = csf_stats_export_csv($report);
    } elseif ($format === 'txt') {
        $filename = 'csf_stats_' . date('Y-m-d_His') . '.txt';
        $content = csf_stats_export_txt($report);
    } else {
        return false;
    }
    
    $export_dir = CSF_VAR_DIR . '/exports';
    if (!is_dir($export_dir)) {
        @mkdir($export_dir, 0755, true);
    }
    
    $file_path = $export_dir . '/' . $filename;
    
    if (csf_file_write($file_path, $content)) {
        return $file_path;
    }
    
    return false;
}

/**
 * Export statistics as CSV
 * 
 * @param array $report Report data
 * @return string CSV content
 */
function csf_stats_export_csv($report) {
    $csv = "CSF Firewall Statistics Report\n";
    $csv .= "Generated: " . date('Y-m-d H:i:s') . "\n\n";
    
    $csv .= "Status\n";
    foreach ($report['status'] as $key => $value) {
        $csv .= $key . "," . $value . "\n";
    }
    
    $csv .= "\nBlocks\n";
    foreach ($report['blocks'] as $key => $value) {
        if (is_array($value)) {
            $csv .= $key . "," . json_encode($value) . "\n";
        } else {
            $csv .= $key . "," . $value . "\n";
        }
    }
    
    return $csv;
}

/**
 * Export statistics as TXT
 * 
 * @param array $report Report data
 * @return string Text content
 */
function csf_stats_export_txt($report) {
    $text = "========================================\n";
    $text .= "CSF FIREWALL STATISTICS REPORT\n";
    $text .= "========================================\n";
    $text .= "Generated: " . date('Y-m-d H:i:s') . "\n\n";
    
    $text .= "STATUS\n";
    $text .= "--------\n";
    foreach ($report['status'] as $key => $value) {
        $text .= ucwords(str_replace('_', ' ', $key)) . ": " . $value . "\n";
    }
    
    $text .= "\nBLOCK STATISTICS\n";
    $text .= "--------\n";
    foreach ($report['blocks'] as $key => $value) {
        if (is_array($value)) {
            $text .= ucwords(str_replace('_', ' ', $key)) . ":\n";
            foreach ($value as $k => $v) {
                $text .= "  " . $k . ": " . $v . "\n";
            }
        } else {
            $text .= ucwords(str_replace('_', ' ', $key)) . ": " . $value . "\n";
        }
    }
    
    return $text;
}

/**
 * Reset statistics
 * 
 * @return bool
 */
function csf_stats_reset() {
    $files = array(
        CSF_VAR_DIR . '/stats/blocks.json',
        CSF_VAR_DIR . '/stats/connections.json'
    );
    
    foreach ($files as $file) {
        if (csf_file_exists($file)) {
            csf_file_write($file, '{}');
        }
    }
    
    csf_log('Statistics reset', 'STATS');
    return true;
}
