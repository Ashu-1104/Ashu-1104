<?php
/**
 * CSF DDoS Protection Module
 * Detects and mitigates DDoS attacks
 */

/**
 * Check connection rate for IP
 * 
 * @param string $ip IP address
 * @param int $limit Maximum connections allowed
 * @param int $timeframe Time period in seconds
 * @return bool True if exceeds limit
 */
function csf_ddos_check_rate($ip, $limit = 0, $timeframe = 60) {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $config = csf_config_get();
    
    if ($limit === 0) {
        $limit = isset($config['DDOS_LIMIT']) ? (int)$config['DDOS_LIMIT'] : 100;
    }
    
    $log_file = CSF_VAR_DIR . '/ddos/' . md5($ip) . '.log';
    $now = time();
    $cutoff = $now - $timeframe;
    $connections = 0;
    
    // Read existing connections
    if (csf_file_exists($log_file)) {
        $content = csf_file_read($log_file);
        $timestamps = explode("\n", trim($content));
        
        foreach ($timestamps as $timestamp) {
            if (!empty($timestamp) && is_numeric($timestamp)) {
                $ts = (int)$timestamp;
                if ($ts > $cutoff) {
                    $connections++;
                }
            }
        }
    }
    
    // Increment counter
    $connections++;
    
    // Write updated timestamps
    $timestamps = array();
    if (csf_file_exists($log_file)) {
        $content = csf_file_read($log_file);
        $timestamps = explode("\n", trim($content));
    }
    
    $timestamps[] = $now;
    // Keep only recent timestamps
    $timestamps = array_filter($timestamps, function($ts) use ($cutoff) {
        return !empty($ts) && (int)$ts > $cutoff;
    });
    
    csf_file_write($log_file, implode("\n", $timestamps));
    
    return $connections > $limit;
}

/**
 * Log DDoS attempt
 * 
 * @param string $ip IP address
 * @param string $reason Reason for blocking
 * @return bool
 */
function csf_ddos_log_attempt($ip, $reason = 'High connection rate') {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $ddos_file = CSF_VAR_DIR . '/ddos/attempts.json';
    $attempts = array();
    
    if (csf_file_exists($ddos_file)) {
        $content = csf_file_read($ddos_file);
        $attempts = json_decode($content, true);
        if (!is_array($attempts)) {
            $attempts = array();
        }
    }
    
    if (!isset($attempts[$ip])) {
        $attempts[$ip] = array(
            'count' => 0,
            'first_attempt' => time(),
            'last_attempt' => time(),
            'reason' => $reason
        );
    }
    
    $attempts[$ip]['count']++;
    $attempts[$ip]['last_attempt'] = time();
    $attempts[$ip]['reason'] = $reason;
    
    return csf_file_write($ddos_file, json_encode($attempts, JSON_PRETTY_PRINT));
}

/**
 * Block IP for DDoS
 * 
 * @param string $ip IP address
 * @param string $reason Reason for block
 * @return bool
 */
function csf_ddos_block_ip($ip, $reason = 'DDoS attack detected') {
    $config = csf_config_get();
    
    if (empty($config['DDOS_BLOCK']) || $config['DDOS_BLOCK'] != 1) {
        return false;
    }
    
    // Check if already blocked
    if (csf_iptables_ip_exists($ip, 'BLOCK')) {
        return true;
    }
    
    if (csf_iptables_add_ip($ip, 'BLOCK', $reason)) {
        csf_log('Blocked IP ' . $ip . ' for DDoS: ' . $reason, 'DDOS');
        csf_lfd_send_command('DDOS_BLOCK', $ip);
        csf_ddos_log_attempt($ip, $reason);
        return true;
    }
    
    return false;
}

/**
 * Get connection statistics for IP
 * 
 * @param string $ip IP address
 * @param int $timeframe Time period in seconds
 * @return array Statistics
 */
function csf_ddos_get_statistics($ip, $timeframe = 3600) {
    if (!csf_validate_ip($ip)) {
        return array();
    }
    
    $log_file = CSF_VAR_DIR . '/ddos/' . md5($ip) . '.log';
    $now = time();
    $cutoff = $now - $timeframe;
    $connections = 0;
    
    if (csf_file_exists($log_file)) {
        $content = csf_file_read($log_file);
        $timestamps = explode("\n", trim($content));
        
        foreach ($timestamps as $timestamp) {
            if (!empty($timestamp) && is_numeric($timestamp) && (int)$timestamp > $cutoff) {
                $connections++;
            }
        }
    }
    
    return array(
        'ip' => $ip,
        'connections' => $connections,
        'timeframe' => $timeframe,
        'rate' => round($connections / $timeframe * 60, 2) . ' per minute'
    );
}

/**
 * Get top DDoS attackers
 * 
 * @param int $limit Maximum results
 * @return array
 */
function csf_ddos_get_top_attackers($limit = 10) {
    $ddos_file = CSF_VAR_DIR . '/ddos/attempts.json';
    
    if (!csf_file_exists($ddos_file)) {
        return array();
    }
    
    $content = csf_file_read($ddos_file);
    $attempts = json_decode($content, true);
    
    if (!is_array($attempts)) {
        return array();
    }
    
    // Sort by attempt count (descending)
    uasort($attempts, function($a, $b) {
        return $b['count'] - $a['count'];
    });
    
    $result = array();
    $count = 0;
    foreach ($attempts as $ip => $data) {
        if ($count >= $limit) {
            break;
        }
        
        $result[] = array_merge(array('ip' => $ip), $data);
        $count++;
    }
    
    return $result;
}

/**
 * Clear DDoS attempt history for IP
 * 
 * @param string $ip IP address
 * @return bool
 */
function csf_ddos_clear_history($ip) {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $log_file = CSF_VAR_DIR . '/ddos/' . md5($ip) . '.log';
    
    if (csf_file_exists($log_file)) {
        return @unlink($log_file);
    }
    
    return true;
}

/**
 * Detect HTTP flood attack
 * 
 * @param string $ip IP address
 * @param string $path Request path
 * @return bool True if flood detected
 */
function csf_ddos_detect_http_flood($ip, $path = '/') {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $config = csf_config_get();
    
    if (empty($config['HTTP_FLOOD_ENABLE']) || $config['HTTP_FLOOD_ENABLE'] != 1) {
        return false;
    }
    
    $flood_file = CSF_VAR_DIR . '/ddos/http_flood_' . md5($ip) . '.json';
    $now = time();
    $window = isset($config['HTTP_FLOOD_WINDOW']) ? (int)$config['HTTP_FLOOD_WINDOW'] : 10;
    $limit = isset($config['HTTP_FLOOD_LIMIT']) ? (int)$config['HTTP_FLOOD_LIMIT'] : 50;
    
    $requests = array();
    
    // Load existing requests
    if (csf_file_exists($flood_file)) {
        $content = csf_file_read($flood_file);
        $data = json_decode($content, true);
        if (is_array($data)) {
            $requests = $data;
        }
    }
    
    // Remove old requests outside window
    $requests = array_filter($requests, function($entry) use ($now, $window) {
        return ($now - $entry['timestamp']) < $window;
    });
    
    // Add new request
    $requests[] = array(
        'path' => $path,
        'timestamp' => $now
    );
    
    // Check limit
    if (count($requests) > $limit) {
        csf_file_write($flood_file, json_encode($requests, JSON_PRETTY_PRINT));
        return true;
    }
    
    csf_file_write($flood_file, json_encode($requests, JSON_PRETTY_PRINT));
    return false;
}

/**
 * Cleanup old DDoS logs
 * 
 * @param int $max_age Age in seconds
 * @return int Number of cleaned files
 */
function csf_ddos_cleanup_logs($max_age = 86400) {
    $ddos_dir = CSF_VAR_DIR . '/ddos';
    $cleaned = 0;
    
    if (!is_dir($ddos_dir)) {
        return 0;
    }
    
    $files = scandir($ddos_dir);
    $now = time();
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..' || $file === 'attempts.json') {
            continue;
        }
        
        $file_path = $ddos_dir . '/' . $file;
        
        if (!is_file($file_path)) {
            continue;
        }
        
        if (($now - filemtime($file_path)) > $max_age) {
            if (@unlink($file_path)) {
                $cleaned++;
            }
        }
    }
    
    return $cleaned;
}

/**
 * Reset DDoS protection
 * 
 * @return bool
 */
function csf_ddos_reset() {
    $ddos_file = CSF_VAR_DIR . '/ddos/attempts.json';
    
    if (csf_file_exists($ddos_file)) {
        csf_file_write($ddos_file, '{}');
    }
    
    csf_ddos_cleanup_logs(0);
    csf_log('DDoS protection reset', 'DDOS');
    
    return true;
}
