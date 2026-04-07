<?php
/**
 * CSF DDoS Protection Module
 * Connection flood and DDoS detection
 */

/**
 * Initialize DDoS protection
 * 
 * @return bool
 */
function ddos_init() {
    $config = $GLOBALS['csf_config'];
    
    if (!isset($config['CONNLIMIT']) || !$config['CONNLIMIT']) {
        return false;
    }
    
    return true;
}

/**
 * Check connection limits
 * 
 * @return array Offending IPs
 */
function ddos_check_connections() {
    $config = $GLOBALS['csf_config'];
    $limit = isset($config['CONNLIMIT']) ? intval($config['CONNLIMIT']) : 100;
    $offenders = array();
    
    // Get netstat data
    $output = array();
    exec('netstat -tn 2>/dev/null | grep ESTABLISHED', $output);
    
    $ip_count = array();
    
    foreach ($output as $line) {
        // Extract source IP
        if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)/', $line, $matches)) {
            $ip = $matches[1];
            
            // Skip localhost
            if ($ip === '127.0.0.1' || $ip === '::1') {
                continue;
            }
            
            if (!isset($ip_count[$ip])) {
                $ip_count[$ip] = 0;
            }
            
            $ip_count[$ip]++;
        }
    }
    
    // Find offenders
    foreach ($ip_count as $ip => $count) {
        if ($count > $limit) {
            $offenders[$ip] = $count;
        }
    }
    
    return $offenders;
}

/**
 * Detect SYN flood attacks
 * 
 * @return array Attacking IPs
 */
function ddos_detect_syn_flood() {
    $config = $GLOBALS['csf_config'];
    
    if (!isset($config['SYNFLOOD']) || !$config['SYNFLOOD']) {
        return array();
    }
    
    $threshold = isset($config['SYNFLOOD_RATE']) ? intval($config['SYNFLOOD_RATE']) : 100;
    $attackers = array();
    
    // Get SYN_RECV connections
    $output = array();
    exec('netstat -tn 2>/dev/null | grep SYN_RECV', $output);
    
    $ip_syn = array();
    
    foreach ($output as $line) {
        if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)/', $line, $matches)) {
            $ip = $matches[1];
            
            if (!isset($ip_syn[$ip])) {
                $ip_syn[$ip] = 0;
            }
            
            $ip_syn[$ip]++;
        }
    }
    
    // Find potential attackers
    foreach ($ip_syn as $ip => $count) {
        if ($count > $threshold) {
            $attackers[$ip] = $count;
        }
    }
    
    return $attackers;
}

/**
 * Detect HTTP flood attacks
 * 
 * @return array Attacking IPs with request counts
 */
function ddos_detect_http_flood() {
    $config = $GLOBALS['csf_config'];
    
    if (!isset($config['HTTPFLOOD']) || !$config['HTTPFLOOD']) {
        return array();
    }
    
    $threshold = isset($config['HTTPFLOOD_RATE']) ? intval($config['HTTPFLOOD_RATE']) : 100;
    $attackers = array();
    
    // Check web server access logs
    $access_logs = array(
        '/var/log/apache2/access.log',
        '/var/log/httpd/access_log',
        '/var/log/nginx/access.log',
    );
    
    $cutoff_time = time() - 60; // Last 60 seconds
    $ip_requests = array();
    
    foreach ($access_logs as $log) {
        if (!file_exists($log) || !is_readable($log)) {
            continue;
        }
        
        $lines = file_tail($log, 10000);
        
        foreach ($lines as $line) {
            // Parse web server log format
            if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $line, $matches)) {
                $ip = $matches[1];
                
                // Skip localhost
                if ($ip === '127.0.0.1') {
                    continue;
                }
                
                if (!isset($ip_requests[$ip])) {
                    $ip_requests[$ip] = 0;
                }
                
                $ip_requests[$ip]++;
            }
        }
    }
    
    // Find attackers
    foreach ($ip_requests as $ip => $count) {
        if ($count > $threshold) {
            $attackers[$ip] = $count;
        }
    }
    
    return $attackers;
}

/**
 * Block DDoS attacker IP
 * 
 * @param string $ip Attacker IP
 * @param string $reason Attack type
 * @return bool
 */
function ddos_block_attacker($ip, $reason = 'DDoS Attack') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    
    // Add to temp block list
    $temp_block_file = CSF_VAR . '/ddos.temp';
    $entry = $ip . '|' . $reason . '|' . time() . '|3600' . "\n";
    
    file_put_contents($temp_block_file, $entry, FILE_APPEND);
    
    // Add to firewall
    iptables_add_deny($ip, $reason);
    
    csf_log('DDoS attacker blocked: ' . $ip . ' - ' . $reason, 'WARN', 'DDOS');
    
    return true;
}

/**
 * Get current DDoS status
 * 
 * @return array Status information
 */
function ddos_get_status() {
    $status = array(
        'syn_flood_detected' => false,
        'http_flood_detected' => false,
        'connection_limit_exceeded' => false,
        'attacking_ips' => array(),
        'last_check' => time(),
    );
    
    // Check SYN floods
    $syn_attackers = ddos_detect_syn_flood();
    if (!empty($syn_attackers)) {
        $status['syn_flood_detected'] = true;
        $status['attacking_ips'] = array_merge($status['attacking_ips'], array_keys($syn_attackers));
    }
    
    // Check HTTP floods
    $http_attackers = ddos_detect_http_flood();
    if (!empty($http_attackers)) {
        $status['http_flood_detected'] = true;
        $status['attacking_ips'] = array_merge($status['attacking_ips'], array_keys($http_attackers));
    }
    
    // Check connection limits
    $conn_violators = ddos_check_connections();
    if (!empty($conn_violators)) {
        $status['connection_limit_exceeded'] = true;
        $status['attacking_ips'] = array_merge($status['attacking_ips'], array_keys($conn_violators));
    }
    
    // Remove duplicates
    $status['attacking_ips'] = array_unique($status['attacking_ips']);
    
    return $status;
}

/**
 * Auto-respond to DDoS attacks
 * 
 * @return array Blocked IPs
 */
function ddos_auto_block() {
    $blocked = array();
    
    // Check SYN floods
    $syn_attackers = ddos_detect_syn_flood();
    foreach ($syn_attackers as $ip => $count) {
        if (ddos_block_attacker($ip, 'SYN Flood (' . $count . ' connections)')) {
            $blocked[] = $ip;
        }
    }
    
    // Check HTTP floods
    $http_attackers = ddos_detect_http_flood();
    foreach ($http_attackers as $ip => $count) {
        if (ddos_block_attacker($ip, 'HTTP Flood (' . $count . ' requests)')) {
            $blocked[] = $ip;
        }
    }
    
    // Check connection limits
    $conn_violators = ddos_check_connections();
    foreach ($conn_violators as $ip => $count) {
        if (ddos_block_attacker($ip, 'Connection Limit Exceeded (' . $count . ')')) {
            $blocked[] = $ip;
        }
    }
    
    return array_unique($blocked);
}

/**
 * Clear temporary DDoS blocks
 * 
 * @param int $max_age Age in seconds
 * @return int Cleared entries
 */
function ddos_clear_temp_blocks($max_age = 3600) {
    $temp_block_file = CSF_VAR . '/ddos.temp';
    
    if (!file_exists($temp_block_file)) {
        return 0;
    }
    
    $lines = file($temp_block_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $updated = array();
    $cleared = 0;
    $now = time();
    
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        
        if (count($parts) >= 4) {
            $ip = $parts[0];
            $timestamp = intval($parts[2]);
            $duration = intval($parts[3]);
            
            if ($now - $timestamp < $duration) {
                $updated[] = $line;
            } else {
                $cleared++;
                
                // Remove from firewall
                iptables_remove_deny($ip);
            }
        }
    }
    
    file_put_contents($temp_block_file, implode("\n", $updated) . "\n");
    
    return $cleared;
}

/**
 * Get DDoS statistics
 * 
 * @return array Statistics
 */
function ddos_get_stats() {
    $temp_block_file = CSF_VAR . '/ddos.temp';
    
    $stats = array(
        'temp_blocks' => 0,
        'syn_floods' => 0,
        'http_floods' => 0,
        'connection_limits' => 0,
        'last_updated' => time(),
    );
    
    if (file_exists($temp_block_file)) {
        $lines = file($temp_block_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        foreach ($lines as $line) {
            $stats['temp_blocks']++;
            
            if (strpos($line, 'SYN Flood') !== false) {
                $stats['syn_floods']++;
            } elseif (strpos($line, 'HTTP Flood') !== false) {
                $stats['http_floods']++;
            } elseif (strpos($line, 'Connection Limit') !== false) {
                $stats['connection_limits']++;
            }
        }
    }
    
    return $stats;
}
