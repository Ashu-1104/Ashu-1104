<?php
/**
 * CSF Port Scan Detection Module
 * Translates Perl CSF port scanning logic to PHP
 */

define('PSCAN_LOG', CSF_LOG . '/psacct.log');

/**
 * Initialize port scan detection
 * 
 * @return bool
 */
function pscan_init() {
    $config = $GLOBALS['csf_config'];
    
    if (!isset($config['PS_ENABLE']) || !$config['PS_ENABLE']) {
        return false;
    }
    
    // Ensure port scan log exists
    if (!file_exists(PSCAN_LOG)) {
        touch(PSCAN_LOG);
        chmod(PSCAN_LOG, 0600);
    }
    
    return true;
}

/**
 * Detect port scans from logs
 * 
 * @param int $hours Hours to lookback
 * @return array Detected port scans
 */
function pscan_detect($hours = 1) {
    $config = $GLOBALS['csf_config'];
    
    if (!isset($config['PS_ENABLE']) || !$config['PS_ENABLE']) {
        return array();
    }
    
    $threshold = isset($config['PS_INTERVAL']) ? intval($config['PS_INTERVAL']) : 300;
    $port_limit = isset($config['PS_LIMIT']) ? intval($config['PS_LIMIT']) : 10;
    
    $detected = array();
    $ip_ports = array();
    
    // Check system logs for port scan activity
    $logs = array(
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/messages',
    );
    
    $cutoff_time = time() - ($hours * 3600);
    
    foreach ($logs as $log) {
        if (!file_exists($log) || !is_readable($log)) {
            continue;
        }
        
        $lines = file_tail($log, 10000);
        
        foreach ($lines as $line) {
            // Look for connection attempts
            if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*port (\d+)/', $line, $matches)) {
                $ip = $matches[1];
                $port = intval($matches[2]);
                
                if (!isset($ip_ports[$ip])) {
                    $ip_ports[$ip] = array();
                }
                
                $ip_ports[$ip][] = $port;
            }
        }
    }
    
    // Analyze for scan patterns
    foreach ($ip_ports as $ip => $ports) {
        $unique_ports = count(array_unique($ports));
        
        if ($unique_ports >= $port_limit) {
            $detected[$ip] = array(
                'ports' => $unique_ports,
                'ports_list' => array_unique($ports),
                'timestamp' => time(),
            );
        }
    }
    
    return $detected;
}

/**
 * Log port scan event
 * 
 * @param string $ip Source IP
 * @param array $ports Ports scanned
 * @param string $reason Scan reason
 * @return bool
 */
function pscan_log($ip, $ports, $reason = '') {
    $entry = array(
        'timestamp' => time(),
        'ip' => $ip,
        'ports' => $ports,
        'reason' => $reason,
    );
    
    $log_entry = date('Y-m-d H:i:s') . '|' . $ip . '|' . implode(',', $ports) . '|' . $reason . "\n";
    
    return file_put_contents(PSCAN_LOG, $log_entry, FILE_APPEND) !== false;
}

/**
 * Block port scanner IP
 * 
 * @param string $ip IP address to block
 * @param string $reason Block reason
 * @return bool
 */
function pscan_block_ip($ip, $reason = 'Port scan detected') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    
    // Add to blocklist
    $result = iptables_add_deny($ip, $reason);
    
    // Log the block
    pscan_log($ip, array(), $reason);
    
    // Notify
    csf_log('Port scanner blocked: ' . $ip . ' - ' . $reason, 'WARN', 'PSCAN');
    
    return $result;
}

/**
 * Get recent port scans
 * 
 * @param int $limit Number of entries
 * @return array Port scan records
 */
function pscan_get_recent($limit = 50) {
    if (!file_exists(PSCAN_LOG)) {
        return array();
    }
    
    $lines = file_tail(PSCAN_LOG, $limit);
    $scans = array();
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        if (empty($line)) {
            continue;
        }
        
        $parts = explode('|', $line);
        
        if (count($parts) >= 3) {
            $scans[] = array(
                'timestamp' => strtotime($parts[0]),
                'ip' => $parts[1],
                'ports' => explode(',', $parts[2]),
                'reason' => isset($parts[3]) ? $parts[3] : '',
            );
        }
    }
    
    return array_reverse($scans);
}

/**
 * Get tail of file (last N lines)
 * 
 * @param string $filename File path
 * @param int $lines Number of lines
 * @return array Last lines
 */
function file_tail($filename, $lines = 100) {
    $file = fopen($filename, 'r');
    
    if (!$file) {
        return array();
    }
    
    fseek($file, 0, SEEK_END);
    $size = ftell($file);
    
    $buffer_size = min(8192, $size);
    $position = $size;
    $tail = array();
    
    while ($position >= 0) {
        $seek_size = min($buffer_size, $position);
        $position -= $seek_size;
        
        fseek($file, $position);
        $chunk = fread($file, $seek_size);
        
        $tail = explode("\n", $chunk) + $tail;
        
        if (count($tail) >= $lines + 1) {
            break;
        }
    }
    
    fclose($file);
    
    return array_slice($tail, -$lines);
}

/**
 * Analyze port scan patterns
 * 
 * @return array Analysis results
 */
function pscan_analyze_patterns() {
    $patterns = array(
        'sequential' => 0,
        'random' => 0,
        'targeted' => 0,
    );
    
    $scans = pscan_get_recent(100);
    
    foreach ($scans as $scan) {
        $ports = $scan['ports'];
        
        if (empty($ports)) {
            continue;
        }
        
        sort($ports);
        
        // Check if sequential
        $is_sequential = true;
        for ($i = 1; $i < count($ports); $i++) {
            if ($ports[$i] - $ports[$i - 1] !== 1) {
                $is_sequential = false;
                break;
            }
        }
        
        if ($is_sequential) {
            $patterns['sequential']++;
        } elseif (count($ports) > 100) {
            // Large port range = comprehensive scan
            $patterns['targeted']++;
        } else {
            $patterns['random']++;
        }
    }
    
    return $patterns;
}

/**
 * Clear old port scan logs
 * 
 * @param int $days Older than N days
 * @return int Removed entries
 */
function pscan_cleanup($days = 30) {
    if (!file_exists(PSCAN_LOG)) {
        return 0;
    }
    
    $cutoff = time() - ($days * 86400);
    $lines = file(PSCAN_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $updated = array();
    $removed = 0;
    
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        
        if (!empty($parts[0])) {
            $timestamp = strtotime($parts[0]);
            
            if ($timestamp > $cutoff) {
                $updated[] = $line;
            } else {
                $removed++;
            }
        }
    }
    
    file_put_contents(PSCAN_LOG, implode("\n", $updated) . "\n");
    
    csf_log('Cleaned ' . $removed . ' old port scan entries', 'INFO', 'PSCAN');
    
    return $removed;
}
