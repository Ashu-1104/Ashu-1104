<?php
/**
 * LFD (Login Failure Daemon) Interface
 * PHP bridge to C-based LFD daemon for login failure detection
 * 
 * LFD itself remains in C for performance
 * This module provides PHP interface to communicate with LFD
 */

define('LFD_PATH', '/usr/local/lfd');
define('LFD_BIN', LFD_PATH . '/bin/lfd');
define('LFD_VAR', '/var/lib/lfd');
define('LFD_LOG', '/var/log/lfd');
define('LFD_SOCK', '/var/run/lfd.sock');

/**
 * Check if LFD daemon is running
 * 
 * @return bool
 */
function lfd_is_running() {
    $output = array();
    $return_var = 0;
    
    exec('ps aux | grep "[l]fd" | wc -l', $output, $return_var);
    
    return intval($output[0]) > 0;
}

/**
 * Start LFD daemon
 * 
 * @return bool
 */
function lfd_start() {
    if (!file_exists(LFD_BIN)) {
        csf_log('LFD binary not found at: ' . LFD_BIN, 'ERROR', 'LFD');
        return false;
    }
    
    // Start LFD daemon
    $output = array();
    $return_var = 0;
    
    exec(LFD_BIN . ' 2>&1', $output, $return_var);
    
    if ($return_var !== 0) {
        csf_log('Failed to start LFD: ' . implode("\n", $output), 'ERROR', 'LFD');
        return false;
    }
    
    csf_log('LFD daemon started', 'INFO', 'LFD');
    return true;
}

/**
 * Stop LFD daemon
 * 
 * @return bool
 */
function lfd_stop() {
    $output = array();
    $return_var = 0;
    
    exec('killall lfd 2>/dev/null', $output, $return_var);
    
    // Give it a moment to shut down
    sleep(1);
    
    if (lfd_is_running()) {
        csf_log('Failed to stop LFD gracefully, forcing shutdown', 'WARN', 'LFD');
        exec('killall -9 lfd 2>/dev/null');
    }
    
    csf_log('LFD daemon stopped', 'INFO', 'LFD');
    return true;
}

/**
 * Restart LFD daemon
 * 
 * @return bool
 */
function lfd_restart() {
    if (!lfd_stop()) {
        return false;
    }
    
    sleep(2);
    
    return lfd_start();
}

/**
 * Get LFD status
 * 
 * @return array Status information
 */
function lfd_get_status() {
    $status = array(
        'running' => lfd_is_running(),
        'pid' => null,
        'memory' => null,
        'uptime' => null,
        'version' => null,
    );
    
    // Get LFD process info
    $output = array();
    exec('ps aux | grep "[l]fd"', $output);
    
    if (!empty($output)) {
        $parts = preg_split('/\s+/', $output[0]);
        
        if (isset($parts[1])) {
            $status['pid'] = intval($parts[1]);
        }
        
        if (isset($parts[5])) {
            $status['memory'] = intval($parts[5]);
        }
    }
    
    return $status;
}

/**
 * Get LFD log entries
 * 
 * @param int $limit Number of entries to return
 * @return array Log entries
 */
function lfd_get_logs($limit = 100) {
    $log_file = LFD_LOG . '/lfd.log';
    
    if (!file_exists($log_file)) {
        return array();
    }
    
    $lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $lines = array_reverse($lines);
    $logs = array();
    
    foreach (array_slice($lines, 0, $limit) as $line) {
        $logs[] = $line;
    }
    
    return $logs;
}

/**
 * Get failed login attempts
 * 
 * @return array Failed login data
 */
function lfd_get_failed_logins() {
    $failed_file = LFD_VAR . '/failed.log';
    
    if (!file_exists($failed_file)) {
        return array();
    }
    
    $lines = file($failed_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $attempts = array();
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        if (empty($line)) {
            continue;
        }
        
        $parts = explode('|', $line);
        
        if (count($parts) < 4) {
            continue;
        }
        
        $attempts[] = array(
            'ip' => $parts[0],
            'service' => $parts[1],
            'user' => $parts[2],
            'count' => intval($parts[3]),
            'timestamp' => isset($parts[4]) ? intval($parts[4]) : 0,
        );
    }
    
    return $attempts;
}

/**
 * Get permanently blocked IPs by LFD
 * 
 * @return array Blocked IPs
 */
function lfd_get_permanent_blocks() {
    $temp_dir = '/var/lib/lfd';
    
    if (!is_dir($temp_dir)) {
        return array();
    }
    
    $blocks = array();
    $files = scandir($temp_dir);
    
    foreach ($files as $file) {
        if (strpos($file, '.block') === false) {
            continue;
        }
        
        $content = file_get_contents($temp_dir . '/' . $file);
        
        if ($content) {
            $parts = explode('|', trim($content));
            
            if (count($parts) >= 2) {
                $blocks[] = array(
                    'ip' => $parts[0],
                    'reason' => isset($parts[1]) ? $parts[1] : 'LFD Block',
                    'time' => filemtime($temp_dir . '/' . $file),
                );
            }
        }
    }
    
    return $blocks;
}

/**
 * Send command to LFD via socket
 * 
 * @param string $command Command to send
 * @return string|bool Response or false on error
 */
function lfd_send_command($command) {
    if (!function_exists('socket_create')) {
        csf_log('Socket extension not available', 'ERROR', 'LFD');
        return false;
    }
    
    $socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
    
    if (!$socket) {
        csf_log('Failed to create socket', 'ERROR', 'LFD');
        return false;
    }
    
    $result = @socket_connect($socket, LFD_SOCK);
    
    if (!$result) {
        socket_close($socket);
        csf_log('Failed to connect to LFD socket', 'ERROR', 'LFD');
        return false;
    }
    
    // Send command
    socket_write($socket, $command . "\n");
    
    // Read response
    $response = '';
    while ($chunk = socket_read($socket, 2048)) {
        $response .= $chunk;
    }
    
    socket_close($socket);
    
    return trim($response);
}

/**
 * Reload LFD configuration
 * 
 * @return bool
 */
function lfd_reload_config() {
    return lfd_send_command('reload') !== false;
}

/**
 * Clear LFD logs
 * 
 * @return bool
 */
function lfd_clear_logs() {
    $log_file = LFD_LOG . '/lfd.log';
    
    if (file_exists($log_file)) {
        return file_put_contents($log_file, '') !== false;
    }
    
    return true;
}

/**
 * Get LFD configuration
 * 
 * @return array Configuration
 */
function lfd_get_config() {
    $config_file = '/etc/lfd/lfd.conf';
    
    if (!file_exists($config_file)) {
        return array();
    }
    
    $config = array();
    $lines = file($config_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        if (empty($line) || substr($line, 0, 1) === '#') {
            continue;
        }
        
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $config[trim($key)] = trim($value, ' "\'');
        }
    }
    
    return $config;
}

/**
 * Monitor LFD health
 * 
 * @return array Health information
 */
function lfd_monitor_health() {
    $health = array(
        'running' => lfd_is_running(),
        'errors' => array(),
        'warnings' => array(),
        'info' => array(),
    );
    
    if (!$health['running']) {
        $health['errors'][] = 'LFD daemon is not running';
        return $health;
    }
    
    // Check log file
    $log_file = LFD_LOG . '/lfd.log';
    if (!is_readable($log_file)) {
        $health['warnings'][] = 'LFD log file is not readable';
    }
    
    // Check failed logins file
    $failed_file = LFD_VAR . '/failed.log';
    if (file_exists($failed_file) && filesize($failed_file) > 1000000) {
        $health['warnings'][] = 'LFD failed logins log is large, consider cleaning';
    }
    
    // Get process status
    $status = lfd_get_status();
    $health['info'][] = 'LFD PID: ' . ($status['pid'] ?: 'unknown');
    $health['info'][] = 'Memory Usage: ' . ($status['memory'] ? $status['memory'] . ' KB' : 'unknown');
    
    return $health;
}
