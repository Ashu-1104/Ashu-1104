<?php
/**
 * CSF Logging Functions
 * Handles all logging operations for CSF
 * Uses file-based logging with rotation support
 */

/**
 * Initialize logging directory
 * 
 * @param string $log_dir Path to logging directory
 * @return bool True on success
 */
function csf_log_init($log_dir = '/var/log/csf') {
    if (!is_dir($log_dir)) {
        if (!@mkdir($log_dir, 0755, true)) {
            error_log("CSF: Failed to create log directory: $log_dir");
            return false;
        }
    }

    if (!is_writable($log_dir)) {
        error_log("CSF: Log directory not writable: $log_dir");
        return false;
    }

    return true;
}

/**
 * Log message to file
 * 
 * @param string $message Message to log
 * @param string $level Log level (info, warning, error, debug)
 * @param string $log_file Path to log file
 * @return bool True on success
 */
function csf_log($message, $level = 'info', $log_file = '/var/log/csf/csf.log') {
    if (empty($message)) {
        return false;
    }

    // Validate log level
    $valid_levels = array('info', 'warning', 'error', 'debug', 'alert');
    if (!in_array(strtolower($level), $valid_levels)) {
        $level = 'info';
    }

    $level = strtoupper($level);

    // Prepare log message
    $timestamp = date('Y-m-d H:i:s');
    $pid = getmypid();
    $log_message = "[$timestamp] [$level] [PID:$pid] $message\n";

    // Create log directory if needed
    $log_dir = dirname($log_file);
    if (!is_dir($log_dir)) {
        @mkdir($log_dir, 0755, true);
    }

    // Write to log file with locking
    $fp = @fopen($log_file, 'a');
    if ($fp === false) {
        error_log("CSF: Failed to open log file: $log_file");
        return false;
    }

    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return false;
    }

    $written = fwrite($fp, $log_message);
    flock($fp, LOCK_UN);
    fclose($fp);

    if ($written === false) {
        error_log("CSF: Failed to write to log file: $log_file");
        return false;
    }

    // Check if log rotation is needed
    csf_check_log_rotation($log_file);

    return true;
}

/**
 * Check and perform log rotation if needed
 * 
 * @param string $log_file Path to log file
 * @param int $max_size Maximum log file size in bytes (default 10MB)
 * @param int $max_files Maximum number of rotated files (default 5)
 * @return bool True if rotation performed or not needed
 */
function csf_check_log_rotation($log_file, $max_size = 10485760, $max_files = 5) {
    if (!file_exists($log_file)) {
        return true;
    }

    $file_size = filesize($log_file);

    // Check if rotation is needed
    if ($file_size < $max_size) {
        return true;
    }

    // Rotate logs
    for ($i = $max_files - 1; $i >= 1; $i--) {
        $old_file = $log_file . '.' . $i;
        $new_file = $log_file . '.' . ($i + 1);

        if (file_exists($old_file)) {
            @rename($old_file, $new_file);
        }
    }

    // Rotate current log file
    $rotated_file = $log_file . '.1';
    if (!@rename($log_file, $rotated_file)) {
        error_log("CSF: Failed to rotate log file: $log_file");
        return false;
    }

    // Compress rotated log if gzip is available
    if (function_exists('gzopen') && file_exists($rotated_file)) {
        csf_compress_log_file($rotated_file);
    }

    return true;
}

/**
 * Compress log file using gzip
 * 
 * @param string $log_file Path to log file
 * @return bool True on success
 */
function csf_compress_log_file($log_file) {
    if (!file_exists($log_file) || !is_readable($log_file)) {
        return false;
    }

    $gz_file = $log_file . '.gz';

    $fp_in = @fopen($log_file, 'rb');
    if ($fp_in === false) {
        return false;
    }

    $fp_out = @gzopen($gz_file, 'wb');
    if ($fp_out === false) {
        fclose($fp_in);
        return false;
    }

    while (!feof($fp_in)) {
        $data = fread($fp_in, 65536);
        if ($data === false) {
            break;
        }
        gzwrite($fp_out, $data);
    }

    fclose($fp_in);
    gzclose($fp_out);

    // Remove original file if compression successful
    if (file_exists($gz_file)) {
        @unlink($log_file);
        return true;
    }

    return false;
}

/**
 * Get log file contents with optional filtering
 * 
 * @param string $log_file Path to log file
 * @param string $filter Optional filter string to match lines
 * @param int $limit Maximum number of lines to return
 * @param int $offset Number of lines to skip from end
 * @return array Array of log lines
 */
function csf_get_log_lines($log_file, $filter = '', $limit = 100, $offset = 0) {
    if (!file_exists($log_file) || !is_readable($log_file)) {
        return array();
    }

    $lines = array();
    $fp = @fopen($log_file, 'r');

    if ($fp === false) {
        return array();
    }

    // Read all lines
    $all_lines = array();
    while (($line = fgets($fp)) !== false) {
        $line = rtrim($line, "\n\r");

        // Apply filter if provided
        if (!empty($filter)) {
            if (stripos($line, $filter) === false) {
                continue;
            }
        }

        $all_lines[] = $line;
    }

    fclose($fp);

    // Get lines from end (most recent first)
    $all_lines = array_reverse($all_lines);
    $lines = array_slice($all_lines, $offset, $limit);

    return $lines;
}

/**
 * Log dropped packet
 * 
 * @param string $ip Source IP address
 * @param string $port Destination port
 * @param string $protocol Protocol (TCP/UDP)
 * @param string $reason Reason for drop
 * @return bool True on success
 */
function csf_log_dropped_packet($ip, $port, $protocol = 'TCP', $reason = 'Unknown') {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    $message = "DROP $protocol from $ip to port $port - Reason: $reason";
    return csf_log($message, 'alert', '/var/log/csf/csf.blocked.log');
}

/**
 * Log connection attempt
 * 
 * @param string $ip Source IP address
 * @param int $port Destination port
 * @param string $service Service name (SSH, FTP, etc)
 * @param string $username Username (if available)
 * @return bool True on success
 */
function csf_log_connection_attempt($ip, $port, $service = 'Unknown', $username = '') {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    $message = "Connection attempt from $ip:$port via $service";
    if (!empty($username)) {
        $message .= " (User: " . substr($username, 0, 32) . ")";
    }

    return csf_log($message, 'info', '/var/log/csf/csf.access.log');
}

/**
 * Log firewall rule change
 * 
 * @param string $action Action performed (ADD/REMOVE/MODIFY)
 * @param string $rule_type Type of rule (IP, PORT, etc)
 * @param string $rule_value Rule value
 * @param string $user User performing the action
 * @return bool True on success
 */
function csf_log_rule_change($action, $rule_type, $rule_value, $user = 'system') {
    $action = strtoupper($action);
    $rule_type = strtoupper($rule_type);

    // Sanitize user name
    $user = preg_replace('/[^a-zA-Z0-9._-]/', '', $user);
    if (empty($user)) {
        $user = 'unknown';
    }

    $message = "[$action] $rule_type rule: $rule_value (User: $user)";
    return csf_log($message, 'info', '/var/log/csf/csf.system.log');
}

/**
 * Get log statistics
 * 
 * @param string $log_file Path to log file
 * @return array Statistics array
 */
function csf_get_log_stats($log_file) {
    if (!file_exists($log_file) || !is_readable($log_file)) {
        return array(
            'total_lines' => 0,
            'file_size' => 0,
            'last_modified' => 0,
        );
    }

    $lines = file($log_file, FILE_IGNORE_NEW_LINES);
    $file_size = filesize($log_file);
    $last_modified = filemtime($log_file);

    return array(
        'total_lines' => count($lines),
        'file_size' => $file_size,
        'file_size_human' => csf_format_bytes($file_size),
        'last_modified' => $last_modified,
        'last_modified_human' => date('Y-m-d H:i:s', $last_modified),
    );
}

/**
 * Format bytes to human readable format
 * 
 * @param int $bytes Number of bytes
 * @return string Formatted size
 */
function csf_format_bytes($bytes) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));

    return round($bytes, 2) . ' ' . $units[$pow];
}

?>
