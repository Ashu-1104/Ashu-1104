<?php
/**
 * ConfigServer Firewall (CSF) - Logging System
 * 
 * Handles all logging operations for CSF events, errors, and security events.
 * Supports rotating log files and configurable log levels.
 * 
 * @package     CSF
 * @subpackage  Logging
 * @author      Webuzo CSF Fork
 * @version     1.0.0
 */

class CSF_Logger {
    /**
     * Log levels
     */
    const LEVEL_CRITICAL = 0;
    const LEVEL_ERROR = 1;
    const LEVEL_WARNING = 2;
    const LEVEL_NOTICE = 3;
    const LEVEL_INFO = 4;
    const LEVEL_DEBUG = 5;
    
    /**
     * Log directory
     * @var string
     */
    private $log_dir;
    
    /**
     * Current log level
     * @var int
     */
    private $log_level = self::LEVEL_NOTICE;
    
    /**
     * Log file size limit (bytes) before rotation
     * @var int
     */
    private $log_size_limit = 10485760; // 10MB
    
    /**
     * Constructor
     * 
     * @param string $log_dir Log directory path
     * @param int $log_level Initial log level
     * @return void
     */
    public function __construct($log_dir, $log_level = self::LEVEL_NOTICE) {
        $this->log_dir = rtrim($log_dir, '/');
        $this->log_level = $log_level;
        
        if (!is_dir($this->log_dir)) {
            @mkdir($this->log_dir, 0755, true);
        }
    }
    
    /**
     * Set current log level
     * 
     * @param int $level Log level constant
     * @return void
     */
    public function set_level($level) {
        if ($level >= self::LEVEL_CRITICAL && $level <= self::LEVEL_DEBUG) {
            $this->log_level = $level;
        }
    }
    
    /**
     * Get current log level
     * 
     * @return int Current log level
     */
    public function get_level() {
        return $this->log_level;
    }
    
    /**
     * Log a message
     * 
     * @param string $message Message to log
     * @param int $level Log level
     * @param string $category Log category (default: 'general')
     * @return bool True if logged successfully
     */
    public function log($message, $level = self::LEVEL_INFO, $category = 'general') {
        // Check if message should be logged based on level
        if ($level > $this->log_level) {
            return false;
        }
        
        // Sanitize inputs
        $message = $this->_sanitize_message($message);
        $category = preg_replace('/[^a-z0-9_-]/i', '', $category);
        
        if (empty($category)) {
            $category = 'general';
        }
        
        $level_name = $this->_get_level_name($level);
        $timestamp = date('Y-m-d H:i:s');
        $log_entry = "[{$timestamp}] [{$level_name}] {$message}";
        
        $log_file = $this->log_dir . '/' . $category . '.log';
        
        return $this->_write_log($log_file, $log_entry);
    }
    
    /**
     * Log security event (attacks, blocks, etc.)
     * 
     * @param string $event_type Type of security event
     * @param string $event_data Event details/data
     * @param array $metadata Additional metadata
     * @return bool True if logged successfully
     */
    public function log_security_event($event_type, $event_data, $metadata = array()) {
        $event_type = preg_replace('/[^a-z0-9_-]/i', '', $event_type);
        
        $log_entry = array(
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => $event_type,
            'data' => $event_data,
            'metadata' => $metadata
        );
        
        $security_log = $this->log_dir . '/security.log';
        $json_entry = json_encode($log_entry) . "\n";
        
        return $this->_write_log($security_log, $json_entry);
    }
    
    /**
     * Log IP block event
     * 
     * @param string $ip IP address being blocked
     * @param string $reason Reason for block
     * @param string $source Source of block (manual, brute-force, etc.)
     * @return bool True if logged successfully
     */
    public function log_block($ip, $reason, $source = 'manual') {
        if (!$this->_validate_ip($ip)) {
            return false;
        }
        
        return $this->log_security_event('IP_BLOCKED', $ip, array(
            'reason' => $reason,
            'source' => $source
        ));
    }
    
    /**
     * Log IP unblock event
     * 
     * @param string $ip IP address being unblocked
     * @param string $reason Reason for unblock
     * @return bool True if logged successfully
     */
    public function log_unblock($ip, $reason = '') {
        if (!$this->_validate_ip($ip)) {
            return false;
        }
        
        return $this->log_security_event('IP_UNBLOCKED', $ip, array(
            'reason' => $reason
        ));
    }
    
    /**
     * Write log entry to file with rotation
     * 
     * @param string $log_file Path to log file
     * @param string $entry Log entry to write
     * @return bool True if successful
     */
    private function _write_log($log_file, $entry) {
        $fp = @fopen($log_file, 'a');
        if ($fp === false) {
            return false;
        }
        
        // Try to lock the file for exclusive write
        $locked = flock($fp, LOCK_EX | LOCK_NB);
        
        if (!$locked) {
            // If can't get exclusive lock, try shared lock
            flock($fp, LOCK_SH);
        }
        
        $result = fwrite($fp, $entry . "\n");
        
        if ($locked) {
            flock($fp, LOCK_UN);
        } else {
            flock($fp, LOCK_UN);
        }
        
        fclose($fp);
        
        // Check file size and rotate if necessary
        if (file_exists($log_file) && filesize($log_file) > $this->log_size_limit) {
            $this->_rotate_log($log_file);
        }
        
        return $result !== false && $result > 0;
    }
    
    /**
     * Rotate log file
     * 
     * @param string $log_file Path to log file to rotate
     * @return bool True if successful
     */
    private function _rotate_log($log_file) {
        $date = date('Y-m-d-His');
        $rotated_file = $log_file . '.' . $date . '.gz';
        
        // Compress and move
        if (!@system("gzip -c {$log_file} > {$rotated_file}", $return_var)) {
            // Fallback: just move without compression
            $rotated_file = $log_file . '.' . $date;
            if (!@rename($log_file, $rotated_file)) {
                return false;
            }
        } else {
            @unlink($log_file);
        }
        
        // Clean old rotated logs (keep last 10)
        $this->_cleanup_old_logs($log_file);
        
        return true;
    }
    
    /**
     * Cleanup old rotated log files
     * 
     * @param string $log_file Base log file path
     * @return void
     */
    private function _cleanup_old_logs($log_file) {
        $log_pattern = $log_file . '.*.gz';
        $files = @glob($log_pattern);
        
        if (!$files || count($files) <= 10) {
            return;
        }
        
        // Sort by modification time, oldest first
        usort($files, function($a, $b) {
            return filemtime($a) - filemtime($b);
        });
        
        // Remove oldest files, keeping last 10
        $to_remove = count($files) - 10;
        for ($i = 0; $i < $to_remove; $i++) {
            @unlink($files[$i]);
        }
    }
    
    /**
     * Get log level name
     * 
     * @param int $level Log level constant
     * @return string Level name
     */
    private function _get_level_name($level) {
        $levels = array(
            self::LEVEL_CRITICAL => 'CRITICAL',
            self::LEVEL_ERROR => 'ERROR',
            self::LEVEL_WARNING => 'WARNING',
            self::LEVEL_NOTICE => 'NOTICE',
            self::LEVEL_INFO => 'INFO',
            self::LEVEL_DEBUG => 'DEBUG'
        );
        
        return isset($levels[$level]) ? $levels[$level] : 'UNKNOWN';
    }
    
    /**
     * Sanitize log message
     * 
     * @param string $message Message to sanitize
     * @return string Sanitized message
     */
    private function _sanitize_message($message) {
        $message = (string)$message;
        // Remove null bytes and control characters
        $message = str_replace("\0", '', $message);
        $message = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $message);
        return trim($message);
    }
    
    /**
     * Validate IPv4 or IPv6 address
     * 
     * @param string $ip IP address to validate
     * @return bool True if valid IP
     */
    private function _validate_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * Get all logs for a category
     * 
     * @param string $category Log category
     * @param int $lines Number of lines to return (0 = all)
     * @return array Log entries
     */
    public function get_logs($category = 'general', $lines = 100) {
        $category = preg_replace('/[^a-z0-9_-]/i', '', $category);
        $log_file = $this->log_dir . '/' . $category . '.log';
        
        if (!file_exists($log_file)) {
            return array();
        }
        
        $all_lines = @file($log_file);
        if ($all_lines === false) {
            return array();
        }
        
        if ($lines > 0 && count($all_lines) > $lines) {
            $all_lines = array_slice($all_lines, -$lines);
        }
        
        return array_map('trim', $all_lines);
    }
}
?>
