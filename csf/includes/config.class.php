<?php
/**
 * ConfigServer Firewall (CSF) - Configuration Management
 * 
 * Handles all configuration file reading/writing, validation, and caching.
 * Follows file-based config system with JSON/text format for Webuzo integration.
 * 
 * @package     CSF
 * @subpackage  Config
 * @author      Webuzo CSF Fork
 * @version     1.0.0
 */

class CSF_Config {
    /**
     * Configuration directory path
     * @var string
     */
    private $config_dir = '/etc/csf';
    
    /**
     * Library directory path (data storage)
     * @var string
     */
    private $lib_dir = '/var/lib/csf';
    
    /**
     * Configuration cache (in-memory)
     * @var array
     */
    private $config_cache = array();
    
    /**
     * Cache status
     * @var bool
     */
    private $cache_loaded = false;
    
    /**
     * Main configuration file
     * @var string
     */
    private $main_config_file = 'csf.conf.json';
    
    /**
     * Constructor - Initialize config paths
     * 
     * @param string $config_dir Optional custom config directory
     * @param string $lib_dir Optional custom library directory
     * @return void
     */
    public function __construct($config_dir = null, $lib_dir = null) {
        if ($config_dir !== null && is_dir($config_dir)) {
            $this->config_dir = rtrim($config_dir, '/');
        }
        
        if ($lib_dir !== null && is_dir($lib_dir)) {
            $this->lib_dir = rtrim($lib_dir, '/');
        }
        
        $this->_initialize_directories();
    }
    
    /**
     * Initialize required directories
     * 
     * @return void
     */
    private function _initialize_directories() {
        $dirs = array(
            $this->config_dir,
            $this->lib_dir,
            $this->lib_dir . '/rules',
            $this->lib_dir . '/data',
            $this->lib_dir . '/logs',
            $this->lib_dir . '/cmd'
        );
        
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                @mkdir($dir, 0755, true);
            }
        }
    }
    
    /**
     * Load all configuration from file
     * 
     * @return bool True if successful, false on error
     */
    public function load_config() {
        if ($this->cache_loaded) {
            return true;
        }
        
        $config_file = $this->config_dir . '/' . $this->main_config_file;
        
        if (!file_exists($config_file)) {
            $this->config_cache = $this->_get_default_config();
            return true;
        }
        
        $content = @file_get_contents($config_file);
        if ($content === false) {
            trigger_error("Failed to read config file: {$config_file}", E_USER_WARNING);
            return false;
        }
        
        $config = @json_decode($content, true);
        if ($config === null) {
            trigger_error("Invalid JSON in config file: {$config_file}", E_USER_WARNING);
            return false;
        }
        
        $this->config_cache = $config;
        $this->cache_loaded = true;
        
        return true;
    }
    
    /**
     * Get configuration value
     * 
     * @param string $key Configuration key (dot-notation for nested: "section.key")
     * @param mixed $default Default value if key not found
     * @return mixed Configuration value or default
     */
    public function get($key, $default = null) {
        if (!$this->cache_loaded) {
            $this->load_config();
        }
        
        if (strpos($key, '.') === false) {
            return isset($this->config_cache[$key]) ? $this->config_cache[$key] : $default;
        }
        
        $parts = explode('.', $key);
        $value = $this->config_cache;
        
        foreach ($parts as $part) {
            if (!is_array($value) || !isset($value[$part])) {
                return $default;
            }
            $value = $value[$part];
        }
        
        return $value;
    }
    
    /**
     * Set configuration value (in-memory only, not persisted)
     * 
     * @param string $key Configuration key (dot-notation supported)
     * @param mixed $value Value to set
     * @return bool True if successful
     */
    public function set($key, $value) {
        if (!$this->cache_loaded) {
            $this->load_config();
        }
        
        if (strpos($key, '.') === false) {
            $this->config_cache[$key] = $value;
            return true;
        }
        
        $parts = explode('.', $key);
        $last_key = array_pop($parts);
        $current = &$this->config_cache;
        
        foreach ($parts as $part) {
            if (!isset($current[$part])) {
                $current[$part] = array();
            }
            $current = &$current[$part];
        }
        
        $current[$last_key] = $value;
        return true;
    }
    
    /**
     * Save configuration to file (atomic write with lock)
     * 
     * @return bool True if successful, false on error
     */
    public function save_config() {
        if (!$this->cache_loaded) {
            return false;
        }
        
        $config_file = $this->config_dir . '/' . $this->main_config_file;
        $backup_file = $config_file . '.bak';
        
        // Create backup
        if (file_exists($config_file)) {
            if (!@copy($config_file, $backup_file)) {
                trigger_error("Failed to create config backup: {$backup_file}", E_USER_WARNING);
                return false;
            }
        }
        
        // Write to temporary file first
        $temp_file = $config_file . '.tmp';
        $json_content = json_encode($this->config_cache, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        
        if ($json_content === false) {
            trigger_error("Failed to encode config to JSON", E_USER_WARNING);
            return false;
        }
        
        $fp = @fopen($temp_file, 'w');
        if ($fp === false) {
            trigger_error("Failed to open config temp file: {$temp_file}", E_USER_WARNING);
            return false;
        }
        
        // Lock file for exclusive write
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            @unlink($temp_file);
            trigger_error("Failed to lock config file: {$config_file}", E_USER_WARNING);
            return false;
        }
        
        $bytes_written = fwrite($fp, $json_content);
        flock($fp, LOCK_UN);
        fclose($fp);
        
        if ($bytes_written === false || $bytes_written === 0) {
            @unlink($temp_file);
            trigger_error("Failed to write config to temp file: {$temp_file}", E_USER_WARNING);
            return false;
        }
        
        // Atomic rename
        if (!@rename($temp_file, $config_file)) {
            @unlink($temp_file);
            trigger_error("Failed to rename config temp file: {$config_file}", E_USER_WARNING);
            return false;
        }
        
        @chmod($config_file, 0640);
        return true;
    }
    
    /**
     * Get default configuration array
     * 
     * @return array Default CSF configuration
     */
    private function _get_default_config() {
        return array(
            'enabled' => 1,
            'testing' => 0,
            'lfd_enabled' => 1,
            'log_level' => 3,
            
            'firewall' => array(
                'tcp_in' => '20,21,22,25,53,80,110,143,443,465,587,993,995,3306,8080,8443',
                'tcp_out' => '20,21,22,25,53,80,110,143,443,465,587,993,995,3306',
                'udp_in' => '20,21,53,123,161',
                'udp_out' => '20,21,53,123,161',
            ),
            
            'security' => array(
                'syn_flood_protection' => 1,
                'port_scan_detection' => 1,
                'ddos_protection' => 1,
                'brute_force_protection' => 1,
            ),
            
            'blocklists' => array(
                'enabled' => 1,
                'update_interval' => 3600,
                'auto_remove' => 1,
                'remove_after' => 604800, // 7 days
            ),
            
            'geoip' => array(
                'enabled' => 0,
                'blocked_countries' => array(),
                'allowed_countries' => array(),
            ),
            
            'lfd' => array(
                'enabled' => 1,
                'check_interval' => 5,
                'email_alert' => 0,
                'email' => '',
            ),
        );
    }
    
    /**
     * Get configuration directory path
     * 
     * @return string Path to configuration directory
     */
    public function get_config_dir() {
        return $this->config_dir;
    }
    
    /**
     * Get library directory path
     * 
     * @return string Path to library directory
     */
    public function get_lib_dir() {
        return $this->lib_dir;
    }
    
    /**
     * Get full path to a file in config directory
     * 
     * @param string $filename Filename in config directory
     * @return string Full path to file
     */
    public function get_config_path($filename) {
        return $this->config_dir . '/' . basename($filename);
    }
    
    /**
     * Get full path to a file in library directory
     * 
     * @param string $filename Filename in library directory
     * @return string Full path to file
     */
    public function get_lib_path($filename) {
        return $this->lib_dir . '/' . basename($filename);
    }
}
?>
