<?php
/**
 * CSF Core Initialization
 * Loads all foundation modules and initializes CSF
 * This is the main entry point for all CSF operations
 */

// Define CSF version and paths
defined('CSF_VERSION') or define('CSF_VERSION', '14.0.0-PHP');
defined('CSF_BASE_DIR') or define('CSF_BASE_DIR', dirname(dirname(__FILE__)));
defined('CSF_INCLUDES_DIR') or define('CSF_INCLUDES_DIR', CSF_BASE_DIR . '/includes');
defined('CSF_CONFIG_DIR') or define('CSF_CONFIG_DIR', '/etc/csf');
defined('CSF_VAR_DIR') or define('CSF_VAR_DIR', '/var/lib/csf');
defined('CSF_LOG_DIR') or define('CSF_LOG_DIR', '/var/log/csf');
defined('CSF_LFD_CMD_DIR') or define('CSF_LFD_CMD_DIR', '/var/lib/csf/cmd');

// Load foundation modules
require_once CSF_INCLUDES_DIR . '/csf.validate.php';
require_once CSF_INCLUDES_DIR . '/csf.logging.php';
require_once CSF_INCLUDES_DIR . '/csf.file.php';
require_once CSF_INCLUDES_DIR . '/csf.conf.php';
require_once CSF_INCLUDES_DIR . '/csf.lfd.php';

// Load core firewall modules
require_once CSF_INCLUDES_DIR . '/csf.iptables.php';
require_once CSF_INCLUDES_DIR . '/csf.ports.php';

// Load advanced features
require_once CSF_INCLUDES_DIR . '/csf.geoip.php';
require_once CSF_INCLUDES_DIR . '/csf.portscan.php';
require_once CSF_INCLUDES_DIR . '/csf.ddos.php';
require_once CSF_INCLUDES_DIR . '/csf.blocklists.php';

// Load statistics, API, and admin modules
require_once CSF_INCLUDES_DIR . '/csf.stats.php';
require_once CSF_INCLUDES_DIR . '/csf.api.php';
require_once CSF_INCLUDES_DIR . '/csf.admin.php';

// Load UI helper functions
require_once CSF_INCLUDES_DIR . '/csf.html.php';

/**
 * Initialize CSF system
 * 
 * @param bool $debug Enable debug logging
 * @return bool True on success
 */
function csf_init($debug = false) {
    global $csf_initialized, $csf_config, $csf_debug;

    if (isset($csf_initialized) && $csf_initialized) {
        return true;
    }

    $csf_debug = $debug;

    // Initialize logging
    if (!csf_log_init(CSF_LOG_DIR)) {
        error_log("CSF: Failed to initialize logging");
        return false;
    }

    csf_log("CSF initialization started (Version: " . CSF_VERSION . ")", "info");

    // Create required directories
    $required_dirs = array(
        CSF_CONFIG_DIR => 0755,
        CSF_VAR_DIR => 0755,
        CSF_LOG_DIR => 0755,
        CSF_LFD_CMD_DIR => 0755,
    );

    foreach ($required_dirs as $dir => $mode) {
        if (!csf_create_directory($dir, $mode)) {
            csf_log("WARNING: Failed to create directory: $dir", "warning");
        }
    }

    // Load configuration
    $csf_config = csf_load_config(CSF_CONFIG_DIR . '/csf.conf');

    if (empty($csf_config)) {
        csf_log("WARNING: No configuration found, using defaults", "warning");
        $csf_config = csf_get_default_config();

        // Save default configuration
        if (!csf_save_config($csf_config, CSF_CONFIG_DIR . '/csf.conf')) {
            csf_log("ERROR: Failed to save default configuration", "error");
        }
    }

    // Initialize LFD communication
    if (!csf_lfd_init(CSF_LFD_CMD_DIR)) {
        csf_log("WARNING: Failed to initialize LFD communication", "warning");
    }

    // Check if LFD is responsive
    if (!csf_lfd_is_responsive(2)) {
        csf_log("WARNING: LFD daemon may not be responding", "warning");
    }

    csf_log("CSF initialization completed successfully", "info");
    $csf_initialized = true;

    return true;
}

/**
 * Get CSF configuration
 * 
 * @return array Current configuration
 */
function csf_get_config() {
    global $csf_config;

    if (!isset($csf_config)) {
        return csf_get_default_config();
    }

    return $csf_config;
}

/**
 * Update CSF configuration
 * 
 * @param array $new_config New configuration array
 * @return bool True on success
 */
function csf_update_config($new_config) {
    global $csf_config;

    if (!is_array($new_config)) {
        csf_log("ERROR: Invalid configuration provided", "error");
        return false;
    }

    // Merge with existing config
    $csf_config = array_merge($csf_config, $new_config);

    // Save to file
    $result = csf_save_config($csf_config, CSF_CONFIG_DIR . '/csf.conf');

    if ($result) {
        csf_log("Configuration updated successfully", "info");
    }

    return $result;
}

/**
 * Get CSF system status
 * 
 * @return array Status information
 */
function csf_get_status() {
    $status = array(
        'version' => CSF_VERSION,
        'initialized' => isset($GLOBALS['csf_initialized']) ? $GLOBALS['csf_initialized'] : false,
        'debug_mode' => isset($GLOBALS['csf_debug']) ? $GLOBALS['csf_debug'] : false,
        'config_file' => CSF_CONFIG_DIR . '/csf.conf',
        'config_exists' => file_exists(CSF_CONFIG_DIR . '/csf.conf'),
        'directories' => array(
            'config' => array(
                'path' => CSF_CONFIG_DIR,
                'exists' => is_dir(CSF_CONFIG_DIR),
                'writable' => is_writable(CSF_CONFIG_DIR),
            ),
            'var' => array(
                'path' => CSF_VAR_DIR,
                'exists' => is_dir(CSF_VAR_DIR),
                'writable' => is_writable(CSF_VAR_DIR),
            ),
            'log' => array(
                'path' => CSF_LOG_DIR,
                'exists' => is_dir(CSF_LOG_DIR),
                'writable' => is_writable(CSF_LOG_DIR),
            ),
            'lfd_cmd' => array(
                'path' => CSF_LFD_CMD_DIR,
                'exists' => is_dir(CSF_LFD_CMD_DIR),
                'writable' => is_writable(CSF_LFD_CMD_DIR),
            ),
        ),
        'lfd' => array(
            'responsive' => csf_lfd_is_responsive(2),
            'queue_status' => csf_lfd_get_queue_status(CSF_LFD_CMD_DIR),
        ),
        'logs' => array(
            'main' => csf_get_log_stats(CSF_LOG_DIR . '/csf.log'),
            'blocked' => csf_get_log_stats(CSF_LOG_DIR . '/csf.blocked.log'),
            'access' => csf_get_log_stats(CSF_LOG_DIR . '/csf.access.log'),
            'system' => csf_get_log_stats(CSF_LOG_DIR . '/csf.system.log'),
        ),
    );

    return $status;
}

/**
 * Check CSF system health
 * 
 * @return array Health check results
 */
function csf_health_check() {
    $health = array(
        'healthy' => true,
        'errors' => array(),
        'warnings' => array(),
    );

    $status = csf_get_status();

    // Check directories
    foreach ($status['directories'] as $dir_name => $dir_info) {
        if (!$dir_info['exists']) {
            $health['errors'][] = "Directory does not exist: {$dir_info['path']}";
            $health['healthy'] = false;
        } elseif (!$dir_info['writable']) {
            $health['warnings'][] = "Directory not writable: {$dir_info['path']}";
        }
    }

    // Check configuration
    if (!$status['config_exists']) {
        $health['warnings'][] = "Configuration file not found, using defaults";
    }

    // Check LFD
    if (!$status['lfd']['responsive']) {
        $health['warnings'][] = "LFD daemon may not be responding";
    }

    return $health;
}

/**
 * Shutdown CSF gracefully
 * 
 * @return bool True on success
 */
function csf_shutdown() {
    csf_log("CSF shutdown initiated", "info");
    $GLOBALS['csf_initialized'] = false;
    return true;
}

// Initialize CSF on include
if (php_sapi_name() !== 'cli' || isset($_SERVER['DOCUMENT_ROOT'])) {
    // Initialize in web context
    @csf_init(false);
}

?>
