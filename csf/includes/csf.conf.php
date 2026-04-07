<?php
/**
 * CSF Configuration Management Functions
 * Handles loading, saving, and validating CSF configuration
 * Follows file-based storage pattern for Webuzo integration
 */

/**
 * Load CSF configuration from file
 * 
 * @param string $config_file Path to configuration file
 * @return array Configuration array or empty array on error
 */
function csf_load_config($config_file = '/etc/csf/csf.conf') {
    if (!file_exists($config_file)) {
        csf_log("ERROR: Configuration file not found: $config_file", "error");
        return array();
    }

    if (!is_readable($config_file)) {
        csf_log("ERROR: Configuration file not readable: $config_file", "error");
        return array();
    }

    $config = array();
    $lines = file($config_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    if ($lines === false) {
        csf_log("ERROR: Failed to read configuration file: $config_file", "error");
        return array();
    }

    foreach ($lines as $line) {
        // Skip comments
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        // Parse key=value pairs
        $line = trim($line);
        if (empty($line) || strpos($line, '=') === false) {
            continue;
        }

        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);

        // Remove quotes if present
        if ((strpos($value, '"') === 0 && strrpos($value, '"') === strlen($value) - 1) ||
            (strpos($value, "'") === 0 && strrpos($value, "'") === strlen($value) - 1)) {
            $value = substr($value, 1, -1);
        }

        // Convert numeric strings to integers
        if (is_numeric($value)) {
            $value = (strpos($value, '.') !== false) ? (float)$value : (int)$value;
        }

        // Convert boolean strings
        if (strtolower($value) === 'true' || $value === '1') {
            $value = true;
        } elseif (strtolower($value) === 'false' || $value === '0') {
            $value = false;
        }

        $config[$key] = $value;
    }

    csf_log("Configuration loaded from: $config_file (Total keys: " . count($config) . ")", "info");
    return $config;
}

/**
 * Save CSF configuration to file
 * 
 * @param array $config Configuration array to save
 * @param string $config_file Path to configuration file
 * @return bool True on success, false on failure
 */
function csf_save_config($config, $config_file = '/etc/csf/csf.conf') {
    if (!is_array($config) || empty($config)) {
        csf_log("ERROR: Invalid configuration array provided", "error");
        return false;
    }

    // Create directory if it doesn't exist
    $config_dir = dirname($config_file);
    if (!is_dir($config_dir)) {
        if (!@mkdir($config_dir, 0755, true)) {
            csf_log("ERROR: Failed to create config directory: $config_dir", "error");
            return false;
        }
    }

    // Prepare configuration content
    $content = "# CSF Configuration File\n";
    $content .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";

    foreach ($config as $key => $value) {
        // Skip invalid keys
        if (!is_string($key) || empty($key)) {
            continue;
        }

        // Format value
        if (is_bool($value)) {
            $formatted_value = $value ? '1' : '0';
        } elseif (is_array($value)) {
            $formatted_value = '"' . implode(',', $value) . '"';
        } else {
            $formatted_value = '"' . addslashes($value) . '"';
        }

        $content .= "$key=$formatted_value\n";
    }

    // Write with file locking
    $temp_file = $config_file . '.tmp';
    $fp = @fopen($temp_file, 'w');

    if ($fp === false) {
        csf_log("ERROR: Failed to open temp file for writing: $temp_file", "error");
        return false;
    }

    if (!flock($fp, LOCK_EX)) {
        csf_log("ERROR: Failed to acquire lock on temp file: $temp_file", "error");
        fclose($fp);
        return false;
    }

    if (fwrite($fp, $content) === false) {
        csf_log("ERROR: Failed to write configuration to temp file: $temp_file", "error");
        flock($fp, LOCK_UN);
        fclose($fp);
        @unlink($temp_file);
        return false;
    }

    flock($fp, LOCK_UN);
    fclose($fp);

    // Atomic rename
    if (!@rename($temp_file, $config_file)) {
        csf_log("ERROR: Failed to move temp file to config location", "error");
        @unlink($temp_file);
        return false;
    }

    // Set proper permissions
    @chmod($config_file, 0600);

    csf_log("Configuration saved to: $config_file (Total keys: " . count($config) . ")", "info");
    return true;
}

/**
 * Get a specific configuration value
 * 
 * @param array $config Configuration array
 * @param string $key Configuration key
 * @param mixed $default Default value if key doesn't exist
 * @return mixed Configuration value or default
 */
function csf_get_config_value(&$config, $key, $default = null) {
    if (!is_array($config)) {
        return $default;
    }

    if (!isset($config[$key])) {
        return $default;
    }

    return $config[$key];
}

/**
 * Set a specific configuration value
 * 
 * @param array &$config Configuration array (passed by reference)
 * @param string $key Configuration key
 * @param mixed $value Configuration value
 * @return bool True on success
 */
function csf_set_config_value(&$config, $key, $value) {
    if (!is_array($config)) {
        csf_log("ERROR: Invalid configuration array provided", "error");
        return false;
    }

    if (!is_string($key) || empty($key)) {
        csf_log("ERROR: Invalid configuration key: $key", "error");
        return false;
    }

    $config[$key] = $value;
    return true;
}

/**
 * Validate configuration value based on type
 * 
 * @param string $key Configuration key
 * @param mixed $value Configuration value
 * @return array Array with 'valid' (bool) and 'message' (string)
 */
function csf_validate_config_value($key, $value) {
    $result = array('valid' => true, 'message' => '');

    // Define validation rules
    $validation_rules = array(
        'ENABLED' => array('type' => 'boolean'),
        'TESTING' => array('type' => 'boolean'),
        'VERBOSE' => array('type' => 'integer', 'min' => 0, 'max' => 2),
        'TCP_IN' => array('type' => 'ports'),
        'TCP_OUT' => array('type' => 'ports'),
        'UDP_IN' => array('type' => 'ports'),
        'UDP_OUT' => array('type' => 'ports'),
        'LF_SSHD' => array('type' => 'integer', 'min' => 0),
        'LF_SSHD_PERM' => array('type' => 'integer', 'min' => 0),
        'LF_IMAPD' => array('type' => 'integer', 'min' => 0),
        'LF_IMAPD_PERM' => array('type' => 'integer', 'min' => 0),
    );

    if (!isset($validation_rules[$key])) {
        return $result; // No validation rule, accept any value
    }

    $rule = $validation_rules[$key];

    switch ($rule['type']) {
        case 'boolean':
            if (!is_bool($value) && $value !== '0' && $value !== '1' && $value !== 0 && $value !== 1) {
                $result['valid'] = false;
                $result['message'] = "Value for $key must be boolean (0 or 1)";
            }
            break;

        case 'integer':
            if (!is_numeric($value)) {
                $result['valid'] = false;
                $result['message'] = "Value for $key must be numeric";
                break;
            }
            $value = (int)$value;
            if (isset($rule['min']) && $value < $rule['min']) {
                $result['valid'] = false;
                $result['message'] = "Value for $key must be >= {$rule['min']}";
            } elseif (isset($rule['max']) && $value > $rule['max']) {
                $result['valid'] = false;
                $result['message'] = "Value for $key must be <= {$rule['max']}";
            }
            break;

        case 'ports':
            if (empty($value)) {
                break; // Empty is allowed
            }
            $ports = explode(',', $value);
            foreach ($ports as $port) {
                $port = trim($port);
                if (!is_numeric($port) || (int)$port < 1 || (int)$port > 65535) {
                    $result['valid'] = false;
                    $result['message'] = "Invalid port in $key: $port (must be 1-65535)";
                    break 2;
                }
            }
            break;
    }

    return $result;
}

/**
 * Initialize default CSF configuration
 * 
 * @return array Default configuration array
 */
function csf_get_default_config() {
    return array(
        'ENABLED' => 1,
        'TESTING' => 0,
        'VERBOSE' => 1,
        'LOGLEVEL' => 2,
        'LOGSIZE' => 1000000,
        'DROP_IP_LOGGING' => 1,
        'DROP_OUT_LOGGING' => 1,
        'SYN_LOGGING' => 1,
        'TCP_IN' => '20,21,22,25,53,80,110,143,443,465,587,993,995,3306',
        'TCP_OUT' => '1:65535',
        'UDP_IN' => '53,123',
        'UDP_OUT' => '53,123',
        'DROP_INCOMING_ICMP' => 0,
        'DROP_OUTGOING_ICMP' => 0,
        'SYNFLOOD' => 1,
        'SYNFLOOD_RATE' => '100/s',
        'CONNLIMIT' => 1,
        'CONNLIMIT_RATE' => '100',
        'LF_SSHD' => 5,
        'LF_SSHD_PERM' => 1,
        'LF_IMAPD' => 10,
        'LF_IMAPD_PERM' => 1,
        'GEOIP_ENABLED' => 0,
        'GEOIP_SKIP_COUNTRIES' => '',
        'GEOIP_BLOCK_COUNTRIES' => '',
        'LF_BLOCKLISTS' => 1,
        'BLOCKLIST_UPDATE_INTERVAL' => 3600,
    );
}

?>
