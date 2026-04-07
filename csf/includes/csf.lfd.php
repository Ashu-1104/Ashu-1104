<?php
/**
 * CSF LFD (Login Failure Daemon) Communication Functions
 * Handles PHP-to-LFD IPC via shared command files
 * LFD remains in C for performance, PHP sends commands via file system
 */

/**
 * Initialize LFD command directory
 * 
 * @param string $cmd_dir Path to command directory
 * @return bool True on success
 */
function csf_lfd_init($cmd_dir = '/var/lib/csf/cmd') {
    if (!is_dir($cmd_dir)) {
        if (!@mkdir($cmd_dir, 0755, true)) {
            csf_log("ERROR: Failed to create LFD command directory: $cmd_dir", "error");
            return false;
        }
    }

    if (!is_writable($cmd_dir)) {
        csf_log("ERROR: LFD command directory not writable: $cmd_dir", "error");
        return false;
    }

    return true;
}

/**
 * Send command to LFD daemon
 * 
 * @param string $command Command to send (e.g., 'add_ip_block', 'remove_ip_block')
 * @param array $params Command parameters
 * @param string $cmd_dir Path to command directory
 * @return bool True on success
 */
function csf_lfd_send_command($command, $params = array(), $cmd_dir = '/var/lib/csf/cmd') {
    if (empty($command)) {
        csf_log("ERROR: Empty command provided to LFD", "error");
        return false;
    }

    // Sanitize command
    $command = csf_sanitize_command($command);
    if (empty($command)) {
        csf_log("ERROR: Invalid command format for LFD", "error");
        return false;
    }

    // Initialize directory
    if (!csf_lfd_init($cmd_dir)) {
        return false;
    }

    // Create command file with unique ID
    $cmd_id = uniqid('cmd_', true);
    $cmd_file = $cmd_dir . '/' . $cmd_id . '.cmd';

    // Build command content
    $cmd_content = $command . "\n";

    // Add parameters if provided
    if (is_array($params) && !empty($params)) {
        foreach ($params as $key => $value) {
            // Sanitize key
            $key = preg_replace('/[^a-zA-Z0-9_]/', '', $key);
            if (empty($key)) {
                continue;
            }

            // Sanitize value
            if (is_array($value)) {
                $value = implode(',', array_map('csf_sanitize_command', $value));
            } else {
                $value = csf_sanitize_command((string)$value);
            }

            $cmd_content .= "$key=$value\n";
        }
    }

    // Write command file atomically
    if (!csf_write_file($cmd_file, $cmd_content, 0644)) {
        csf_log("ERROR: Failed to write LFD command file: $cmd_file", "error");
        return false;
    }

    csf_log("LFD command sent: $command (ID: $cmd_id)", "info");
    return true;
}

/**
 * Add IP to block list (sends command to LFD)
 * 
 * @param string $ip IP address to block
 * @param string $reason Reason for blocking
 * @param int $duration Duration in seconds (0 = permanent)
 * @return bool True on success
 */
function csf_lfd_add_ip_block($ip, $reason = 'Blocked by CSF', $duration = 0) {
    if (!csf_validate_ip($ip)) {
        csf_log("ERROR: Invalid IP address provided: $ip", "error");
        return false;
    }

    $params = array(
        'ip' => $ip,
        'reason' => $reason,
        'duration' => (int)$duration,
    );

    return csf_lfd_send_command('add_ip_block', $params);
}

/**
 * Remove IP from block list (sends command to LFD)
 * 
 * @param string $ip IP address to unblock
 * @return bool True on success
 */
function csf_lfd_remove_ip_block($ip) {
    if (!csf_validate_ip($ip)) {
        csf_log("ERROR: Invalid IP address provided: $ip", "error");
        return false;
    }

    $params = array('ip' => $ip);
    return csf_lfd_send_command('remove_ip_block', $params);
}

/**
 * Add IP to whitelist (sends command to LFD)
 * 
 * @param string $ip IP address to whitelist
 * @param string $reason Reason for whitelisting
 * @return bool True on success
 */
function csf_lfd_add_ip_whitelist($ip, $reason = 'Whitelisted by CSF') {
    if (!csf_validate_ip($ip)) {
        csf_log("ERROR: Invalid IP address provided: $ip", "error");
        return false;
    }

    $params = array(
        'ip' => $ip,
        'reason' => $reason,
    );

    return csf_lfd_send_command('add_ip_whitelist', $params);
}

/**
 * Remove IP from whitelist (sends command to LFD)
 * 
 * @param string $ip IP address
 * @return bool True on success
 */
function csf_lfd_remove_ip_whitelist($ip) {
    if (!csf_validate_ip($ip)) {
        csf_log("ERROR: Invalid IP address provided: $ip", "error");
        return false;
    }

    $params = array('ip' => $ip);
    return csf_lfd_send_command('remove_ip_whitelist', $params);
}

/**
 * Add port to allow list
 * 
 * @param int $port Port number
 * @param string $protocol Protocol (TCP/UDP)
 * @return bool True on success
 */
function csf_lfd_allow_port($port, $protocol = 'TCP') {
    if (!csf_validate_port($port)) {
        csf_log("ERROR: Invalid port provided: $port", "error");
        return false;
    }

    $protocol = strtoupper($protocol);
    if (!in_array($protocol, array('TCP', 'UDP'))) {
        csf_log("ERROR: Invalid protocol: $protocol", "error");
        return false;
    }

    $params = array(
        'port' => (int)$port,
        'protocol' => $protocol,
    );

    return csf_lfd_send_command('allow_port', $params);
}

/**
 * Remove port from allow list
 * 
 * @param int $port Port number
 * @param string $protocol Protocol (TCP/UDP)
 * @return bool True on success
 */
function csf_lfd_deny_port($port, $protocol = 'TCP') {
    if (!csf_validate_port($port)) {
        csf_log("ERROR: Invalid port provided: $port", "error");
        return false;
    }

    $protocol = strtoupper($protocol);
    if (!in_array($protocol, array('TCP', 'UDP'))) {
        csf_log("ERROR: Invalid protocol: $protocol", "error");
        return false;
    }

    $params = array(
        'port' => (int)$port,
        'protocol' => $protocol,
    );

    return csf_lfd_send_command('deny_port', $params);
}

/**
 * Update iptables rules (sends command to LFD)
 * 
 * @param string $action Action to perform (reload, flush, etc)
 * @return bool True on success
 */
function csf_lfd_update_iptables($action = 'reload') {
    $valid_actions = array('reload', 'flush', 'status');

    if (!in_array(strtolower($action), $valid_actions)) {
        csf_log("ERROR: Invalid iptables action: $action", "error");
        return false;
    }

    $params = array('action' => strtolower($action));
    return csf_lfd_send_command('update_iptables', $params);
}

/**
 * Block country by GeoIP (sends command to LFD)
 * 
 * @param string $country_code Country code (e.g., 'CN', 'RU')
 * @param bool $block True to block, false to allow
 * @return bool True on success
 */
function csf_lfd_country_block($country_code, $block = true) {
    if (empty($country_code) || strlen($country_code) !== 2) {
        csf_log("ERROR: Invalid country code: $country_code", "error");
        return false;
    }

    $country_code = strtoupper($country_code);

    $params = array(
        'country' => $country_code,
        'action' => $block ? 'block' : 'allow',
    );

    return csf_lfd_send_command('country_block', $params);
}

/**
 * Get command queue status
 * 
 * @param string $cmd_dir Path to command directory
 * @return array Command queue statistics
 */
function csf_lfd_get_queue_status($cmd_dir = '/var/lib/csf/cmd') {
    if (!is_dir($cmd_dir)) {
        return array(
            'pending_commands' => 0,
            'queue_dir' => $cmd_dir,
            'exists' => false,
        );
    }

    $files = @scandir($cmd_dir);
    if ($files === false) {
        return array(
            'pending_commands' => 0,
            'queue_dir' => $cmd_dir,
            'exists' => false,
        );
    }

    // Count .cmd files (exclude . and ..)
    $cmd_files = array_filter($files, function($file) {
        return strpos($file, '.cmd') !== false;
    });

    return array(
        'pending_commands' => count($cmd_files),
        'queue_dir' => $cmd_dir,
        'exists' => true,
        'last_command' => filemtime($cmd_dir),
    );
}

/**
 * Clear command queue
 * 
 * @param string $cmd_dir Path to command directory
 * @return bool True on success
 */
function csf_lfd_clear_queue($cmd_dir = '/var/lib/csf/cmd') {
    if (!is_dir($cmd_dir)) {
        return true;
    }

    $files = @scandir($cmd_dir);
    if ($files === false) {
        return false;
    }

    $count = 0;
    foreach ($files as $file) {
        if ($file !== '.' && $file !== '..') {
            $file_path = $cmd_dir . '/' . $file;
            if (is_file($file_path) && @unlink($file_path)) {
                $count++;
            }
        }
    }

    csf_log("LFD command queue cleared ($count commands removed)", "info");
    return true;
}

/**
 * Check if LFD is responsive
 * 
 * @param int $timeout Timeout in seconds
 * @return bool True if LFD is responding
 */
function csf_lfd_is_responsive($timeout = 5) {
    // Simple check: try to send a ping command
    $cmd_dir = '/var/lib/csf/cmd';

    if (!csf_lfd_init($cmd_dir)) {
        return false;
    }

    // Send ping command
    $cmd_id = uniqid('ping_', true);
    $cmd_file = $cmd_dir . '/' . $cmd_id . '.cmd';

    if (!csf_write_file($cmd_file, 'ping' . "\n", 0644)) {
        return false;
    }

    // Wait for response (check if command file was processed)
    $start_time = time();
    while (time() - $start_time < $timeout) {
        if (!file_exists($cmd_file)) {
            return true; // LFD processed the command
        }
        usleep(100000); // Wait 100ms before checking again
    }

    // Clean up if command wasn't processed
    @unlink($cmd_file);
    return false;
}

?>
