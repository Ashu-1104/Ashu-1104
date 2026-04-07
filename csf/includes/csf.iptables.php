<?php
/**
 * CSF iptables and IP Rules Management
 * Handles iptables rule generation and IP blocking/whitelisting
 */

/**
 * Generate iptables rule for blocking IP
 * 
 * @param string $ip IP address or CIDR range
 * @param string $chain iptables chain (INPUT, OUTPUT, FORWARD)
 * @param string $action iptables target (DROP, REJECT, ACCEPT)
 * @return string iptables command or empty string on error
 */
function csf_generate_block_rule($ip, $chain = 'INPUT', $action = 'DROP') {
    if (!csf_validate_cidr($ip)) {
        csf_log("ERROR: Invalid IP/CIDR for rule generation: $ip", "error");
        return '';
    }

    $chain = strtoupper($chain);
    $action = strtoupper($action);

    // Validate chain
    $valid_chains = array('INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING');
    if (!in_array($chain, $valid_chains)) {
        csf_log("ERROR: Invalid iptables chain: $chain", "error");
        return '';
    }

    // Validate action
    $valid_actions = array('DROP', 'REJECT', 'ACCEPT', 'LOG');
    if (!in_array($action, $valid_actions)) {
        csf_log("ERROR: Invalid iptables action: $action", "error");
        return '';
    }

    // Determine if IPv4 or IPv6
    $is_ipv6 = (strpos($ip, ':') !== false);

    // Build iptables command
    $iptables = $is_ipv6 ? 'ip6tables' : 'iptables';
    $rule = "$iptables -I $chain -s $ip -j $action";

    return $rule;
}

/**
 * Apply iptables rule
 * 
 * @param string $ip IP address or CIDR range
 * @param string $chain iptables chain
 * @param string $action iptables target
 * @return bool True on success
 */
function csf_apply_block_rule($ip, $chain = 'INPUT', $action = 'DROP') {
    $rule = csf_generate_block_rule($ip, $chain, $action);

    if (empty($rule)) {
        return false;
    }

    // Send to LFD for execution
    return csf_lfd_send_command('apply_iptables_rule', array('rule' => $rule));
}

/**
 * Block IP address
 * 
 * @param string $ip IP address or CIDR range
 * @param string $reason Reason for blocking
 * @param int $duration Duration in seconds (0 = permanent)
 * @return bool True on success
 */
function csf_block_ip($ip, $reason = 'Blocked by CSF', $duration = 0) {
    if (!csf_validate_cidr($ip)) {
        csf_log("ERROR: Invalid IP/CIDR: $ip", "error");
        return false;
    }

    // Save to deny list file
    $deny_file = CSF_VAR_DIR . '/deny.list';

    // Format: ip|reason|timestamp|expiry
    $timestamp = time();
    $expiry = ($duration > 0) ? ($timestamp + $duration) : 0;
    $entry = "$ip|$reason|$timestamp|$expiry\n";

    if (!csf_append_file($deny_file, $entry)) {
        csf_log("ERROR: Failed to add IP to deny list: $ip", "error");
        return false;
    }

    // Apply iptables rule
    if (!csf_apply_block_rule($ip, 'INPUT', 'DROP')) {
        csf_log("WARNING: Failed to apply iptables rule for: $ip", "warning");
    }

    // Send to LFD
    csf_lfd_add_ip_block($ip, $reason, $duration);

    csf_log_rule_change('BLOCK', 'IP', $ip, 'system');
    csf_log("IP blocked: $ip (Reason: $reason)", "alert");

    return true;
}

/**
 * Unblock IP address
 * 
 * @param string $ip IP address or CIDR range
 * @return bool True on success
 */
function csf_unblock_ip($ip) {
    if (!csf_validate_cidr($ip)) {
        csf_log("ERROR: Invalid IP/CIDR: $ip", "error");
        return false;
    }

    // Read deny list
    $deny_file = CSF_VAR_DIR . '/deny.list';
    $lines = csf_read_file_lines($deny_file);

    if ($lines === false) {
        return false;
    }

    // Filter out the IP
    $updated_lines = array();
    $found = false;

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            continue;
        }

        $parts = explode('|', $line);
        if ($parts[0] === $ip) {
            $found = true;
            continue;
        }

        $updated_lines[] = $line;
    }

    // Write back
    $content = implode("\n", $updated_lines);
    if (!empty($content)) {
        $content .= "\n";
    }

    if (!csf_write_file($deny_file, $content)) {
        csf_log("ERROR: Failed to remove IP from deny list: $ip", "error");
        return false;
    }

    // Remove iptables rule
    csf_lfd_remove_ip_block($ip);

    csf_log_rule_change('UNBLOCK', 'IP', $ip, 'system');
    csf_log("IP unblocked: $ip", "alert");

    return $found;
}

/**
 * Whitelist IP address
 * 
 * @param string $ip IP address or CIDR range
 * @param string $reason Reason for whitelisting
 * @return bool True on success
 */
function csf_whitelist_ip($ip, $reason = 'Whitelisted by CSF') {
    if (!csf_validate_cidr($ip)) {
        csf_log("ERROR: Invalid IP/CIDR: $ip", "error");
        return false;
    }

    // Save to allow list file
    $allow_file = CSF_VAR_DIR . '/allow.list';

    // Format: ip|reason|timestamp
    $timestamp = time();
    $entry = "$ip|$reason|$timestamp\n";

    if (!csf_append_file($allow_file, $entry)) {
        csf_log("ERROR: Failed to add IP to allow list: $ip", "error");
        return false;
    }

    // Send to LFD
    csf_lfd_add_ip_whitelist($ip, $reason);

    csf_log_rule_change('WHITELIST', 'IP', $ip, 'system');
    csf_log("IP whitelisted: $ip (Reason: $reason)", "info");

    return true;
}

/**
 * Remove IP from whitelist
 * 
 * @param string $ip IP address or CIDR range
 * @return bool True on success
 */
function csf_remove_whitelist($ip) {
    if (!csf_validate_cidr($ip)) {
        csf_log("ERROR: Invalid IP/CIDR: $ip", "error");
        return false;
    }

    // Read allow list
    $allow_file = CSF_VAR_DIR . '/allow.list';
    $lines = csf_read_file_lines($allow_file);

    if ($lines === false) {
        return false;
    }

    // Filter out the IP
    $updated_lines = array();
    $found = false;

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            continue;
        }

        $parts = explode('|', $line);
        if ($parts[0] === $ip) {
            $found = true;
            continue;
        }

        $updated_lines[] = $line;
    }

    // Write back
    $content = implode("\n", $updated_lines);
    if (!empty($content)) {
        $content .= "\n";
    }

    if (!csf_write_file($allow_file, $content)) {
        csf_log("ERROR: Failed to remove IP from allow list: $ip", "error");
        return false;
    }

    // Send to LFD
    csf_lfd_remove_ip_whitelist($ip);

    csf_log_rule_change('UNWHITELIST', 'IP', $ip, 'system');
    csf_log("IP removed from whitelist: $ip", "info");

    return $found;
}

/**
 * Get blocked IPs
 * 
 * @param bool $include_expired Include expired blocks
 * @return array Array of blocked IPs with details
 */
function csf_get_blocked_ips($include_expired = false) {
    $deny_file = CSF_VAR_DIR . '/deny.list';
    $lines = csf_read_file_lines($deny_file);

    if ($lines === false) {
        return array();
    }

    $blocked_ips = array();
    $current_time = time();

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            continue;
        }

        $parts = explode('|', $line);
        if (count($parts) < 2) {
            continue;
        }

        $ip = $parts[0];
        $reason = isset($parts[1]) ? $parts[1] : 'Unknown';
        $timestamp = isset($parts[2]) ? (int)$parts[2] : 0;
        $expiry = isset($parts[3]) ? (int)$parts[3] : 0;

        // Check if expired
        if ($expiry > 0 && $current_time > $expiry) {
            if (!$include_expired) {
                continue;
            }
            $is_expired = true;
        } else {
            $is_expired = false;
        }

        $blocked_ips[] = array(
            'ip' => $ip,
            'reason' => $reason,
            'timestamp' => $timestamp,
            'timestamp_human' => date('Y-m-d H:i:s', $timestamp),
            'expiry' => $expiry,
            'expiry_human' => ($expiry > 0) ? date('Y-m-d H:i:s', $expiry) : 'Never',
            'is_expired' => $is_expired,
        );
    }

    return $blocked_ips;
}

/**
 * Get whitelisted IPs
 * 
 * @return array Array of whitelisted IPs with details
 */
function csf_get_whitelisted_ips() {
    $allow_file = CSF_VAR_DIR . '/allow.list';
    $lines = csf_read_file_lines($allow_file);

    if ($lines === false) {
        return array();
    }

    $whitelisted_ips = array();

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            continue;
        }

        $parts = explode('|', $line);
        if (count($parts) < 1) {
            continue;
        }

        $ip = $parts[0];
        $reason = isset($parts[1]) ? $parts[1] : 'Unknown';
        $timestamp = isset($parts[2]) ? (int)$parts[2] : 0;

        $whitelisted_ips[] = array(
            'ip' => $ip,
            'reason' => $reason,
            'timestamp' => $timestamp,
            'timestamp_human' => date('Y-m-d H:i:s', $timestamp),
        );
    }

    return $whitelisted_ips;
}

/**
 * Check if IP is blocked
 * 
 * @param string $ip IP address
 * @return bool True if blocked
 */
function csf_is_ip_blocked($ip) {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    $blocked_ips = csf_get_blocked_ips(false);

    foreach ($blocked_ips as $block) {
        if (csf_ip_in_cidr($ip, $block['ip'])) {
            return true;
        }
    }

    return false;
}

/**
 * Check if IP is whitelisted
 * 
 * @param string $ip IP address
 * @return bool True if whitelisted
 */
function csf_is_ip_whitelisted($ip) {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    $whitelisted_ips = csf_get_whitelisted_ips();

    foreach ($whitelisted_ips as $allow) {
        if (csf_ip_in_cidr($ip, $allow['ip'])) {
            return true;
        }
    }

    return false;
}

/**
 * Get IP status (blocked, whitelisted, or allowed)
 * 
 * @param string $ip IP address
 * @return array Status information
 */
function csf_get_ip_status($ip) {
    if (!csf_validate_ip($ip)) {
        return array('status' => 'invalid', 'ip' => $ip);
    }

    $is_whitelisted = csf_is_ip_whitelisted($ip);
    $is_blocked = csf_is_ip_blocked($ip);

    if ($is_whitelisted) {
        return array(
            'status' => 'whitelisted',
            'ip' => $ip,
            'allowed' => true,
        );
    }

    if ($is_blocked) {
        return array(
            'status' => 'blocked',
            'ip' => $ip,
            'allowed' => false,
        );
    }

    return array(
        'status' => 'allowed',
        'ip' => $ip,
        'allowed' => true,
    );
}

?>
