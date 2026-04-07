<?php
/**
 * CSF iptables Management Functions
 * Translates Perl CSF firewall rules to iptables commands
 */

/**
 * Apply firewall rules using iptables
 * Equivalent to Perl: csf.pl -r
 * 
 * @return bool
 */
function iptables_apply_rules() {
    csf_log('Applying firewall rules', 'INFO', 'iptables');
    
    // Flush existing rules
    if (!iptables_flush_rules()) {
        csf_log('Failed to flush existing iptables rules', 'ERROR', 'iptables');
        return false;
    }
    
    // Create CSF chains
    if (!iptables_create_chains()) {
        csf_log('Failed to create iptables chains', 'ERROR', 'iptables');
        return false;
    }
    
    // Add inbound rules
    if (!iptables_add_inbound_rules()) {
        csf_log('Failed to add inbound rules', 'ERROR', 'iptables');
        return false;
    }
    
    // Add outbound rules
    if (!iptables_add_outbound_rules()) {
        csf_log('Failed to add outbound rules', 'ERROR', 'iptables');
        return false;
    }
    
    // Add whitelist rules
    if (!iptables_add_whitelist_rules()) {
        csf_log('Failed to add whitelist rules', 'ERROR', 'iptables');
        return false;
    }
    
    // Add blacklist rules
    if (!iptables_add_blacklist_rules()) {
        csf_log('Failed to add blacklist rules', 'ERROR', 'iptables');
        return false;
    }
    
    // Add port-specific rules
    if (!iptables_add_port_rules()) {
        csf_log('Failed to add port rules', 'ERROR', 'iptables');
        return false;
    }
    
    // Save rules to file
    if (!iptables_save_rules()) {
        csf_log('Failed to save iptables rules', 'ERROR', 'iptables');
        return false;
    }
    
    csf_log('Firewall rules applied successfully', 'INFO', 'iptables');
    return true;
}

/**
 * Flush all iptables rules
 * 
 * @return bool
 */
function iptables_flush_rules() {
    $commands = array(
        'iptables -t filter -F',
        'iptables -t filter -X',
        'iptables -t nat -F',
        'iptables -t nat -X',
        'iptables -t mangle -F',
        'iptables -t mangle -X',
        'ip6tables -t filter -F',
        'ip6tables -t filter -X',
        'ip6tables -t nat -F',
        'ip6tables -t nat -X',
    );
    
    foreach ($commands as $cmd) {
        exec($cmd . ' 2>/dev/null');
    }
    
    return true;
}

/**
 * Create CSF iptables chains
 * 
 * @return bool
 */
function iptables_create_chains() {
    $chains = array(
        'CSF_INPUT',
        'CSF_OUTPUT',
        'CSF_FORWARD',
        'CSF_ALLOWIN',
        'CSF_ALLOWOUT',
        'CSF_DENYIN',
        'CSF_DENYOUT',
        'CSF_LOGDROP',
    );
    
    foreach ($chains as $chain) {
        exec('iptables -t filter -N ' . escapeshellarg($chain) . ' 2>/dev/null');
        exec('ip6tables -t filter -N ' . escapeshellarg($chain) . ' 2>/dev/null');
    }
    
    // Link CSF chains to default chains
    exec('iptables -t filter -I INPUT -j CSF_INPUT');
    exec('iptables -t filter -I OUTPUT -j CSF_OUTPUT');
    exec('iptables -t filter -I FORWARD -j CSF_FORWARD');
    
    exec('ip6tables -t filter -I INPUT -j CSF_INPUT');
    exec('ip6tables -t filter -I OUTPUT -j CSF_OUTPUT');
    exec('ip6tables -t filter -I FORWARD -j CSF_FORWARD');
    
    return true;
}

/**
 * Add inbound firewall rules
 * 
 * @return bool
 */
function iptables_add_inbound_rules() {
    $config = $GLOBALS['csf_config'];
    
    // Default policy
    $default_policy = isset($config['DENY_INCOMING']) && $config['DENY_INCOMING'] ? 'DROP' : 'ACCEPT';
    
    // Allow localhost
    exec('iptables -I CSF_INPUT -i lo -j ACCEPT');
    exec('ip6tables -I CSF_INPUT -i lo -j ACCEPT');
    
    // Allow established connections
    exec('iptables -I CSF_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT');
    exec('ip6tables -I CSF_INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT');
    
    // Allow ICMP
    if (isset($config['ICMP_PING']) && $config['ICMP_PING']) {
        exec('iptables -I CSF_INPUT -p icmp --icmp-type echo-request -j ACCEPT');
        exec('ip6tables -I CSF_INPUT -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT');
    }
    
    // Set default drop policy
    exec('iptables -P INPUT ' . $default_policy);
    exec('iptables -P FORWARD DROP');
    exec('iptables -P OUTPUT ACCEPT');
    
    return true;
}

/**
 * Add outbound firewall rules
 * 
 * @return bool
 */
function iptables_add_outbound_rules() {
    $config = $GLOBALS['csf_config'];
    
    // Allow localhost
    exec('iptables -I CSF_OUTPUT -o lo -j ACCEPT');
    exec('ip6tables -I CSF_OUTPUT -o lo -j ACCEPT');
    
    // Allow established connections
    exec('iptables -I CSF_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT');
    exec('ip6tables -I CSF_OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT');
    
    return true;
}

/**
 * Add whitelist (allow) rules
 * 
 * @return bool
 */
function iptables_add_whitelist_rules() {
    $whitelist = $GLOBALS['csf_whitelist'];
    
    foreach ($whitelist as $entry) {
        $ip = $entry['ip'];
        
        // Skip invalid IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }
        
        // Determine IP version
        $version = strpos($ip, ':') !== false ? 6 : 4;
        $iptables = $version === 6 ? 'ip6tables' : 'iptables';
        
        // Add allow rule
        exec($iptables . ' -I CSF_ALLOWIN -s ' . escapeshellarg($ip) . ' -j ACCEPT');
        exec($iptables . ' -I CSF_ALLOWOUT -d ' . escapeshellarg($ip) . ' -j ACCEPT');
    }
    
    return true;
}

/**
 * Add blacklist (deny) rules
 * 
 * @return bool
 */
function iptables_add_blacklist_rules() {
    $blacklist = $GLOBALS['csf_blacklist'];
    
    foreach ($blacklist as $entry) {
        $ip = $entry['ip'];
        
        // Skip invalid IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }
        
        // Determine IP version
        $version = strpos($ip, ':') !== false ? 6 : 4;
        $iptables = $version === 6 ? 'ip6tables' : 'iptables';
        
        // Add deny rule
        exec($iptables . ' -I CSF_DENYIN -s ' . escapeshellarg($ip) . ' -j REJECT');
        exec($iptables . ' -I CSF_DENYOUT -d ' . escapeshellarg($ip) . ' -j REJECT');
    }
    
    return true;
}

/**
 * Add port-specific rules
 * 
 * @return bool
 */
function iptables_add_port_rules() {
    $config = $GLOBALS['csf_config'];
    
    // Parse TCP ports
    if (isset($config['TCP_IN']) && !empty($config['TCP_IN'])) {
        $ports = explode(',', $config['TCP_IN']);
        
        foreach ($ports as $port) {
            $port = trim($port);
            
            if (is_numeric($port) && $port > 0 && $port < 65536) {
                exec('iptables -I CSF_ALLOWIN -p tcp --dport ' . intval($port) . ' -j ACCEPT');
                exec('ip6tables -I CSF_ALLOWIN -p tcp --dport ' . intval($port) . ' -j ACCEPT');
            }
        }
    }
    
    // Parse UDP ports
    if (isset($config['UDP_IN']) && !empty($config['UDP_IN'])) {
        $ports = explode(',', $config['UDP_IN']);
        
        foreach ($ports as $port) {
            $port = trim($port);
            
            if (is_numeric($port) && $port > 0 && $port < 65536) {
                exec('iptables -I CSF_ALLOWIN -p udp --dport ' . intval($port) . ' -j ACCEPT');
                exec('ip6tables -I CSF_ALLOWIN -p udp --dport ' . intval($port) . ' -j ACCEPT');
            }
        }
    }
    
    return true;
}

/**
 * Save iptables rules to file
 * 
 * @return bool
 */
function iptables_save_rules() {
    // Save IPv4 rules
    exec('iptables-save > /etc/iptables/rules.v4 2>/dev/null');
    
    // Save IPv6 rules
    exec('ip6tables-save > /etc/iptables/rules.v6 2>/dev/null');
    
    return true;
}

/**
 * Restart firewall rules
 * Equivalent to Perl: csf.pl -r
 * 
 * @return bool
 */
function iptables_restart() {
    return iptables_apply_rules();
}

/**
 * Stop firewall rules
 * Equivalent to Perl: csf.pl -x
 * 
 * @return bool
 */
function iptables_stop() {
    csf_log('Stopping firewall', 'INFO', 'iptables');
    
    // Set accept policy
    exec('iptables -P INPUT ACCEPT');
    exec('iptables -P FORWARD ACCEPT');
    exec('iptables -P OUTPUT ACCEPT');
    exec('ip6tables -P INPUT ACCEPT');
    exec('ip6tables -P FORWARD ACCEPT');
    exec('ip6tables -P OUTPUT ACCEPT');
    
    // Flush all rules
    iptables_flush_rules();
    
    csf_log('Firewall stopped', 'INFO', 'iptables');
    return true;
}

/**
 * Add IP to allow list
 * 
 * @param string $ip IP address or CIDR
 * @param string $comment Reason for addition
 * @return bool
 */
function iptables_add_allow($ip, $comment = '') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        csf_log('Invalid IP address: ' . $ip, 'WARN', 'iptables');
        return false;
    }
    
    $allow_file = CSF_CONF . '/csf.allow';
    
    $entry = $ip . '|' . $comment . '|' . date('Y-m-d H:i:s') . "\n";
    
    if (file_put_contents($allow_file, $entry, FILE_APPEND) === false) {
        csf_log('Failed to add IP to allow list: ' . $ip, 'ERROR', 'iptables');
        return false;
    }
    
    // Apply rule
    $version = strpos($ip, ':') !== false ? 6 : 4;
    $iptables = $version === 6 ? 'ip6tables' : 'iptables';
    exec($iptables . ' -I CSF_ALLOWIN -s ' . escapeshellarg($ip) . ' -j ACCEPT');
    
    csf_log('IP added to allow list: ' . $ip, 'INFO', 'iptables');
    return true;
}

/**
 * Add IP to deny list
 * 
 * @param string $ip IP address or CIDR
 * @param string $comment Reason for addition
 * @return bool
 */
function iptables_add_deny($ip, $comment = '') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        csf_log('Invalid IP address: ' . $ip, 'WARN', 'iptables');
        return false;
    }
    
    $deny_file = CSF_CONF . '/csf.deny';
    
    $entry = $ip . '|' . $comment . '|' . date('Y-m-d H:i:s') . "\n";
    
    if (file_put_contents($deny_file, $entry, FILE_APPEND) === false) {
        csf_log('Failed to add IP to deny list: ' . $ip, 'ERROR', 'iptables');
        return false;
    }
    
    // Apply rule
    $version = strpos($ip, ':') !== false ? 6 : 4;
    $iptables = $version === 6 ? 'ip6tables' : 'iptables';
    exec($iptables . ' -I CSF_DENYIN -s ' . escapeshellarg($ip) . ' -j REJECT');
    
    csf_log('IP added to deny list: ' . $ip, 'INFO', 'iptables');
    return true;
}

/**
 * Remove IP from allow list
 * 
 * @param string $ip IP address
 * @return bool
 */
function iptables_remove_allow($ip) {
    $allow_file = CSF_CONF . '/csf.allow';
    
    if (!file_exists($allow_file)) {
        return false;
    }
    
    $lines = file($allow_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $updated_lines = array();
    $found = false;
    
    foreach ($lines as $line) {
        if (strpos($line, $ip . '|') !== 0) {
            $updated_lines[] = $line;
        } else {
            $found = true;
        }
    }
    
    if (!$found) {
        return false;
    }
    
    file_put_contents($allow_file, implode("\n", $updated_lines) . "\n");
    
    // Remove rule
    $version = strpos($ip, ':') !== false ? 6 : 4;
    $iptables = $version === 6 ? 'ip6tables' : 'iptables';
    exec($iptables . ' -D CSF_ALLOWIN -s ' . escapeshellarg($ip) . ' -j ACCEPT 2>/dev/null');
    
    csf_log('IP removed from allow list: ' . $ip, 'INFO', 'iptables');
    return true;
}

/**
 * Remove IP from deny list
 * 
 * @param string $ip IP address
 * @return bool
 */
function iptables_remove_deny($ip) {
    $deny_file = CSF_CONF . '/csf.deny';
    
    if (!file_exists($deny_file)) {
        return false;
    }
    
    $lines = file($deny_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $updated_lines = array();
    $found = false;
    
    foreach ($lines as $line) {
        if (strpos($line, $ip . '|') !== 0) {
            $updated_lines[] = $line;
        } else {
            $found = true;
        }
    }
    
    if (!$found) {
        return false;
    }
    
    file_put_contents($deny_file, implode("\n", $updated_lines) . "\n");
    
    // Remove rule
    $version = strpos($ip, ':') !== false ? 6 : 4;
    $iptables = $version === 6 ? 'ip6tables' : 'iptables';
    exec($iptables . ' -D CSF_DENYIN -s ' . escapeshellarg($ip) . ' -j REJECT 2>/dev/null');
    
    csf_log('IP removed from deny list: ' . $ip, 'INFO', 'iptables');
    return true;
}
