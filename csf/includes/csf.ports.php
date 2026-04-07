<?php
/**
 * CSF Port Management Functions
 * Handles port allow/deny rules and firewall port configuration
 */

/**
 * Add port to allow list
 * 
 * @param int $port Port number
 * @param string $protocol Protocol (TCP, UDP, or both)
 * @param string $description Port description
 * @return bool True on success
 */
function csf_allow_port($port, $protocol = 'TCP', $description = '') {
    if (!csf_validate_port($port)) {
        csf_log("ERROR: Invalid port number: $port", "error");
        return false;
    }

    $protocol = strtoupper($protocol);
    if (!in_array($protocol, array('TCP', 'UDP', 'BOTH'))) {
        csf_log("ERROR: Invalid protocol: $protocol", "error");
        return false;
    }

    // Get current TCP_IN and UDP_IN
    $config = csf_get_config();
    
    $tcp_ports = isset($config['TCP_IN']) ? $config['TCP_IN'] : '';
    $udp_ports = isset($config['UDP_IN']) ? $config['UDP_IN'] : '';

    // Add port to appropriate list
    if ($protocol === 'TCP' || $protocol === 'BOTH') {
        if (!csf_is_port_in_list($port, $tcp_ports)) {
            $tcp_ports = csf_add_port_to_list($port, $tcp_ports);
        }
    }

    if ($protocol === 'UDP' || $protocol === 'BOTH') {
        if (!csf_is_port_in_list($port, $udp_ports)) {
            $udp_ports = csf_add_port_to_list($port, $udp_ports);
        }
    }

    // Update configuration
    $new_config = array();
    if ($protocol === 'TCP' || $protocol === 'BOTH') {
        $new_config['TCP_IN'] = $tcp_ports;
    }
    if ($protocol === 'UDP' || $protocol === 'BOTH') {
        $new_config['UDP_IN'] = $udp_ports;
    }

    if (!csf_update_config($new_config)) {
        csf_log("ERROR: Failed to update configuration", "error");
        return false;
    }

    // Send to LFD
    csf_lfd_allow_port($port, $protocol);

    csf_log_rule_change('ALLOW_PORT', 'PORT', "$port/$protocol", 'system');
    csf_log("Port allowed: $port/$protocol" . (!empty($description) ? " ($description)" : ""), "info");

    return true;
}

/**
 * Remove port from allow list
 * 
 * @param int $port Port number
 * @param string $protocol Protocol (TCP, UDP, or both)
 * @return bool True on success
 */
function csf_deny_port($port, $protocol = 'TCP') {
    if (!csf_validate_port($port)) {
        csf_log("ERROR: Invalid port number: $port", "error");
        return false;
    }

    $protocol = strtoupper($protocol);
    if (!in_array($protocol, array('TCP', 'UDP', 'BOTH'))) {
        csf_log("ERROR: Invalid protocol: $protocol", "error");
        return false;
    }

    // Get current TCP_IN and UDP_IN
    $config = csf_get_config();
    
    $tcp_ports = isset($config['TCP_IN']) ? $config['TCP_IN'] : '';
    $udp_ports = isset($config['UDP_IN']) ? $config['UDP_IN'] : '';

    // Remove port from appropriate list
    if ($protocol === 'TCP' || $protocol === 'BOTH') {
        $tcp_ports = csf_remove_port_from_list($port, $tcp_ports);
    }

    if ($protocol === 'UDP' || $protocol === 'BOTH') {
        $udp_ports = csf_remove_port_from_list($port, $udp_ports);
    }

    // Update configuration
    $new_config = array();
    if ($protocol === 'TCP' || $protocol === 'BOTH') {
        $new_config['TCP_IN'] = $tcp_ports;
    }
    if ($protocol === 'UDP' || $protocol === 'BOTH') {
        $new_config['UDP_IN'] = $udp_ports;
    }

    if (!csf_update_config($new_config)) {
        csf_log("ERROR: Failed to update configuration", "error");
        return false;
    }

    // Send to LFD
    csf_lfd_deny_port($port, $protocol);

    csf_log_rule_change('DENY_PORT', 'PORT', "$port/$protocol", 'system');
    csf_log("Port denied: $port/$protocol", "info");

    return true;
}

/**
 * Check if port is in port list
 * 
 * @param int $port Port number
 * @param string $port_list Port list string (e.g., "80,443,8080:8090")
 * @return bool True if port is in list
 */
function csf_is_port_in_list($port, $port_list) {
    if (!csf_validate_port($port)) {
        return false;
    }

    if (empty($port_list)) {
        return false;
    }

    // Split by comma
    $ports = explode(',', $port_list);

    foreach ($ports as $p) {
        $p = trim($p);

        // Check for range
        if (strpos($p, ':') !== false) {
            list($start, $end) = explode(':', $p, 2);
            $start = (int)trim($start);
            $end = (int)trim($end);

            if ($port >= $start && $port <= $end) {
                return true;
            }
        } else {
            // Single port
            if ((int)$p === $port) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Add port to port list
 * 
 * @param int $port Port to add
 * @param string $port_list Existing port list
 * @return string Updated port list
 */
function csf_add_port_to_list($port, $port_list = '') {
    if (!csf_validate_port($port)) {
        return $port_list;
    }

    if (empty($port_list)) {
        return (string)$port;
    }

    // Check if already in list
    if (csf_is_port_in_list($port, $port_list)) {
        return $port_list;
    }

    // Append port
    return $port_list . ',' . $port;
}

/**
 * Remove port from port list
 * 
 * @param int $port Port to remove
 * @param string $port_list Existing port list
 * @return string Updated port list
 */
function csf_remove_port_from_list($port, $port_list = '') {
    if (empty($port_list)) {
        return '';
    }

    if (!csf_validate_port($port)) {
        return $port_list;
    }

    $ports = explode(',', $port_list);
    $updated_ports = array();

    foreach ($ports as $p) {
        $p = trim($p);

        // Check for range
        if (strpos($p, ':') !== false) {
            list($start, $end) = explode(':', $p, 2);
            $start = (int)trim($start);
            $end = (int)trim($end);

            if ($port >= $start && $port <= $end) {
                // Skip this port/range
                continue;
            }
        } else {
            // Single port
            if ((int)$p === $port) {
                // Skip this port
                continue;
            }
        }

        $updated_ports[] = $p;
    }

    return implode(',', $updated_ports);
}

/**
 * Get allowed ports
 * 
 * @param string $protocol Protocol (TCP or UDP)
 * @return array Array of allowed ports
 */
function csf_get_allowed_ports($protocol = 'TCP') {
    $config = csf_get_config();
    $protocol = strtoupper($protocol);

    if ($protocol === 'TCP') {
        $port_list = isset($config['TCP_IN']) ? $config['TCP_IN'] : '';
    } elseif ($protocol === 'UDP') {
        $port_list = isset($config['UDP_IN']) ? $config['UDP_IN'] : '';
    } else {
        return array();
    }

    return csf_parse_port_list($port_list);
}

/**
 * Parse port list string into array
 * 
 * @param string $port_list Port list string (e.g., "80,443,8080:8090")
 * @return array Array of ports
 */
function csf_parse_port_list($port_list) {
    if (empty($port_list)) {
        return array();
    }

    $ports = array();
    $items = explode(',', $port_list);

    foreach ($items as $item) {
        $item = trim($item);

        if (empty($item)) {
            continue;
        }

        // Check for range
        if (strpos($item, ':') !== false) {
            list($start, $end) = explode(':', $item, 2);
            $start = (int)trim($start);
            $end = (int)trim($end);

            for ($p = $start; $p <= $end; $p++) {
                if (csf_validate_port($p)) {
                    $ports[] = $p;
                }
            }
        } else {
            // Single port
            $port = (int)$item;
            if (csf_validate_port($port)) {
                $ports[] = $port;
            }
        }
    }

    return array_unique($ports);
}

/**
 * Check if port is allowed
 * 
 * @param int $port Port number
 * @param string $protocol Protocol (TCP or UDP)
 * @return bool True if port is allowed
 */
function csf_is_port_allowed($port, $protocol = 'TCP') {
    if (!csf_validate_port($port)) {
        return false;
    }

    $protocol = strtoupper($protocol);

    if ($protocol === 'TCP') {
        $config = csf_get_config();
        $tcp_ports = isset($config['TCP_IN']) ? $config['TCP_IN'] : '';
        return csf_is_port_in_list($port, $tcp_ports);
    } elseif ($protocol === 'UDP') {
        $config = csf_get_config();
        $udp_ports = isset($config['UDP_IN']) ? $config['UDP_IN'] : '';
        return csf_is_port_in_list($port, $udp_ports);
    }

    return false;
}

/**
 * Get port status
 * 
 * @param int $port Port number
 * @return array Port status information
 */
function csf_get_port_status($port) {
    if (!csf_validate_port($port)) {
        return array('status' => 'invalid', 'port' => $port);
    }

    $tcp_allowed = csf_is_port_allowed($port, 'TCP');
    $udp_allowed = csf_is_port_allowed($port, 'UDP');

    return array(
        'port' => $port,
        'tcp_allowed' => $tcp_allowed,
        'udp_allowed' => $udp_allowed,
        'status' => ($tcp_allowed || $udp_allowed) ? 'allowed' : 'denied',
    );
}

?>
