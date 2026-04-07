<?php
/**
 * CSF Validation and Utility Functions
 * Input validation, sanitization, and common utilities
 */

/**
 * Validate IP address (IPv4 and IPv6)
 * 
 * @param string $ip IP address to validate
 * @return bool True if valid IP
 */
function csf_validate_ip($ip) {
    if (empty($ip) || !is_string($ip)) {
        return false;
    }

    $ip = trim($ip);

    // Check for IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return true;
    }

    // Check for IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return true;
    }

    return false;
}

/**
 * Validate IP range (CIDR notation)
 * 
 * @param string $cidr CIDR notation (e.g., 192.168.0.0/24)
 * @return bool True if valid CIDR
 */
function csf_validate_cidr($cidr) {
    if (empty($cidr) || !is_string($cidr)) {
        return false;
    }

    $cidr = trim($cidr);

    // Check if it contains /
    if (strpos($cidr, '/') === false) {
        // It's a single IP
        return csf_validate_ip($cidr);
    }

    list($ip, $prefix) = explode('/', $cidr, 2);

    // Validate IP part
    if (!csf_validate_ip(trim($ip))) {
        return false;
    }

    // Validate prefix length
    $prefix = trim($prefix);
    if (!is_numeric($prefix)) {
        return false;
    }

    $prefix = (int)$prefix;

    // Check if it's IPv4 or IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $prefix >= 1 && $prefix <= 32;
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return $prefix >= 1 && $prefix <= 128;
    }

    return false;
}

/**
 * Validate port number
 * 
 * @param int $port Port number
 * @return bool True if valid port
 */
function csf_validate_port($port) {
    if (!is_numeric($port)) {
        return false;
    }

    $port = (int)$port;
    return $port >= 1 && $port <= 65535;
}

/**
 * Validate port range
 * 
 * @param string $range Port range (e.g., "1024:65535" or "80,443,8080")
 * @return bool True if valid port range
 */
function csf_validate_port_range($range) {
    if (empty($range)) {
        return true; // Empty is allowed
    }

    // Handle comma-separated ports
    if (strpos($range, ',') !== false) {
        $ports = explode(',', $range);
        foreach ($ports as $port) {
            $port = trim($port);

            // Check for port range within comma list
            if (strpos($port, ':') !== false) {
                if (!csf_validate_port_range($port)) {
                    return false;
                }
            } else {
                if (!csf_validate_port((int)$port)) {
                    return false;
                }
            }
        }
        return true;
    }

    // Handle colon-separated range
    if (strpos($range, ':') !== false) {
        list($start, $end) = explode(':', $range, 2);
        $start = (int)trim($start);
        $end = (int)trim($end);

        if (!csf_validate_port($start) || !csf_validate_port($end)) {
            return false;
        }

        return $start <= $end;
    }

    // Single port
    return csf_validate_port((int)$range);
}

/**
 * Check if IP is in CIDR range
 * 
 * @param string $ip IP address to check
 * @param string $cidr CIDR range
 * @return bool True if IP is in range
 */
function csf_ip_in_cidr($ip, $cidr) {
    if (!csf_validate_ip($ip) || !csf_validate_cidr($cidr)) {
        return false;
    }

    // If CIDR is a single IP
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }

    list($net, $prefix) = explode('/', $cidr, 2);
    $net = trim($net);
    $prefix = (int)trim($prefix);

    // Handle IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
        filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        
        $ip_long = ip2long($ip);
        $net_long = ip2long($net);
        $mask = -1 << (32 - $prefix);
        
        return ($ip_long & $mask) === ($net_long & $mask);
    }

    // Handle IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) &&
        filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        
        // IPv6 CIDR check (simplified)
        $ip_packed = inet_pton($ip);
        $net_packed = inet_pton($net);
        
        if ($ip_packed === false || $net_packed === false) {
            return false;
        }

        $bytes = intval($prefix / 8);
        $bits = $prefix % 8;
        
        if ($bytes > 0) {
            if (substr($ip_packed, 0, $bytes) !== substr($net_packed, 0, $bytes)) {
                return false;
            }
        }

        if ($bits > 0) {
            $mask = 0xFF << (8 - $bits);
            $ip_byte = ord($ip_packed[$bytes]);
            $net_byte = ord($net_packed[$bytes]);
            
            return ($ip_byte & $mask) === ($net_byte & $mask);
        }

        return true;
    }

    return false;
}

/**
 * Sanitize IP address (remove invalid characters)
 * 
 * @param string $ip IP address
 * @return string Sanitized IP address
 */
function csf_sanitize_ip($ip) {
    if (empty($ip)) {
        return '';
    }

    $ip = trim($ip);

    // Remove invalid characters (keep only valid IP characters)
    $ip = preg_replace('/[^0-9a-fA-F:.\/]/', '', $ip);

    // Validate and return
    if (csf_validate_ip($ip) || csf_validate_cidr($ip)) {
        return $ip;
    }

    return '';
}

/**
 * Sanitize filename
 * 
 * @param string $filename Filename to sanitize
 * @return string Sanitized filename
 */
function csf_sanitize_filename($filename) {
    if (empty($filename)) {
        return '';
    }

    // Remove path traversal attempts
    $filename = basename($filename);

    // Remove invalid characters
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);

    return $filename;
}

/**
 * Sanitize command string (for LFD communication)
 * 
 * @param string $command Command string
 * @return string Sanitized command
 */
function csf_sanitize_command($command) {
    if (empty($command)) {
        return '';
    }

    // Remove dangerous characters
    $command = preg_replace('/[;&|`$()<>]/', '', $command);

    // Trim whitespace
    $command = trim($command);

    return $command;
}

/**
 * Validate service name
 * 
 * @param string $service Service name
 * @return bool True if valid service name
 */
function csf_validate_service_name($service) {
    if (empty($service)) {
        return false;
    }

    // Allow alphanumeric, underscore, hyphen
    return preg_match('/^[a-zA-Z0-9_-]+$/', $service) === 1;
}

/**
 * Validate username
 * 
 * @param string $username Username
 * @return bool True if valid username
 */
function csf_validate_username($username) {
    if (empty($username) || strlen($username) > 32) {
        return false;
    }

    // Allow alphanumeric, underscore, hyphen, dot
    return preg_match('/^[a-zA-Z0-9_.-]+$/', $username) === 1;
}

/**
 * Validate email address
 * 
 * @param string $email Email address
 * @return bool True if valid email
 */
function csf_validate_email($email) {
    if (empty($email)) {
        return false;
    }

    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate URL
 * 
 * @param string $url URL to validate
 * @return bool True if valid URL
 */
function csf_validate_url($url) {
    if (empty($url)) {
        return false;
    }

    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * Convert IP to integer (IPv4 only)
 * 
 * @param string $ip IP address
 * @return int|bool IP as integer or false
 */
function csf_ip_to_int($ip) {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    $long = ip2long($ip);
    if ($long === false) {
        return false;
    }

    // Convert to unsigned integer
    return (int)sprintf("%u", $long);
}

/**
 * Check if string is valid JSON
 * 
 * @param string $string String to check
 * @return bool True if valid JSON
 */
function csf_is_valid_json($string) {
    if (empty($string)) {
        return false;
    }

    json_decode($string);
    return json_last_error() === JSON_ERROR_NONE;
}

/**
 * Get country code from IP (requires GeoIP database)
 * 
 * @param string $ip IP address
 * @param string $geoip_db Path to GeoIP database file
 * @return string|bool Country code or false
 */
function csf_get_country_from_ip($ip, $geoip_db = '') {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    // Check if geoip extension is available
    if (function_exists('geoip_country_code_by_name')) {
        $country = @geoip_country_code_by_name($ip);
        return $country !== false ? $country : false;
    }

    // Alternative: Use MaxMind GeoIP2 if available
    // This would require the maxmind/geoip2 composer package
    
    return false;
}

?>
