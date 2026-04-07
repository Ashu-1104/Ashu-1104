<?php
/**
 * CSF Blocklist Management Functions
 * Handles third-party blocklist integration (spamhaus, etc.)
 */

/**
 * Get available blocklists
 * 
 * @return array Available blocklists
 */
function csf_get_available_blocklists() {
    return array(
        'spamhaus_zen' => array(
            'name' => 'Spamhaus ZEN',
            'url' => 'https://www.spamhaus.org',
            'description' => 'Spamhaus Zero Tolerance Blacklist',
            'type' => 'dnsbl',
            'enabled' => false,
        ),
        'spamhaus_drop' => array(
            'name' => 'Spamhaus DROP',
            'url' => 'https://www.spamhaus.org',
            'description' => 'Spamhaus Don\'t Route Or Peer',
            'type' => 'iplist',
            'enabled' => false,
        ),
        'abuseipdb' => array(
            'name' => 'AbuseIPDB',
            'url' => 'https://abuseipdb.com',
            'description' => 'Community-powered IP reputation database',
            'type' => 'api',
            'enabled' => false,
        ),
        'maxmind_geoip' => array(
            'name' => 'MaxMind GeoIP',
            'url' => 'https://www.maxmind.com',
            'description' => 'Geographic IP database',
            'type' => 'database',
            'enabled' => false,
        ),
        'team_cymru' => array(
            'name' => 'Team Cymru',
            'url' => 'https://www.team-cymru.com',
            'description' => 'IP reputation and netblock information',
            'type' => 'api',
            'enabled' => false,
        ),
    );
}

/**
 * Enable blocklist
 * 
 * @param string $blocklist_id Blocklist identifier
 * @return bool True on success
 */
function csf_enable_blocklist($blocklist_id) {
    if (empty($blocklist_id)) {
        csf_log("ERROR: Empty blocklist ID provided", "error");
        return false;
    }

    // Sanitize blocklist ID
    $blocklist_id = preg_replace('/[^a-zA-Z0-9_]/', '', $blocklist_id);
    if (empty($blocklist_id)) {
        csf_log("ERROR: Invalid blocklist ID format", "error");
        return false;
    }

    // Check if blocklist exists
    $available = csf_get_available_blocklists();
    if (!isset($available[$blocklist_id])) {
        csf_log("ERROR: Unknown blocklist: $blocklist_id", "error");
        return false;
    }

    // Save to enabled blocklists file
    $enabled_file = CSF_VAR_DIR . '/blocklists_enabled.list';
    $entry = "$blocklist_id|" . time() . "\n";

    if (!csf_append_file($enabled_file, $entry)) {
        csf_log("ERROR: Failed to enable blocklist: $blocklist_id", "error");
        return false;
    }

    csf_log_rule_change('ENABLE', 'BLOCKLIST', $blocklist_id, 'system');
    csf_log("Blocklist enabled: $blocklist_id", "info");

    return true;
}

/**
 * Disable blocklist
 * 
 * @param string $blocklist_id Blocklist identifier
 * @return bool True on success
 */
function csf_disable_blocklist($blocklist_id) {
    if (empty($blocklist_id)) {
        csf_log("ERROR: Empty blocklist ID provided", "error");
        return false;
    }

    // Sanitize blocklist ID
    $blocklist_id = preg_replace('/[^a-zA-Z0-9_]/', '', $blocklist_id);
    if (empty($blocklist_id)) {
        csf_log("ERROR: Invalid blocklist ID format", "error");
        return false;
    }

    // Read enabled blocklists
    $enabled_file = CSF_VAR_DIR . '/blocklists_enabled.list';
    $lines = csf_read_file_lines($enabled_file);

    if ($lines === false) {
        return false;
    }

    // Filter out the blocklist
    $updated_lines = array();
    $found = false;

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            continue;
        }

        $parts = explode('|', $line);
        if ($parts[0] === $blocklist_id) {
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

    if (!csf_write_file($enabled_file, $content)) {
        csf_log("ERROR: Failed to disable blocklist: $blocklist_id", "error");
        return false;
    }

    csf_log_rule_change('DISABLE', 'BLOCKLIST', $blocklist_id, 'system');
    csf_log("Blocklist disabled: $blocklist_id", "info");

    return $found;
}

/**
 * Get enabled blocklists
 * 
 * @return array Array of enabled blocklists
 */
function csf_get_enabled_blocklists() {
    $enabled_file = CSF_VAR_DIR . '/blocklists_enabled.list';
    $lines = csf_read_file_lines($enabled_file);

    if ($lines === false) {
        return array();
    }

    $enabled = array();

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            continue;
        }

        $parts = explode('|', $line);
        if (count($parts) < 1) {
            continue;
        }

        $blocklist_id = $parts[0];
        $timestamp = isset($parts[1]) ? (int)$parts[1] : 0;

        $enabled[] = array(
            'id' => $blocklist_id,
            'timestamp' => $timestamp,
            'timestamp_human' => date('Y-m-d H:i:s', $timestamp),
        );
    }

    return $enabled;
}

/**
 * Update blocklist data (download latest)
 * 
 * @param string $blocklist_id Blocklist identifier
 * @param string $source_url URL to download blocklist from
 * @return bool True on success
 */
function csf_update_blocklist($blocklist_id, $source_url) {
    if (empty($blocklist_id) || empty($source_url)) {
        csf_log("ERROR: Empty blocklist ID or URL provided", "error");
        return false;
    }

    // Sanitize inputs
    $blocklist_id = preg_replace('/[^a-zA-Z0-9_]/', '', $blocklist_id);
    if (empty($blocklist_id)) {
        csf_log("ERROR: Invalid blocklist ID format", "error");
        return false;
    }

    if (!csf_validate_url($source_url)) {
        csf_log("ERROR: Invalid blocklist URL: $source_url", "error");
        return false;
    }

    // Download blocklist
    $content = csf_download_blocklist($source_url);
    if ($content === false) {
        csf_log("ERROR: Failed to download blocklist: $blocklist_id", "error");
        return false;
    }

    // Save to file
    $blocklist_file = CSF_VAR_DIR . '/blocklists/' . $blocklist_id . '.list';

    if (!csf_write_file($blocklist_file, $content, 0644)) {
        csf_log("ERROR: Failed to save blocklist file: $blocklist_id", "error");
        return false;
    }

    // Update last download time
    $metadata_file = CSF_VAR_DIR . '/blocklists/' . $blocklist_id . '.meta';
    $metadata = json_encode(array(
        'id' => $blocklist_id,
        'url' => $source_url,
        'updated' => time(),
        'lines' => count(explode("\n", $content)),
    ));

    csf_write_file($metadata_file, $metadata, 0644);

    csf_log("Blocklist updated: $blocklist_id (Lines: " . count(explode("\n", $content)) . ")", "info");

    return true;
}

/**
 * Download blocklist from URL
 * 
 * @param string $url URL to download from
 * @param int $timeout Download timeout in seconds
 * @return string|bool Downloaded content or false on error
 */
function csf_download_blocklist($url, $timeout = 30) {
    if (empty($url)) {
        csf_log("ERROR: Empty URL provided", "error");
        return false;
    }

    if (!csf_validate_url($url)) {
        csf_log("ERROR: Invalid URL: $url", "error");
        return false;
    }

    // Use cURL if available
    if (function_exists('curl_init')) {
        return csf_download_via_curl($url, $timeout);
    }

    // Fall back to file_get_contents
    if (ini_get('allow_url_fopen')) {
        return csf_download_via_fopen($url, $timeout);
    }

    csf_log("ERROR: No download method available", "error");
    return false;
}

/**
 * Download file via cURL
 * 
 * @param string $url URL to download
 * @param int $timeout Timeout in seconds
 * @return string|bool Downloaded content or false
 */
function csf_download_via_curl($url, $timeout = 30) {
    $ch = curl_init();

    curl_setopt_array($ch, array(
        CURLOPT_URL => $url,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => 'CSF/14.0.0 (PHP)',
    ));

    $content = curl_exec($ch);

    if ($content === false) {
        csf_log("ERROR: cURL download failed: " . curl_error($ch), "error");
        curl_close($ch);
        return false;
    }

    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code !== 200) {
        csf_log("ERROR: HTTP error $http_code when downloading blocklist", "error");
        return false;
    }

    return $content;
}

/**
 * Download file via file_get_contents
 * 
 * @param string $url URL to download
 * @param int $timeout Timeout in seconds
 * @return string|bool Downloaded content or false
 */
function csf_download_via_fopen($url, $timeout = 30) {
    $context = stream_context_create(array(
        'http' => array(
            'timeout' => $timeout,
            'user_agent' => 'CSF/14.0.0 (PHP)',
        ),
        'https' => array(
            'timeout' => $timeout,
            'user_agent' => 'CSF/14.0.0 (PHP)',
        ),
    ));

    $content = @file_get_contents($url, false, $context);

    if ($content === false) {
        csf_log("ERROR: file_get_contents download failed for: $url", "error");
        return false;
    }

    return $content;
}

/**
 * Check if IP is in blocklist
 * 
 * @param string $ip IP address to check
 * @param string $blocklist_id Optional specific blocklist to check
 * @return bool True if IP is in blocklist
 */
function csf_is_ip_in_blocklist($ip, $blocklist_id = '') {
    if (!csf_validate_ip($ip)) {
        return false;
    }

    $blocklists_dir = CSF_VAR_DIR . '/blocklists';

    if (!empty($blocklist_id)) {
        // Check specific blocklist
        $blocklist_file = $blocklists_dir . '/' . preg_replace('/[^a-zA-Z0-9_]/', '', $blocklist_id) . '.list';

        if (!file_exists($blocklist_file)) {
            return false;
        }

        return csf_ip_in_blocklist_file($ip, $blocklist_file);
    }

    // Check all enabled blocklists
    $enabled = csf_get_enabled_blocklists();

    foreach ($enabled as $blocklist) {
        $blocklist_file = $blocklists_dir . '/' . $blocklist['id'] . '.list';

        if (file_exists($blocklist_file)) {
            if (csf_ip_in_blocklist_file($ip, $blocklist_file)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Check if IP is in blocklist file
 * 
 * @param string $ip IP address
 * @param string $blocklist_file Path to blocklist file
 * @return bool True if IP is in file
 */
function csf_ip_in_blocklist_file($ip, $blocklist_file) {
    if (!file_exists($blocklist_file) || !is_readable($blocklist_file)) {
        return false;
    }

    $lines = csf_read_file_lines($blocklist_file);

    if ($lines === false) {
        return false;
    }

    foreach ($lines as $line) {
        $line = trim($line);

        if (empty($line) || strpos($line, '#') === 0) {
            continue;
        }

        // Check both single IPs and CIDR ranges
        if (csf_ip_in_cidr($ip, $line)) {
            return true;
        }
    }

    return false;
}

?>
