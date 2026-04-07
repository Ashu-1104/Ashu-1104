<?php
/**
 * CSF GeoIP Module - Country-based blocking and whitelisting
 * Translates GeoIP functionality from original CSF
 */

/**
 * Load GeoIP database
 * Returns array of country data
 *
 * @return array
 */
function csf_geoip_load_db() {
    $db_file = CSF_VAR_DIR . '/geoip/countries.json';
    
    if (!csf_file_exists($db_file)) {
        csf_log('GeoIP database not found: ' . $db_file, 'GEOIP');
        return array();
    }
    
    $db_content = csf_file_read($db_file);
    if (!$db_content) {
        csf_log('Failed to read GeoIP database', 'GEOIP');
        return array();
    }
    
    $db = json_decode($db_content, true);
    if (!is_array($db)) {
        csf_log('Invalid GeoIP database format', 'GEOIP');
        return array();
    }
    
    return $db;
}

/**
 * Get country code for IP address
 * 
 * @param string $ip IP address to lookup
 * @return string|false Country code or false if not found
 */
function csf_geoip_lookup($ip) {
    if (!csf_validate_ip($ip)) {
        return false;
    }
    
    $cache_file = CSF_VAR_DIR . '/geoip/cache/' . md5($ip) . '.json';
    
    // Check cache first
    if (csf_file_exists($cache_file)) {
        $cache = json_decode(csf_file_read($cache_file), true);
        if (is_array($cache) && isset($cache['country']) && time() - $cache['timestamp'] < 2592000) { // 30 days
            return $cache['country'];
        }
    }
    
    // Query external GeoIP service (MaxMind or similar)
    $country = csf_geoip_query_service($ip);
    
    if ($country) {
        // Cache the result
        $cache_data = array(
            'ip' => $ip,
            'country' => $country,
            'timestamp' => time()
        );
        csf_file_write($cache_file, json_encode($cache_data, JSON_PRETTY_PRINT));
    }
    
    return $country;
}

/**
 * Query GeoIP service for country information
 * 
 * @param string $ip IP address
 * @return string|false Country code or false
 */
function csf_geoip_query_service($ip) {
    $config = csf_config_get();
    
    if (empty($config['GEOIP_SERVICE']) || empty($config['GEOIP_API_KEY'])) {
        return false;
    }
    
    $service = $config['GEOIP_SERVICE'];
    $api_key = $config['GEOIP_API_KEY'];
    
    if ($service === 'maxmind') {
        return csf_geoip_maxmind($ip, $api_key);
    } elseif ($service === 'ip2location') {
        return csf_geoip_ip2location($ip, $api_key);
    }
    
    return false;
}

/**
 * Query MaxMind GeoIP service
 * 
 * @param string $ip IP address
 * @param string $api_key API key
 * @return string|false Country code
 */
function csf_geoip_maxmind($ip, $api_key) {
    $url = 'https://geoip.maxmind.com/geoip/v2.1/country/' . urlencode($ip);
    
    $context = stream_context_create(array(
        'http' => array(
            'method' => 'GET',
            'timeout' => 5,
            'header' => 'Authorization: Basic ' . base64_encode('account_id:' . $api_key)
        )
    ));
    
    $response = @file_get_contents($url, false, $context);
    
    if (!$response) {
        return false;
    }
    
    $data = json_decode($response, true);
    
    if (isset($data['country']['iso_code'])) {
        return $data['country']['iso_code'];
    }
    
    return false;
}

/**
 * Query IP2Location GeoIP service
 * 
 * @param string $ip IP address
 * @param string $api_key API key
 * @return string|false Country code
 */
function csf_geoip_ip2location($ip, $api_key) {
    $url = 'https://api.ip2location.com/?' . http_build_query(array(
        'ip' => $ip,
        'key' => $api_key,
        'format' => 'json'
    ));
    
    $context = stream_context_create(array(
        'http' => array(
            'method' => 'GET',
            'timeout' => 5
        )
    ));
    
    $response = @file_get_contents($url, false, $context);
    
    if (!$response) {
        return false;
    }
    
    $data = json_decode($response, true);
    
    if (isset($data['country_code'])) {
        return $data['country_code'];
    }
    
    return false;
}

/**
 * Check if country is in whitelist
 * 
 * @param string $country_code Country code (e.g., 'US', 'GB')
 * @return bool
 */
function csf_geoip_is_whitelisted($country_code) {
    $config = csf_config_get();
    
    if (empty($config['GEOIP_WHITELIST'])) {
        return false;
    }
    
    $whitelist = explode(',', $config['GEOIP_WHITELIST']);
    $whitelist = array_map('trim', $whitelist);
    
    return in_array(strtoupper($country_code), $whitelist);
}

/**
 * Check if country is in blacklist
 * 
 * @param string $country_code Country code
 * @return bool
 */
function csf_geoip_is_blacklisted($country_code) {
    $config = csf_config_get();
    
    if (empty($config['GEOIP_BLACKLIST'])) {
        return false;
    }
    
    $blacklist = explode(',', $config['GEOIP_BLACKLIST']);
    $blacklist = array_map('trim', $blacklist);
    
    return in_array(strtoupper($country_code), $blacklist);
}

/**
 * Block country - add all IPs from country to blacklist
 * 
 * @param string $country_code Country code
 * @return bool
 */
function csf_geoip_block_country($country_code) {
    if (!preg_match('/^[A-Z]{2}$/', $country_code)) {
        csf_log('Invalid country code: ' . $country_code, 'GEOIP', 'WARN');
        return false;
    }
    
    $blocklist_file = CSF_VAR_DIR . '/geoip/blocked_countries.json';
    $blocked = array();
    
    if (csf_file_exists($blocklist_file)) {
        $content = csf_file_read($blocklist_file);
        $blocked = json_decode($content, true);
        if (!is_array($blocked)) {
            $blocked = array();
        }
    }
    
    if (in_array($country_code, $blocked)) {
        return true; // Already blocked
    }
    
    $blocked[] = $country_code;
    
    $result = csf_file_write($blocklist_file, json_encode($blocked, JSON_PRETTY_PRINT));
    
    if ($result) {
        csf_log('Blocked country: ' . $country_code, 'GEOIP');
        csf_lfd_send_command('GEOIP_BLOCK', $country_code);
    }
    
    return $result;
}

/**
 * Unblock country
 * 
 * @param string $country_code Country code
 * @return bool
 */
function csf_geoip_unblock_country($country_code) {
    if (!preg_match('/^[A-Z]{2}$/', $country_code)) {
        csf_log('Invalid country code: ' . $country_code, 'GEOIP', 'WARN');
        return false;
    }
    
    $blocklist_file = CSF_VAR_DIR . '/geoip/blocked_countries.json';
    
    if (!csf_file_exists($blocklist_file)) {
        return false;
    }
    
    $content = csf_file_read($blocklist_file);
    $blocked = json_decode($content, true);
    
    if (!is_array($blocked) || !in_array($country_code, $blocked)) {
        return false;
    }
    
    $blocked = array_diff($blocked, array($country_code));
    $blocked = array_values($blocked); // Re-index array
    
    $result = csf_file_write($blocklist_file, json_encode($blocked, JSON_PRETTY_PRINT));
    
    if ($result) {
        csf_log('Unblocked country: ' . $country_code, 'GEOIP');
        csf_lfd_send_command('GEOIP_UNBLOCK', $country_code);
    }
    
    return $result;
}

/**
 * Get list of blocked countries
 * 
 * @return array
 */
function csf_geoip_get_blocked_countries() {
    $blocklist_file = CSF_VAR_DIR . '/geoip/blocked_countries.json';
    
    if (!csf_file_exists($blocklist_file)) {
        return array();
    }
    
    $content = csf_file_read($blocklist_file);
    $blocked = json_decode($content, true);
    
    return is_array($blocked) ? $blocked : array();
}

/**
 * Update GeoIP database from remote source
 * 
 * @return bool
 */
function csf_geoip_update_database() {
    $config = csf_config_get();
    
    if (empty($config['GEOIP_DB_URL'])) {
        csf_log('GEOIP_DB_URL not configured', 'GEOIP', 'WARN');
        return false;
    }
    
    $url = $config['GEOIP_DB_URL'];
    $temp_file = CSF_VAR_DIR . '/geoip/countries.json.tmp';
    $db_file = CSF_VAR_DIR . '/geoip/countries.json';
    
    // Download database
    $context = stream_context_create(array(
        'http' => array(
            'timeout' => 30,
            'user_agent' => 'CSF-Firewall/1.0'
        )
    ));
    
    $db_content = @file_get_contents($url, false, $context);
    
    if (!$db_content) {
        csf_log('Failed to download GeoIP database from: ' . $url, 'GEOIP', 'ERROR');
        return false;
    }
    
    // Validate JSON
    $data = json_decode($db_content, true);
    if (!is_array($data)) {
        csf_log('Invalid GeoIP database format received', 'GEOIP', 'ERROR');
        return false;
    }
    
    // Write to temp file first
    if (!csf_file_write($temp_file, $db_content)) {
        csf_log('Failed to write temporary GeoIP database', 'GEOIP', 'ERROR');
        return false;
    }
    
    // Atomic move
    if (!rename($temp_file, $db_file)) {
        csf_log('Failed to update GeoIP database', 'GEOIP', 'ERROR');
        @unlink($temp_file);
        return false;
    }
    
    csf_log('GeoIP database updated successfully', 'GEOIP');
    return true;
}

/**
 * Cleanup old GeoIP cache entries
 * 
 * @return int Number of cleaned entries
 */
function csf_geoip_cleanup_cache() {
    $cache_dir = CSF_VAR_DIR . '/geoip/cache';
    $max_age = 2592000; // 30 days in seconds
    $cleaned = 0;
    
    if (!is_dir($cache_dir)) {
        return 0;
    }
    
    $files = scandir($cache_dir);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        
        $file_path = $cache_dir . '/' . $file;
        
        if (!is_file($file_path)) {
            continue;
        }
        
        if (time() - filemtime($file_path) > $max_age) {
            if (unlink($file_path)) {
                $cleaned++;
            }
        }
    }
    
    if ($cleaned > 0) {
        csf_log('Cleaned ' . $cleaned . ' old GeoIP cache entries', 'GEOIP');
    }
    
    return $cleaned;
}
