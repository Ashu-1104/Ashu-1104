<?php
/**
 * CSF GeoIP Blocking Module
 * Country-based IP blocking using MaxMind/IP2Location databases
 */

define('GEOIP_DB', CSF_VAR . '/GeoIP.dat');
define('GEOIP2_DB', CSF_VAR . '/GeoLite2-Country.mmdb');

/**
 * Initialize GeoIP database
 * 
 * @return bool
 */
function geoip_init() {
    $config = $GLOBALS['csf_config'];
    
    if (!isset($config['GEOIP']) || !$config['GEOIP']) {
        return false;
    }
    
    // Check if GeoIP database exists
    if (!file_exists(GEOIP_DB) && !file_exists(GEOIP2_DB)) {
        csf_log('GeoIP database not found, downloading', 'INFO', 'GEOIP');
        return geoip_download_database();
    }
    
    return true;
}

/**
 * Download GeoIP database
 * 
 * @return bool
 */
function geoip_download_database() {
    $url = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz';
    
    csf_log('Downloading GeoIP database from: ' . $url, 'INFO', 'GEOIP');
    
    $tmp_file = CSF_TMP . '/geoip.tar.gz';
    
    // Download database
    $context = stream_context_create(array(
        'http' => array(
            'timeout' => 30,
        ),
    ));
    
    $content = @file_get_contents($url, false, $context);
    
    if (!$content) {
        csf_log('Failed to download GeoIP database', 'ERROR', 'GEOIP');
        return false;
    }
    
    // Save to temp file
    if (file_put_contents($tmp_file, $content) === false) {
        csf_log('Failed to save GeoIP database', 'ERROR', 'GEOIP');
        return false;
    }
    
    // Extract database
    $extract_dir = CSF_TMP . '/geoip';
    @mkdir($extract_dir, 0755, true);
    
    exec('cd ' . escapeshellarg($extract_dir) . ' && tar -xzf ' . escapeshellarg($tmp_file) . ' 2>/dev/null');
    
    // Find and copy the mmdb file
    $files = array();
    $cmd = 'find ' . escapeshellarg($extract_dir) . ' -name "*.mmdb" 2>/dev/null';
    exec($cmd, $files);
    
    if (!empty($files)) {
        copy($files[0], GEOIP2_DB);
        chmod(GEOIP2_DB, 0600);
        
        // Cleanup
        exec('rm -rf ' . escapeshellarg($extract_dir) . ' ' . escapeshellarg($tmp_file));
        
        csf_log('GeoIP database updated successfully', 'INFO', 'GEOIP');
        return true;
    }
    
    csf_log('GeoIP database file not found in archive', 'ERROR', 'GEOIP');
    return false;
}

/**
 * Get country code for IP address
 * 
 * @param string $ip IP address
 * @return string|bool Country code or false
 */
function geoip_get_country($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    
    // Try MaxMind GeoIP2
    if (file_exists(GEOIP2_DB)) {
        return geoip_get_country_mmdb($ip);
    }
    
    // Fallback to built-in function
    if (function_exists('geoip_country_code_by_name')) {
        $country = geoip_country_code_by_name($ip);
        return $country ? $country : false;
    }
    
    return false;
}

/**
 * Get country from MaxMind MMDB
 * 
 * @param string $ip IP address
 * @return string|bool Country code
 */
function geoip_get_country_mmdb($ip) {
    if (!class_exists('GeoIp2\\Database\\Reader')) {
        // Fallback to command line tool
        return geoip_get_country_cli($ip);
    }
    
    try {
        $reader = new \GeoIp2\Database\Reader(GEOIP2_DB);
        $record = $reader->country($ip);
        return strtoupper($record->country->isoCode);
    } catch (Exception $e) {
        csf_log('GeoIP lookup error: ' . $e->getMessage(), 'WARN', 'GEOIP');
        return false;
    }
}

/**
 * Get country using command line tool
 * 
 * @param string $ip IP address
 * @return string|bool Country code
 */
function geoip_get_country_cli($ip) {
    $output = array();
    
    // Try geoiplookup tool
    exec('geoiplookup ' . escapeshellarg($ip) . ' 2>/dev/null', $output);
    
    if (!empty($output) && preg_match('/GeoIP Country Edition: ([A-Z]{2})/', $output[0], $matches)) {
        return $matches[1];
    }
    
    return false;
}

/**
 * Block country by ISO code
 * 
 * @param string $country_code ISO country code (e.g. 'CN', 'RU')
 * @return bool
 */
function geoip_block_country($country_code) {
    $country_code = strtoupper($country_code);
    
    if (strlen($country_code) !== 2 || !ctype_alpha($country_code)) {
        csf_log('Invalid country code: ' . $country_code, 'WARN', 'GEOIP');
        return false;
    }
    
    // Add to blocked countries list
    $blocked_file = CSF_CONF . '/csf.geoip_blocked';
    
    $content = file_exists($blocked_file) ? file_get_contents($blocked_file) : '';
    
    if (strpos($content, $country_code) !== false) {
        return true; // Already blocked
    }
    
    $content .= $country_code . "\n";
    
    if (file_put_contents($blocked_file, $content) === false) {
        csf_log('Failed to add country block: ' . $country_code, 'ERROR', 'GEOIP');
        return false;
    }
    
    csf_log('Country blocked: ' . $country_code, 'INFO', 'GEOIP');
    return true;
}

/**
 * Get list of blocked countries
 * 
 * @return array Country codes
 */
function geoip_get_blocked_countries() {
    $blocked_file = CSF_CONF . '/csf.geoip_blocked';
    
    if (!file_exists($blocked_file)) {
        return array();
    }
    
    $countries = file($blocked_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    return array_map('strtoupper', array_filter($countries));
}

/**
 * Check if IP is from blocked country
 * 
 * @param string $ip IP address
 * @return bool
 */
function geoip_is_blocked($ip) {
    $country = geoip_get_country($ip);
    
    if (!$country) {
        return false;
    }
    
    $blocked = geoip_get_blocked_countries();
    
    return in_array($country, $blocked);
}

/**
 * Apply GeoIP blocks to firewall
 * 
 * @return int Number of IPs blocked
 */
function geoip_apply_blocks() {
    $blocked = 0;
    $blocked_countries = geoip_get_blocked_countries();
    
    if (empty($blocked_countries)) {
        return 0;
    }
    
    // Get list of all IPs and check against blocked countries
    $whitelist = $GLOBALS['csf_whitelist'];
    $blacklist = $GLOBALS['csf_blacklist'];
    
    // This would require additional IP range databases
    // For now, we apply rules through iptables with ipset for performance
    
    foreach ($blocked_countries as $country) {
        $ipset_name = 'csf_geoip_' . strtolower($country);
        
        // Create ipset for country
        exec('ipset create ' . escapeshellarg($ipset_name) . ' hash:ip 2>/dev/null');
        
        // Add block rule
        exec('iptables -I CSF_DENYIN -m set --match-set ' . escapeshellarg($ipset_name) . ' src -j REJECT');
    }
    
    csf_log('GeoIP blocks applied for countries: ' . implode(',', $blocked_countries), 'INFO', 'GEOIP');
    
    return count($blocked_countries);
}

/**
 * Get GeoIP statistics
 * 
 * @return array Statistics
 */
function geoip_get_stats() {
    $stats = array(
        'enabled' => geoip_init(),
        'database_file' => file_exists(GEOIP2_DB) ? GEOIP2_DB : GEOIP_DB,
        'database_exists' => file_exists(GEOIP2_DB) || file_exists(GEOIP_DB),
        'blocked_countries' => count(geoip_get_blocked_countries()),
        'last_updated' => filemtime(GEOIP2_DB) ?: 0,
    );
    
    return $stats;
}

/**
 * Update GeoIP database
 * 
 * @return bool
 */
function geoip_update_database() {
    return geoip_download_database();
}

/**
 * Unblock country
 * 
 * @param string $country_code Country code
 * @return bool
 */
function geoip_unblock_country($country_code) {
    $country_code = strtoupper($country_code);
    
    $blocked_file = CSF_CONF . '/csf.geoip_blocked';
    
    if (!file_exists($blocked_file)) {
        return true;
    }
    
    $lines = file($blocked_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $updated = array();
    $found = false;
    
    foreach ($lines as $line) {
        if (strtoupper(trim($line)) !== $country_code) {
            $updated[] = $line;
        } else {
            $found = true;
        }
    }
    
    if (!$found) {
        return true;
    }
    
    file_put_contents($blocked_file, implode("\n", $updated) . "\n");
    
    csf_log('Country unblocked: ' . $country_code, 'INFO', 'GEOIP');
    return true;
}
