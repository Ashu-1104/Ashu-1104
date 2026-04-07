<?php
/**
 * CSF Blocklists Module
 * Manages third-party IP blocklists and blacklists
 */

/**
 * Get list of configured blocklists
 * 
 * @return array Blocklists
 */
function csf_blocklist_get_list() {
    $blocklist_file = CSF_CONFIG_DIR . '/blocklists.json';
    
    if (!csf_file_exists($blocklist_file)) {
        return csf_blocklist_get_defaults();
    }
    
    $content = csf_file_read($blocklist_file);
    $blocklists = json_decode($content, true);
    
    if (!is_array($blocklists)) {
        return csf_blocklist_get_defaults();
    }
    
    return $blocklists;
}

/**
 * Get default blocklists
 * 
 * @return array Default blocklists
 */
function csf_blocklist_get_defaults() {
    return array(
        'abuse_net' => array(
            'name' => 'AbuseIPDB',
            'url' => 'https://www.abuseipdb.com/api/v2/download',
            'type' => 'ip_list',
            'enabled' => 0,
            'update_interval' => 86400,
            'last_update' => 0,
            'count' => 0
        ),
        'stopforumspam' => array(
            'name' => 'StopForumSpam',
            'url' => 'http://www.stopforumspam.com/downloads/toxic_ips.txt',
            'type' => 'ip_list',
            'enabled' => 0,
            'update_interval' => 86400,
            'last_update' => 0,
            'count' => 0
        ),
        'spamhaus_drop' => array(
            'name' => 'Spamhaus DROP',
            'url' => 'https://www.spamhaus.org/drop/drop.txt',
            'type' => 'cidr_list',
            'enabled' => 0,
            'update_interval' => 86400,
            'last_update' => 0,
            'count' => 0
        ),
        'maxmind_geoip' => array(
            'name' => 'MaxMind GeoIP',
            'url' => 'https://geoip.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip',
            'type' => 'geoip',
            'enabled' => 0,
            'update_interval' => 604800,
            'last_update' => 0,
            'count' => 0
        )
    );
}

/**
 * Add custom blocklist
 * 
 * @param string $id Blocklist ID
 * @param array $data Blocklist data
 * @return bool
 */
function csf_blocklist_add($id, $data) {
    if (empty($id) || !is_array($data)) {
        return false;
    }
    
    if (empty($data['name']) || empty($data['url'])) {
        csf_log('Missing required blocklist fields', 'BLOCKLIST', 'WARN');
        return false;
    }
    
    $blocklists = csf_blocklist_get_list();
    
    if (isset($blocklists[$id])) {
        csf_log('Blocklist already exists: ' . $id, 'BLOCKLIST', 'WARN');
        return false;
    }
    
    $data['enabled'] = isset($data['enabled']) ? (int)$data['enabled'] : 0;
    $data['update_interval'] = isset($data['update_interval']) ? (int)$data['update_interval'] : 86400;
    $data['last_update'] = 0;
    $data['count'] = 0;
    
    $blocklists[$id] = $data;
    
    if (csf_blocklist_save($blocklists)) {
        csf_log('Blocklist added: ' . $id, 'BLOCKLIST');
        return true;
    }
    
    return false;
}

/**
 * Remove blocklist
 * 
 * @param string $id Blocklist ID
 * @return bool
 */
function csf_blocklist_remove($id) {
    if (empty($id)) {
        return false;
    }
    
    $blocklists = csf_blocklist_get_list();
    
    if (!isset($blocklists[$id])) {
        return false;
    }
    
    unset($blocklists[$id]);
    
    if (csf_blocklist_save($blocklists)) {
        csf_log('Blocklist removed: ' . $id, 'BLOCKLIST');
        return true;
    }
    
    return false;
}

/**
 * Update blocklist from remote source
 * 
 * @param string $id Blocklist ID
 * @return bool
 */
function csf_blocklist_update($id) {
    if (empty($id)) {
        return false;
    }
    
    $blocklists = csf_blocklist_get_list();
    
    if (!isset($blocklists[$id])) {
        csf_log('Blocklist not found: ' . $id, 'BLOCKLIST', 'WARN');
        return false;
    }
    
    $blocklist = $blocklists[$id];
    
    if (empty($blocklist['url'])) {
        return false;
    }
    
    $content = csf_blocklist_download($blocklist['url']);
    
    if (!$content) {
        csf_log('Failed to download blocklist: ' . $id, 'BLOCKLIST', 'ERROR');
        return false;
    }
    
    $ips = csf_blocklist_parse($content, $blocklist['type']);
    
    if (empty($ips)) {
        csf_log('No IPs found in blocklist: ' . $id, 'BLOCKLIST', 'WARN');
        return false;
    }
    
    $blocklist_data_file = CSF_VAR_DIR . '/blocklists/' . $id . '.json';
    
    if (!is_dir(dirname($blocklist_data_file))) {
        @mkdir(dirname($blocklist_data_file), 0755, true);
    }
    
    $data = array(
        'id' => $id,
        'name' => $blocklist['name'],
        'type' => $blocklist['type'],
        'ips' => $ips,
        'count' => count($ips),
        'updated' => time()
    );
    
    if (!csf_file_write($blocklist_data_file, json_encode($data, JSON_PRETTY_PRINT))) {
        csf_log('Failed to write blocklist data: ' . $id, 'BLOCKLIST', 'ERROR');
        return false;
    }
    
    $blocklists[$id]['last_update'] = time();
    $blocklists[$id]['count'] = count($ips);
    
    if (csf_blocklist_save($blocklists)) {
        csf_log('Blocklist updated: ' . $id . ' (' . count($ips) . ' IPs)', 'BLOCKLIST');
        
        if ($blocklist['enabled']) {
            csf_blocklist_apply($id);
        }
        
        return true;
    }
    
    return false;
}

/**
 * Download blocklist content
 * 
 * @param string $url Blocklist URL
 * @return string|false Content or false
 */
function csf_blocklist_download($url) {
    $context = stream_context_create(array(
        'http' => array(
            'timeout' => 30,
            'user_agent' => 'CSF-Firewall/1.0',
            'follow_location' => 1,
            'max_redirects' => 5
        )
    ));
    
    $content = @file_get_contents($url, false, $context);
    
    return $content;
}

/**
 * Parse blocklist content
 * 
 * @param string $content List content
 * @param string $type List type (ip_list, cidr_list, geoip)
 * @return array Parsed IPs
 */
function csf_blocklist_parse($content, $type = 'ip_list') {
    $ips = array();
    
    if ($type === 'ip_list') {
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || substr($line, 0, 1) === '#') {
                continue;
            }
            
            if (csf_validate_ip($line)) {
                $ips[] = $line;
            }
        }
    } elseif ($type === 'cidr_list') {
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || substr($line, 0, 1) === ';') {
                continue;
            }
            
            if (csf_validate_cidr($line)) {
                $ips[] = $line;
            }
        }
    }
    
    return array_unique($ips);
}

/**
 * Apply blocklist to firewall
 * 
 * @param string $id Blocklist ID
 * @return bool
 */
function csf_blocklist_apply($id) {
    $blocklist_data_file = CSF_VAR_DIR . '/blocklists/' . $id . '.json';
    
    if (!csf_file_exists($blocklist_data_file)) {
        return false;
    }
    
    $content = csf_file_read($blocklist_data_file);
    $data = json_decode($content, true);
    
    if (!is_array($data) || empty($data['ips'])) {
        return false;
    }
    
    $reason = 'Blocklist: ' . $data['name'];
    $added = 0;
    
    foreach ($data['ips'] as $ip) {
        if (csf_iptables_add_ip($ip, 'BLOCK', $reason)) {
            $added++;
        }
    }
    
    csf_log('Applied blocklist ' . $id . ': ' . $added . ' IPs blocked', 'BLOCKLIST');
    
    return true;
}

/**
 * Remove blocklist from firewall
 * 
 * @param string $id Blocklist ID
 * @return bool
 */
function csf_blocklist_remove_rules($id) {
    $blocklist_data_file = CSF_VAR_DIR . '/blocklists/' . $id . '.json';
    
    if (!csf_file_exists($blocklist_data_file)) {
        return false;
    }
    
    $content = csf_file_read($blocklist_data_file);
    $data = json_decode($content, true);
    
    if (!is_array($data) || empty($data['ips'])) {
        return false;
    }
    
    $removed = 0;
    
    foreach ($data['ips'] as $ip) {
        if (csf_iptables_remove_ip($ip)) {
            $removed++;
        }
    }
    
    csf_log('Removed blocklist ' . $id . ': ' . $removed . ' IPs unblocked', 'BLOCKLIST');
    
    return true;
}

/**
 * Get blocklist statistics
 * 
 * @return array Statistics
 */
function csf_blocklist_get_stats() {
    $blocklists = csf_blocklist_get_list();
    $stats = array(
        'total_lists' => count($blocklists),
        'enabled' => 0,
        'total_ips' => 0,
        'last_update' => 0,
        'lists' => array()
    );
    
    foreach ($blocklists as $id => $list) {
        if ($list['enabled']) {
            $stats['enabled']++;
        }
        
        $stats['total_ips'] += isset($list['count']) ? $list['count'] : 0;
        
        if (isset($list['last_update']) && $list['last_update'] > $stats['last_update']) {
            $stats['last_update'] = $list['last_update'];
        }
        
        $stats['lists'][$id] = array(
            'name' => $list['name'],
            'enabled' => (int)$list['enabled'],
            'ips' => isset($list['count']) ? $list['count'] : 0,
            'last_update' => isset($list['last_update']) ? $list['last_update'] : 0
        );
    }
    
    return $stats;
}

/**
 * Save blocklists configuration
 * 
 * @param array $blocklists Blocklists data
 * @return bool
 */
function csf_blocklist_save($blocklists) {
    $blocklist_file = CSF_CONFIG_DIR . '/blocklists.json';
    
    return csf_file_write($blocklist_file, json_encode($blocklists, JSON_PRETTY_PRINT));
}

/**
 * Auto-update all enabled blocklists
 * 
 * @return array Update results
 */
function csf_blocklist_auto_update() {
    $blocklists = csf_blocklist_get_list();
    $results = array();
    $now = time();
    
    foreach ($blocklists as $id => $list) {
        if (!$list['enabled']) {
            continue;
        }
        
        $next_update = $list['last_update'] + $list['update_interval'];
        
        if ($now < $next_update) {
            continue;
        }
        
        $results[$id] = csf_blocklist_update($id);
    }
    
    return $results;
}

/**
 * Cleanup old blocklist data
 * 
 * @return int Number of cleaned files
 */
function csf_blocklist_cleanup() {
    $blocklists_dir = CSF_VAR_DIR . '/blocklists';
    $blocklists = csf_blocklist_get_list();
    $cleaned = 0;
    
    if (!is_dir($blocklists_dir)) {
        return 0;
    }
    
    $files = scandir($blocklists_dir);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }
        
        $file_path = $blocklists_dir . '/' . $file;
        $id = str_replace('.json', '', $file);
        
        if (!isset($blocklists[$id])) {
            if (@unlink($file_path)) {
                $cleaned++;
            }
        }
    }
    
    if ($cleaned > 0) {
        csf_log('Cleaned ' . $cleaned . ' blocklist files', 'BLOCKLIST');
    }
    
    return $cleaned;
}

