<?php
/**
 * CSF REST API Module
 * Provides RESTful API interface for CSF operations
 */

/**
 * Initialize API routing
 * 
 * @param array $request Request data
 * @return array API response
 */
function csf_api_route($request) {
    // Get request method and path
    $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    $path = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '/';
    
    // Parse request body
    $body = file_get_contents('php://input');
    $data = json_decode($body, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        $data = array();
    }
    
    // Validate API key
    if (!csf_api_validate_key()) {
        return csf_api_response('Unauthorized', 401);
    }
    
    // Route requests
    $path = trim($path, '/');
    $parts = explode('/', $path);
    
    if (empty($parts[0])) {
        return csf_api_response(array('version' => '1.0', 'status' => 'online'));
    }
    
    $resource = $parts[0];
    $action = isset($parts[1]) ? $parts[1] : null;
    $param = isset($parts[2]) ? $parts[2] : null;
    
    // Route to handlers
    switch ($resource) {
        case 'status':
            return csf_api_status($method, $action);
        
        case 'rules':
            return csf_api_rules($method, $action, $param, $data);
        
        case 'ips':
            return csf_api_ips($method, $action, $param, $data);
        
        case 'blocklists':
            return csf_api_blocklists($method, $action, $param, $data);
        
        case 'geoip':
            return csf_api_geoip($method, $action, $param, $data);
        
        case 'stats':
            return csf_api_stats($method, $action);
        
        case 'logs':
            return csf_api_logs($method, $action, $param);
        
        default:
            return csf_api_response('Resource not found', 404);
    }
}

/**
 * Validate API key
 * 
 * @return bool
 */
function csf_api_validate_key() {
    $config = csf_config_get();
    
    if (empty($config['API_ENABLE']) || $config['API_ENABLE'] != 1) {
        return false;
    }
    
    // Get API key from headers or query string
    $api_key = null;
    
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (isset($headers['Authorization'])) {
            $auth = $headers['Authorization'];
            if (preg_match('/Bearer\s+(.+)/i', $auth, $matches)) {
                $api_key = $matches[1];
            }
        }
    }
    
    if (!$api_key && isset($_GET['api_key'])) {
        $api_key = $_GET['api_key'];
    }
    
    if (!$api_key) {
        return false;
    }
    
    // Validate API key
    $stored_key = isset($config['API_KEY']) ? $config['API_KEY'] : '';
    
    if (empty($stored_key)) {
        return false;
    }
    
    // Use hash_equals for timing-safe comparison
    if (function_exists('hash_equals')) {
        return hash_equals($stored_key, $api_key);
    } else {
        return $stored_key === $api_key;
    }
}

/**
 * Get firewall status via API
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @return array Response
 */
function csf_api_status($method, $action) {
    if ($method !== 'GET') {
        return csf_api_response('Method not allowed', 405);
    }
    
    $status = csf_stats_get_status();
    
    return csf_api_response(array(
        'firewall_status' => $status,
        'timestamp' => time()
    ));
}

/**
 * Handle rules API requests
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @param string $param Parameter
 * @param array $data Request data
 * @return array Response
 */
function csf_api_rules($method, $action, $param, $data) {
    if ($method === 'GET') {
        $rules = csf_iptables_get_rules();
        return csf_api_response(array('rules' => $rules));
    }
    
    if ($method === 'POST' && $action === 'add') {
        if (empty($data['port']) || empty($data['protocol'])) {
            return csf_api_response('Missing required fields', 400);
        }
        
        if (csf_ports_add_rule($data['port'], strtoupper($data['protocol']))) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to add rule', 500);
    }
    
    if ($method === 'DELETE' && !empty($param)) {
        if (csf_ports_remove_rule($param)) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to remove rule', 500);
    }
    
    return csf_api_response('Invalid action', 400);
}

/**
 * Handle IPs API requests
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @param string $param Parameter
 * @param array $data Request data
 * @return array Response
 */
function csf_api_ips($method, $action, $param, $data) {
    if ($method === 'GET') {
        if ($action === 'blocked') {
            $ips = csf_iptables_get_blocked_ips();
            return csf_api_response(array('blocked_ips' => $ips));
        } elseif ($action === 'allowed') {
            $ips = csf_iptables_get_allowed_ips();
            return csf_api_response(array('allowed_ips' => $ips));
        }
    }
    
    if ($method === 'POST' && $action === 'block') {
        if (empty($data['ip'])) {
            return csf_api_response('IP address required', 400);
        }
        
        $reason = isset($data['reason']) ? $data['reason'] : 'API block';
        
        if (csf_iptables_add_ip($data['ip'], 'BLOCK', $reason)) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to block IP', 500);
    }
    
    if ($method === 'POST' && $action === 'allow') {
        if (empty($data['ip'])) {
            return csf_api_response('IP address required', 400);
        }
        
        $reason = isset($data['reason']) ? $data['reason'] : 'API allow';
        
        if (csf_iptables_add_ip($data['ip'], 'ALLOW', $reason)) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to allow IP', 500);
    }
    
    if ($method === 'DELETE' && !empty($param)) {
        if (csf_iptables_remove_ip($param)) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to remove IP', 500);
    }
    
    return csf_api_response('Invalid action', 400);
}

/**
 * Handle blocklists API requests
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @param string $param Parameter
 * @param array $data Request data
 * @return array Response
 */
function csf_api_blocklists($method, $action, $param, $data) {
    if ($method === 'GET') {
        $blocklists = csf_blocklist_get_list();
        return csf_api_response(array('blocklists' => $blocklists));
    }
    
    if ($method === 'POST' && $action === 'update') {
        if (empty($param)) {
            return csf_api_response('Blocklist ID required', 400);
        }
        
        if (csf_blocklist_update($param)) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to update blocklist', 500);
    }
    
    return csf_api_response('Invalid action', 400);
}

/**
 * Handle GeoIP API requests
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @param string $param Parameter
 * @param array $data Request data
 * @return array Response
 */
function csf_api_geoip($method, $action, $param, $data) {
    if ($method === 'GET' && $action === 'lookup') {
        if (empty($param)) {
            return csf_api_response('IP address required', 400);
        }
        
        $country = csf_geoip_lookup($param);
        
        return csf_api_response(array(
            'ip' => $param,
            'country' => $country
        ));
    }
    
    if ($method === 'GET' && $action === 'blocked') {
        $countries = csf_geoip_get_blocked_countries();
        return csf_api_response(array('blocked_countries' => $countries));
    }
    
    if ($method === 'POST' && $action === 'block') {
        if (empty($data['country'])) {
            return csf_api_response('Country code required', 400);
        }
        
        if (csf_geoip_block_country($data['country'])) {
            return csf_api_response(array('status' => 'success'));
        }
        
        return csf_api_response('Failed to block country', 500);
    }
    
    return csf_api_response('Invalid action', 400);
}

/**
 * Handle statistics API requests
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @return array Response
 */
function csf_api_stats($method, $action) {
    if ($method !== 'GET') {
        return csf_api_response('Method not allowed', 405);
    }
    
    if ($action === 'status') {
        return csf_api_response(csf_stats_get_status());
    }
    
    if ($action === 'blocks') {
        return csf_api_response(csf_stats_get_blocks());
    }
    
    if ($action === 'report') {
        return csf_api_response(csf_stats_generate_report());
    }
    
    return csf_api_response(csf_stats_get_status());
}

/**
 * Handle logs API requests
 * 
 * @param string $method HTTP method
 * @param string $action Action
 * @param string $param Parameter
 * @return array Response
 */
function csf_api_logs($method, $action, $param) {
    if ($method !== 'GET') {
        return csf_api_response('Method not allowed', 405);
    }
    
    $lines = isset($param) ? (int)$param : 100;
    $lines = min($lines, 1000); // Limit to 1000 lines
    
    $log_file = CSF_VAR_DIR . '/log/csf.log';
    $logs = array();
    
    if (csf_file_exists($log_file)) {
        $handle = @fopen($log_file, 'r');
        if ($handle) {
            $all_lines = array();
            while (!feof($handle)) {
                $line = fgets($handle);
                if (!empty(trim($line))) {
                    $all_lines[] = trim($line);
                }
            }
            fclose($handle);
            
            // Get last N lines
            $logs = array_slice($all_lines, -$lines);
        }
    }
    
    return csf_api_response(array('logs' => $logs, 'count' => count($logs)));
}

/**
 * Send API response
 * 
 * @param mixed $data Response data
 * @param int $status HTTP status code
 * @return array Response array
 */
function csf_api_response($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json');
    header('X-API-Version: 1.0');
    
    $response = array(
        'status' => $status,
        'data' => $data,
        'timestamp' => time()
    );
    
    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    
    return $response;
}

/**
 * Rate limit API requests
 * 
 * @param string $identifier Client identifier (IP, API key, etc.)
 * @param int $max_requests Maximum requests
 * @param int $window Time window in seconds
 * @return bool True if within limits
 */
function csf_api_rate_limit($identifier, $max_requests = 100, $window = 3600) {
    $rate_file = CSF_VAR_DIR . '/api/rate_limit_' . md5($identifier) . '.json';
    $now = time();
    $cutoff = $now - $window;
    
    $requests = array();
    
    if (csf_file_exists($rate_file)) {
        $content = csf_file_read($rate_file);
        $data = json_decode($content, true);
        
        if (is_array($data)) {
            $requests = array_filter($data, function($ts) use ($cutoff) {
                return $ts > $cutoff;
            });
        }
    }
    
    $requests[] = $now;
    
    // Write updated requests
    csf_file_write($rate_file, json_encode($requests));
    
    return count($requests) <= $max_requests;
}
