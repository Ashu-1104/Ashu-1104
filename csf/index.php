<?php
/**
 * CSF Firewall - Web Interface
 * HTTP API and Web UI for managing firewall
 */

// Load CSF core modules
require_once __DIR__ . '/includes/csf.php';
require_once __DIR__ . '/includes/iptables.php';
require_once __DIR__ . '/includes/lfd.php';
require_once __DIR__ . '/includes/portscan.php';
require_once __DIR__ . '/includes/ddos.php';
require_once __DIR__ . '/includes/geoip.php';

// Set headers for API
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');

/**
 * API Route handler
 */
function csf_api_route() {
    $method = $_SERVER['REQUEST_METHOD'];
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $parts = array_filter(explode('/', $path));
    
    // Handle API requests
    if (isset($parts[2])) {
        $resource = $parts[2];
        $action = isset($parts[3]) ? $parts[3] : null;
        
        switch ($resource) {
            case 'firewall':
                return csf_api_firewall($method, $action);
                
            case 'allow':
                return csf_api_allow($method, $action);
                
            case 'deny':
                return csf_api_deny($method, $action);
                
            case 'status':
                return csf_api_status($method);
                
            case 'lfd':
                return csf_api_lfd($method, $action);
                
            case 'geoip':
                return csf_api_geoip($method, $action);
                
            case 'ddos':
                return csf_api_ddos($method, $action);
                
            case 'portscan':
                return csf_api_portscan($method, $action);
                
            default:
                return csf_api_error('Unknown resource: ' . $resource, 404);
        }
    }
    
    return csf_api_error('No resource specified', 400);
}

/**
 * Firewall API endpoints
 */
function csf_api_firewall($method, $action) {
    if ($method === 'POST') {
        switch ($action) {
            case 'restart':
                if (iptables_restart()) {
                    return csf_api_success('Firewall restarted');
                }
                return csf_api_error('Failed to restart firewall');
                
            case 'stop':
                if (iptables_stop()) {
                    return csf_api_success('Firewall stopped');
                }
                return csf_api_error('Failed to stop firewall');
                
            case 'enable':
                csf_set_config('ENABLED', '1');
                if (csf_save_config()) {
                    return csf_api_success('Firewall enabled');
                }
                return csf_api_error('Failed to enable firewall');
                
            case 'disable':
                csf_set_config('ENABLED', '0');
                if (csf_save_config()) {
                    return csf_api_success('Firewall disabled');
                }
                return csf_api_error('Failed to disable firewall');
                
            default:
                return csf_api_error('Unknown action: ' . $action, 400);
        }
    }
    
    if ($method === 'GET') {
        return csf_api_success('Firewall API', array(
            'version' => CSF_VERSION,
            'enabled' => csf_get_config('ENABLED') == 1,
            'config' => $GLOBALS['csf_config'],
        ));
    }
    
    return csf_api_error('Method not allowed', 405);
}

/**
 * Allow list API endpoints
 */
function csf_api_allow($method, $action) {
    if ($method === 'GET') {
        return csf_api_success('Allow list', array(
            'entries' => $GLOBALS['csf_whitelist'],
            'count' => count($GLOBALS['csf_whitelist']),
        ));
    }
    
    if ($method === 'POST') {
        $data = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($data['ip'])) {
            return csf_api_error('Missing IP address', 400);
        }
        
        $ip = $data['ip'];
        $comment = isset($data['comment']) ? $data['comment'] : '';
        
        if (iptables_add_allow($ip, $comment)) {
            return csf_api_success('IP added to allow list', array(
                'ip' => $ip,
                'comment' => $comment,
            ));
        }
        
        return csf_api_error('Failed to add IP to allow list');
    }
    
    return csf_api_error('Method not allowed', 405);
}

/**
 * Deny list API endpoints
 */
function csf_api_deny($method, $action) {
    if ($method === 'GET') {
        return csf_api_success('Deny list', array(
            'entries' => $GLOBALS['csf_blacklist'],
            'count' => count($GLOBALS['csf_blacklist']),
        ));
    }
    
    if ($method === 'POST') {
        $data = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($data['ip'])) {
            return csf_api_error('Missing IP address', 400);
        }
        
        $ip = $data['ip'];
        $comment = isset($data['comment']) ? $data['comment'] : '';
        
        if (iptables_add_deny($ip, $comment)) {
            return csf_api_success('IP added to deny list', array(
                'ip' => $ip,
                'comment' => $comment,
            ));
        }
        
        return csf_api_error('Failed to add IP to deny list');
    }
    
    return csf_api_error('Method not allowed', 405);
}

/**
 * Status API endpoint
 */
function csf_api_status($method) {
    if ($method === 'GET') {
        return csf_api_success('Firewall status', array(
            'firewall_enabled' => csf_get_config('ENABLED') == 1,
            'lfd_running' => lfd_is_running(),
            'allow_count' => count($GLOBALS['csf_whitelist']),
            'deny_count' => count($GLOBALS['csf_blacklist']),
            'version' => CSF_VERSION,
            'timestamp' => time(),
        ));
    }
    
    return csf_api_error('Method not allowed', 405);
}

/**
 * LFD API endpoints
 */
function csf_api_lfd($method, $action) {
    if ($method === 'GET') {
        if ($action === 'status') {
            $status = lfd_get_status();
            $logs = lfd_get_logs(10);
            
            return csf_api_success('LFD status', array(
                'running' => lfd_is_running(),
                'status' => $status,
                'recent_logs' => $logs,
            ));
        }
        
        if ($action === 'logs') {
            $logs = lfd_get_logs(100);
            return csf_api_success('LFD logs', array('logs' => $logs));
        }
        
        if ($action === 'failed_logins') {
            $attempts = lfd_get_failed_logins();
            return csf_api_success('Failed login attempts', array('attempts' => $attempts));
        }
    }
    
    if ($method === 'POST') {
        if ($action === 'start') {
            if (lfd_start()) {
                return csf_api_success('LFD daemon started');
            }
            return csf_api_error('Failed to start LFD daemon');
        }
        
        if ($action === 'stop') {
            if (lfd_stop()) {
                return csf_api_success('LFD daemon stopped');
            }
            return csf_api_error('Failed to stop LFD daemon');
        }
        
        if ($action === 'restart') {
            if (lfd_restart()) {
                return csf_api_success('LFD daemon restarted');
            }
            return csf_api_error('Failed to restart LFD daemon');
        }
    }
    
    return csf_api_error('Invalid LFD request', 400);
}

/**
 * GeoIP API endpoints
 */
function csf_api_geoip($method, $action) {
    if ($method === 'GET') {
        if ($action === 'status') {
            $stats = geoip_get_stats();
            return csf_api_success('GeoIP status', $stats);
        }
        
        if ($action === 'blocked') {
            $blocked = geoip_get_blocked_countries();
            return csf_api_success('Blocked countries', array('countries' => $blocked));
        }
    }
    
    if ($method === 'POST') {
        $data = json_decode(file_get_contents('php://input'), true);
        
        if ($action === 'block') {
            if (!isset($data['country'])) {
                return csf_api_error('Missing country code', 400);
            }
            
            if (geoip_block_country($data['country'])) {
                return csf_api_success('Country blocked: ' . $data['country']);
            }
            return csf_api_error('Failed to block country');
        }
        
        if ($action === 'unblock') {
            if (!isset($data['country'])) {
                return csf_api_error('Missing country code', 400);
            }
            
            if (geoip_unblock_country($data['country'])) {
                return csf_api_success('Country unblocked: ' . $data['country']);
            }
            return csf_api_error('Failed to unblock country');
        }
    }
    
    return csf_api_error('Invalid GeoIP request', 400);
}

/**
 * DDoS API endpoints
 */
function csf_api_ddos($method, $action) {
    if ($method === 'GET') {
        if ($action === 'status') {
            $status = ddos_get_status();
            return csf_api_success('DDoS status', $status);
        }
        
        if ($action === 'stats') {
            $stats = ddos_get_stats();
            return csf_api_success('DDoS statistics', $stats);
        }
    }
    
    if ($method === 'POST') {
        if ($action === 'block') {
            $blocked = ddos_auto_block();
            return csf_api_success('Auto-blocked IPs', array(
                'count' => count($blocked),
                'ips' => $blocked,
            ));
        }
    }
    
    return csf_api_error('Invalid DDoS request', 400);
}

/**
 * Port scan API endpoints
 */
function csf_api_portscan($method, $action) {
    if ($method === 'GET') {
        if ($action === 'recent') {
            $scans = pscan_get_recent(50);
            return csf_api_success('Recent port scans', array('scans' => $scans));
        }
        
        if ($action === 'patterns') {
            $patterns = pscan_analyze_patterns();
            return csf_api_success('Port scan patterns', $patterns);
        }
    }
    
    return csf_api_error('Invalid port scan request', 400);
}

/**
 * Helper: API success response
 */
function csf_api_success($message, $data = null) {
    http_response_code(200);
    echo json_encode(array(
        'success' => true,
        'message' => $message,
        'data' => $data,
        'timestamp' => time(),
    ));
    exit;
}

/**
 * Helper: API error response
 */
function csf_api_error($message, $code = 400) {
    http_response_code($code);
    echo json_encode(array(
        'success' => false,
        'error' => $message,
        'timestamp' => time(),
    ));
    exit;
}

// Route the API request
csf_api_route();
