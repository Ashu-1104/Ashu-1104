<?php
/**
 * CSF Admin Module
 * Administrative functions for firewall management
 */

/**
 * Enable firewall
 * 
 * @return bool
 */
function csf_admin_enable() {
    $config = csf_config_get();
    $config['ENABLED'] = 1;
    
    if (csf_config_write($config)) {
        csf_log('Firewall enabled', 'ADMIN');
        csf_lfd_send_command('ENABLE', '');
        return true;
    }
    
    return false;
}

/**
 * Disable firewall
 * 
 * @return bool
 */
function csf_admin_disable() {
    $config = csf_config_get();
    $config['ENABLED'] = 0;
    
    if (csf_config_write($config)) {
        csf_log('Firewall disabled', 'ADMIN');
        csf_lfd_send_command('DISABLE', '');
        return true;
    }
    
    return false;
}

/**
 * Enable LFD daemon
 * 
 * @return bool
 */
function csf_admin_enable_lfd() {
    $config = csf_config_get();
    $config['LFD_ENABLE'] = 1;
    
    if (csf_config_write($config)) {
        csf_log('LFD enabled', 'ADMIN');
        csf_lfd_send_command('LFD_ENABLE', '');
        return true;
    }
    
    return false;
}

/**
 * Disable LFD daemon
 * 
 * @return bool
 */
function csf_admin_disable_lfd() {
    $config = csf_config_get();
    $config['LFD_ENABLE'] = 0;
    
    if (csf_config_write($config)) {
        csf_log('LFD disabled', 'ADMIN');
        csf_lfd_send_command('LFD_DISABLE', '');
        return true;
    }
    
    return false;
}

/**
 * Restart firewall
 * 
 * @return bool
 */
function csf_admin_restart() {
    // Flush existing rules
    csf_iptables_flush();
    
    // Reload configuration
    $config = csf_config_get();
    
    // Reapply rules
    csf_iptables_apply_all();
    
    csf_log('Firewall restarted', 'ADMIN');
    csf_lfd_send_command('RESTART', '');
    
    return true;
}

/**
 * Add user
 * 
 * @param string $username Username
 * @param string $password Password
 * @param string $role Role (admin, user, readonly)
 * @return bool
 */
function csf_admin_add_user($username, $password, $role = 'user') {
    if (empty($username) || empty($password)) {
        return false;
    }
    
    // Validate username
    if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) {
        csf_log('Invalid username format: ' . $username, 'ADMIN', 'WARN');
        return false;
    }
    
    // Validate role
    if (!in_array($role, array('admin', 'user', 'readonly'))) {
        csf_log('Invalid role: ' . $role, 'ADMIN', 'WARN');
        return false;
    }
    
    // Get users file
    $users_file = CSF_CONFIG_DIR . '/users.json';
    $users = array();
    
    if (csf_file_exists($users_file)) {
        $content = csf_file_read($users_file);
        $users = json_decode($content, true);
        if (!is_array($users)) {
            $users = array();
        }
    }
    
    // Check if user exists
    if (isset($users[$username])) {
        csf_log('User already exists: ' . $username, 'ADMIN', 'WARN');
        return false;
    }
    
    // Hash password using bcrypt
    $password_hash = password_hash($password, PASSWORD_BCRYPT, array('cost' => 12));
    
    // Add user
    $users[$username] = array(
        'password' => $password_hash,
        'role' => $role,
        'created' => time(),
        'last_login' => 0,
        'enabled' => 1
    );
    
    if (csf_file_write($users_file, json_encode($users, JSON_PRETTY_PRINT))) {
        csf_log('User added: ' . $username, 'ADMIN');
        return true;
    }
    
    return false;
}

/**
 * Delete user
 * 
 * @param string $username Username
 * @return bool
 */
function csf_admin_delete_user($username) {
    if (empty($username)) {
        return false;
    }
    
    $users_file = CSF_CONFIG_DIR . '/users.json';
    
    if (!csf_file_exists($users_file)) {
        return false;
    }
    
    $content = csf_file_read($users_file);
    $users = json_decode($content, true);
    
    if (!is_array($users) || !isset($users[$username])) {
        return false;
    }
    
    unset($users[$username]);
    
    if (csf_file_write($users_file, json_encode($users, JSON_PRETTY_PRINT))) {
        csf_log('User deleted: ' . $username, 'ADMIN');
        return true;
    }
    
    return false;
}

/**
 * Update user password
 * 
 * @param string $username Username
 * @param string $password New password
 * @return bool
 */
function csf_admin_update_password($username, $password) {
    if (empty($username) || empty($password)) {
        return false;
    }
    
    $users_file = CSF_CONFIG_DIR . '/users.json';
    
    if (!csf_file_exists($users_file)) {
        return false;
    }
    
    $content = csf_file_read($users_file);
    $users = json_decode($content, true);
    
    if (!is_array($users) || !isset($users[$username])) {
        return false;
    }
    
    $password_hash = password_hash($password, PASSWORD_BCRYPT, array('cost' => 12));
    $users[$username]['password'] = $password_hash;
    
    if (csf_file_write($users_file, json_encode($users, JSON_PRETTY_PRINT))) {
        csf_log('User password updated: ' . $username, 'ADMIN');
        return true;
    }
    
    return false;
}

/**
 * Verify user credentials
 * 
 * @param string $username Username
 * @param string $password Password
 * @return bool
 */
function csf_admin_verify_user($username, $password) {
    if (empty($username) || empty($password)) {
        return false;
    }
    
    $users_file = CSF_CONFIG_DIR . '/users.json';
    
    if (!csf_file_exists($users_file)) {
        return false;
    }
    
    $content = csf_file_read($users_file);
    $users = json_decode($content, true);
    
    if (!is_array($users) || !isset($users[$username])) {
        return false;
    }
    
    $user = $users[$username];
    
    // Check if user is enabled
    if (empty($user['enabled'])) {
        return false;
    }
    
    // Verify password
    if (!password_verify($password, $user['password'])) {
        csf_log('Failed login attempt for user: ' . $username, 'ADMIN', 'WARN');
        return false;
    }
    
    // Update last login
    $users[$username]['last_login'] = time();
    csf_file_write($users_file, json_encode($users, JSON_PRETTY_PRINT));
    
    return true;
}

/**
 * Get user role
 * 
 * @param string $username Username
 * @return string|false User role or false
 */
function csf_admin_get_user_role($username) {
    if (empty($username)) {
        return false;
    }
    
    $users_file = CSF_CONFIG_DIR . '/users.json';
    
    if (!csf_file_exists($users_file)) {
        return false;
    }
    
    $content = csf_file_read($users_file);
    $users = json_decode($content, true);
    
    if (!is_array($users) || !isset($users[$username])) {
        return false;
    }
    
    return isset($users[$username]['role']) ? $users[$username]['role'] : 'user';
}

/**
 * List all users
 * 
 * @return array
 */
function csf_admin_list_users() {
    $users_file = CSF_CONFIG_DIR . '/users.json';
    $users = array();
    
    if (csf_file_exists($users_file)) {
        $content = csf_file_read($users_file);
        $user_data = json_decode($content, true);
        
        if (is_array($user_data)) {
            foreach ($user_data as $username => $data) {
                // Don't return password hashes
                unset($data['password']);
                $users[$username] = $data;
            }
        }
    }
    
    return $users;
}

/**
 * Get audit log
 * 
 * @param int $limit Number of entries
 * @return array
 */
function csf_admin_get_audit_log($limit = 100) {
    $log_file = CSF_VAR_DIR . '/log/audit.log';
    $logs = array();
    
    if (!csf_file_exists($log_file)) {
        return array();
    }
    
    $handle = @fopen($log_file, 'r');
    if (!$handle) {
        return array();
    }
    
    $all_lines = array();
    while (!feof($handle)) {
        $line = fgets($handle);
        if (!empty(trim($line))) {
            $all_lines[] = trim($line);
        }
    }
    fclose($handle);
    
    // Get last N lines
    $logs = array_slice($all_lines, -$limit);
    
    return array_reverse($logs);
}

/**
 * Clear audit log
 * 
 * @return bool
 */
function csf_admin_clear_audit_log() {
    $log_file = CSF_VAR_DIR . '/log/audit.log';
    
    if (csf_file_exists($log_file)) {
        csf_file_write($log_file, '');
    }
    
    csf_log('Audit log cleared', 'ADMIN');
    return true;
}

/**
 * Get configuration
 * 
 * @return array
 */
function csf_admin_get_config() {
    return csf_config_get();
}

/**
 * Update configuration
 * 
 * @param array $updates Configuration updates
 * @return bool
 */
function csf_admin_update_config($updates) {
    if (!is_array($updates) || empty($updates)) {
        return false;
    }
    
    $config = csf_config_get();
    
    // List of allowed config keys to update
    $allowed_keys = array(
        'ENABLED', 'LFD_ENABLE', 'PT_ENABLE', 'PT_LIMIT', 'PT_BLOCK',
        'DDOS_ENABLE', 'DDOS_LIMIT', 'DDOS_BLOCK',
        'GEOIP_ENABLE', 'GEOIP_WHITELIST', 'GEOIP_BLACKLIST',
        'API_ENABLE', 'HTTP_FLOOD_ENABLE', 'HTTP_FLOOD_LIMIT'
    );
    
    $modified = false;
    
    foreach ($updates as $key => $value) {
        if (!in_array($key, $allowed_keys)) {
            csf_log('Attempted to update restricted config: ' . $key, 'ADMIN', 'WARN');
            continue;
        }
        
        if ($config[$key] !== $value) {
            $config[$key] = $value;
            $modified = true;
        }
    }
    
    if ($modified) {
        if (csf_config_write($config)) {
            csf_log('Configuration updated', 'ADMIN');
            csf_lfd_send_command('CONFIG_UPDATE', '');
            return true;
        }
    }
    
    return $modified;
}

/**
 * Get system information
 * 
 * @return array
 */
function csf_admin_get_system_info() {
    return array(
        'os' => php_uname(),
        'php_version' => phpversion(),
        'php_sapi' => php_sapi_name(),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'disk_usage' => csf_admin_get_disk_usage()
    );
}

/**
 * Get disk usage
 * 
 * @return array
 */
function csf_admin_get_disk_usage() {
    $basepath = CSF_BASE_DIR;
    
    $total = 0;
    $count = 0;
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($basepath, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $total += $file->getSize();
            $count++;
        }
    }
    
    return array(
        'total_size' => $total,
        'formatted_size' => csf_format_bytes($total),
        'file_count' => $count
    );
}

/**
 * Format bytes to human readable
 * 
 * @param int $bytes Number of bytes
 * @param int $precision Precision
 * @return string
 */
function csf_format_bytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    
    return round($bytes, $precision) . ' ' . $units[$pow];
}
