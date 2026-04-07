#!/usr/bin/env php
<?php
/**
 * CSF Firewall - PHP Implementation of ConfigServer Firewall
 * Command-line interface equivalent to the original Perl 'csf' command
 * 
 * Usage: csf [options]
 */

// Load CSF core modules
require_once dirname(__DIR__) . '/includes/csf.php';
require_once dirname(__DIR__) . '/includes/iptables.php';
require_once dirname(__DIR__) . '/includes/lfd.php';
require_once dirname(__DIR__) . '/includes/portscan.php';
require_once dirname(__DIR__) . '/includes/ddos.php';
require_once dirname(__DIR__) . '/includes/geoip.php';

/**
 * Display usage information
 */
function csf_usage() {
    echo <<<'USAGE'
ConfigServer Firewall (CSF) - PHP Port
Version: 1.0

Usage: csf [OPTION]

OPTIONS:
  -r, --reload            Reload firewall rules
  -x, --stop              Stop firewall (remove all rules)
  -e, --enable            Enable firewall
  -d, --disable           Disable firewall
  -q, --query             Query firewall rules
  -a IP, --allow=IP       Allow IP address
  -d IP, --deny=IP        Deny/block IP address
  -dr IP                  Remove IP from deny list
  -ar IP                  Remove IP from allow list
  -g, --geoip             Show GeoIP status
  -l, --list              List allow/deny rules
  -s, --status            Show firewall status
  -c, --check             Check firewall configuration
  -u, --update            Update firewall rules
  
LFD OPTIONS:
  -L, --lfd-status        Show LFD daemon status
  -S                      Start LFD daemon
  -K                      Stop LFD daemon
  
PORT SCAN OPTIONS:
  -p, --portscan          Show port scan detection status
  
DDoS OPTIONS:
  -dd, --ddos-detect      Detect DDoS attacks
  -db, --ddos-block       Auto-block DDoS attackers
  
EXAMPLES:
  csf -r                  Reload firewall rules
  csf -a 192.168.1.1      Allow IP 192.168.1.1
  csf -d 10.0.0.1         Block IP 10.0.0.1
  csf -ar 192.168.1.1     Remove allow rule for IP
  csf -dr 10.0.0.1        Remove block rule for IP
  csf -L                  Show LFD status
  
USAGE;
    exit(0);
}

/**
 * Parse command-line arguments
 */
$options = getopt('r:xedqa:d:glscuLSpdddbhv', array(
    'reload',
    'stop',
    'enable',
    'disable',
    'query',
    'allow:',
    'deny:',
    'geoip',
    'list',
    'status',
    'check',
    'update',
    'lfd-status',
    'portscan',
    'ddos-detect',
    'ddos-block',
    'help',
    'version',
));

if (empty($options) || isset($options['h']) || isset($options['help'])) {
    csf_usage();
}

if (isset($options['v']) || isset($options['version'])) {
    echo "CSF Firewall (PHP Port) v" . CSF_VERSION . "\n";
    exit(0);
}

// Check if running as root
if (posix_geteuid() !== 0) {
    echo "ERROR: This script must be run as root\n";
    exit(1);
}

// Process commands
$handled = false;

// Firewall control commands
if (isset($options['r']) || isset($options['reload'])) {
    echo "Reloading firewall rules...\n";
    if (iptables_restart()) {
        echo "Firewall rules reloaded successfully\n";
    } else {
        echo "ERROR: Failed to reload firewall rules\n";
        exit(1);
    }
    $handled = true;
}

if (isset($options['x']) || isset($options['stop'])) {
    echo "Stopping firewall...\n";
    if (iptables_stop()) {
        echo "Firewall stopped\n";
    } else {
        echo "ERROR: Failed to stop firewall\n";
        exit(1);
    }
    $handled = true;
}

if (isset($options['e']) || isset($options['enable'])) {
    echo "Enabling firewall...\n";
    csf_set_config('ENABLED', '1');
    if (csf_save_config() && iptables_apply_rules()) {
        echo "Firewall enabled\n";
    } else {
        echo "ERROR: Failed to enable firewall\n";
        exit(1);
    }
    $handled = true;
}

if (isset($options['d']) || isset($options['disable'])) {
    echo "Disabling firewall...\n";
    csf_set_config('ENABLED', '0');
    if (csf_save_config()) {
        echo "Firewall disabled\n";
    } else {
        echo "ERROR: Failed to disable firewall\n";
        exit(1);
    }
    $handled = true;
}

// IP management commands
if (isset($options['a']) || isset($options['allow'])) {
    $ip = isset($options['a']) ? $options['a'] : $options['allow'];
    
    echo "Adding IP to allow list: $ip\n";
    if (iptables_add_allow($ip, 'Manual allow')) {
        echo "IP added to allow list\n";
    } else {
        echo "ERROR: Failed to add IP to allow list\n";
        exit(1);
    }
    $handled = true;
}

if (isset($options['deny'])) {
    $ip = $options['deny'];
    
    echo "Adding IP to deny list: $ip\n";
    if (iptables_add_deny($ip, 'Manual deny')) {
        echo "IP added to deny list\n";
    } else {
        echo "ERROR: Failed to add IP to deny list\n";
        exit(1);
    }
    $handled = true;
}

if (isset($options['ar'])) {
    $ip = $options['ar'];
    
    echo "Removing IP from allow list: $ip\n";
    if (iptables_remove_allow($ip)) {
        echo "IP removed from allow list\n";
    } else {
        echo "IP not found in allow list\n";
    }
    $handled = true;
}

if (isset($options['dr'])) {
    $ip = $options['dr'];
    
    echo "Removing IP from deny list: $ip\n";
    if (iptables_remove_deny($ip)) {
        echo "IP removed from deny list\n";
    } else {
        echo "IP not found in deny list\n";
    }
    $handled = true;
}

// Status commands
if (isset($options['l']) || isset($options['list'])) {
    echo "\n=== ALLOW LIST ===\n";
    foreach ($GLOBALS['csf_whitelist'] as $entry) {
        echo $entry['ip'] . ' | ' . $entry['comment'] . ' | ' . $entry['date'] . "\n";
    }
    
    echo "\n=== DENY LIST ===\n";
    foreach ($GLOBALS['csf_blacklist'] as $entry) {
        echo $entry['ip'] . ' | ' . $entry['comment'] . ' | ' . $entry['date'] . "\n";
    }
    $handled = true;
}

if (isset($options['s']) || isset($options['status'])) {
    echo "\n=== CSF FIREWALL STATUS ===\n";
    echo "Version: " . CSF_VERSION . "\n";
    echo "Enabled: " . (csf_get_config('ENABLED') ? 'Yes' : 'No') . "\n";
    echo "Status: " . (lfd_is_running() ? 'Running' : 'Stopped') . "\n";
    echo "Allow list entries: " . count($GLOBALS['csf_whitelist']) . "\n";
    echo "Deny list entries: " . count($GLOBALS['csf_blacklist']) . "\n";
    
    // LFD status
    if (lfd_is_running()) {
        $lfd_status = lfd_get_status();
        echo "LFD PID: " . ($lfd_status['pid'] ?: 'N/A') . "\n";
    }
    $handled = true;
}

// LFD commands
if (isset($options['L']) || isset($options['lfd-status'])) {
    echo "\n=== LFD DAEMON STATUS ===\n";
    if (lfd_is_running()) {
        echo "Status: Running\n";
        $status = lfd_get_status();
        echo "PID: " . $status['pid'] . "\n";
        echo "Memory: " . $status['memory'] . " KB\n";
        
        $logs = lfd_get_logs(5);
        if (!empty($logs)) {
            echo "\nRecent log entries:\n";
            foreach ($logs as $log) {
                echo "  " . $log . "\n";
            }
        }
    } else {
        echo "Status: Not running\n";
    }
    $handled = true;
}

if (isset($options['S'])) {
    echo "Starting LFD daemon...\n";
    if (lfd_start()) {
        echo "LFD daemon started\n";
    } else {
        echo "ERROR: Failed to start LFD daemon\n";
        exit(1);
    }
    $handled = true;
}

if (isset($options['K'])) {
    echo "Stopping LFD daemon...\n";
    if (lfd_stop()) {
        echo "LFD daemon stopped\n";
    } else {
        echo "ERROR: Failed to stop LFD daemon\n";
        exit(1);
    }
    $handled = true;
}

// Port scan detection
if (isset($options['p']) || isset($options['portscan'])) {
    echo "\n=== PORT SCAN DETECTION ===\n";
    $scans = pscan_get_recent(10);
    if (empty($scans)) {
        echo "No recent port scans detected\n";
    } else {
        foreach ($scans as $scan) {
            echo "IP: " . $scan['ip'] . " | Ports: " . implode(',', $scan['ports']) . " | Time: " . date('Y-m-d H:i:s', $scan['timestamp']) . "\n";
        }
    }
    $handled = true;
}

// DDoS detection
if (isset($options['dd']) || isset($options['ddos-detect'])) {
    echo "\n=== DDoS DETECTION ===\n";
    $status = ddos_get_status();
    
    if ($status['syn_flood_detected']) {
        echo "SYN Flood: DETECTED\n";
    } else {
        echo "SYN Flood: Normal\n";
    }
    
    if ($status['http_flood_detected']) {
        echo "HTTP Flood: DETECTED\n";
    } else {
        echo "HTTP Flood: Normal\n";
    }
    
    if (!empty($status['attacking_ips'])) {
        echo "Attacking IPs: " . implode(', ', $status['attacking_ips']) . "\n";
    }
    $handled = true;
}

if (isset($options['db']) || isset($options['ddos-block'])) {
    echo "Auto-blocking DDoS attackers...\n";
    $blocked = ddos_auto_block();
    if (empty($blocked)) {
        echo "No DDoS attackers detected\n";
    } else {
        echo "Blocked " . count($blocked) . " attacking IP(s): " . implode(', ', $blocked) . "\n";
    }
    $handled = true;
}

if (!$handled) {
    echo "ERROR: No action specified. Use -h for help.\n";
    exit(1);
}

exit(0);
