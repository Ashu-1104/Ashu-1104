# CSF PHP Fork - Quick Start Guide

## Installation

### 1. Directory Setup
```bash
mkdir -p /etc/csf
mkdir -p /var/lib/csf/cmd
mkdir -p /var/log/csf
chmod 755 /etc/csf /var/lib/csf /var/log/csf
```

### 2. Copy Files
```bash
cp -r csf /path/to/webuzo/modules/
cp csf/includes/* /path/to/webuzo/firewall/includes/
```

### 3. Set Permissions
```bash
chmod 644 /etc/csf/csf.conf
chmod 644 /etc/csf/csf.allow
chmod 644 /etc/csf/csf.deny
chmod 755 /var/lib/csf/cmd
```

## Basic Usage

### Initialize CSF
```php
<?php
require_once '/path/to/csf/includes/csf.core.php';
csf_init();
?>
```

### Enable Firewall
```php
<?php
csf_admin_enable();
?>
```

### Disable Firewall
```php
<?php
csf_admin_disable();
?>
```

### Block an IP
```php
<?php
csf_iptables_add_ip('1.2.3.4', 'BLOCK', 'Malicious activity');
?>
```

### Whitelist an IP
```php
<?php
csf_iptables_add_ip('192.168.1.100', 'ALLOW', 'Local trusted device');
?>
```

### Unblock an IP
```php
<?php
csf_iptables_remove_ip('1.2.3.4');
?>
```

### Get Blocked IPs
```php
<?php
$blocked = csf_iptables_get_blocked_ips();
foreach ($blocked as $ip => $reason) {
    echo "$ip: $reason\n";
}
?>
```

### Get Firewall Status
```php
<?php
$status = csf_stats_get_status();
echo "Blocked IPs: " . $status['blocked_ips'] . "\n";
echo "Firewall: " . ($status['firewall_enabled'] ? 'Enabled' : 'Disabled') . "\n";
?>
```

## REST API Usage

### Get Status
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://your-domain.com/csf/api/status
```

### Block an IP
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","reason":"Suspicious"}' \
  https://your-domain.com/csf/api/ips/block
```

### Get Blocked IPs
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://your-domain.com/csf/api/ips/blocked
```

### Enable Port Scanning Detection
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"PT_ENABLE":1}' \
  https://your-domain.com/csf/api/config
```

### Check GeoIP for IP
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://your-domain.com/csf/api/geoip/lookup/1.2.3.4
```

### Block a Country
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"country":"CN"}' \
  https://your-domain.com/csf/api/geoip/block
```

### Get Statistics
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://your-domain.com/csf/api/stats/report
```

## Configuration

Edit `/etc/csf/csf.conf`:

```ini
# Enable firewall
ENABLED=1

# Enable LFD daemon
LFD_ENABLE=1

# Port scanning
PT_ENABLE=1
PT_LIMIT=10
PT_BLOCK=1

# DDoS protection
DDOS_ENABLE=1
DDOS_LIMIT=100

# API access
API_ENABLE=1
API_KEY=your_secret_key_here
```

## Admin Functions

### Create Admin User
```php
<?php
csf_admin_add_user('admin', 'password', 'admin');
?>
```

### Change Password
```php
<?php
csf_admin_update_password('admin', 'newpassword');
?>
```

### List Users
```php
<?php
$users = csf_admin_list_users();
foreach ($users as $username => $data) {
    echo $username . " (" . $data['role'] . ")\n";
}
?>
```

### Get Audit Log
```php
<?php
$logs = csf_admin_get_audit_log(50);
foreach ($logs as $log) {
    echo $log . "\n";
}
?>
```

## Port Management

### Add Port Rule
```php
<?php
csf_ports_add_rule(22, 'TCP');  // SSH
csf_ports_add_rule(80, 'TCP');  // HTTP
csf_ports_add_rule(443, 'TCP'); // HTTPS
?>
```

### Remove Port Rule
```php
<?php
csf_ports_remove_rule('25/TCP'); // Remove SMTP
?>
```

## Blocklist Management

### Enable Blocklist
```php
<?php
$blocklists = csf_blocklist_get_list();
$blocklists['spamhaus_drop']['enabled'] = 1;
csf_blocklist_save($blocklists);
csf_blocklist_update('spamhaus_drop');
?>
```

### Get Blocklist Stats
```php
<?php
$stats = csf_blocklist_get_stats();
echo "Total blocklists: " . $stats['total_lists'] . "\n";
echo "Enabled: " . $stats['enabled'] . "\n";
echo "Total IPs: " . $stats['total_ips'] . "\n";
?>
```

## Statistics & Reports

### Get Block Statistics
```php
<?php
$blocks = csf_stats_get_blocks();
echo "Total blocks: " . $blocks['total_blocks'] . "\n";
echo "Today: " . $blocks['blocks_today'] . "\n";
?>
```

### Record a Block Event
```php
<?php
csf_stats_record_block('1.2.3.4', 'port_scan');
?>
```

### Export Report
```php
<?php
$report_file = csf_stats_export('json');
// Returns: /var/lib/csf/exports/csf_stats_2026-04-07_143000.json
?>
```

## LFD Daemon Commands

Send commands to LFD via command queue:

```php
<?php
// Block IP via LFD
csf_lfd_send_command('BLOCK', '1.2.3.4');

// Unblock IP
csf_lfd_send_command('UNBLOCK', '1.2.3.4');

// Restart firewall
csf_lfd_send_command('RESTART', '');

// Update configuration
csf_lfd_send_command('CONFIG_UPDATE', '');

// Check LFD status
if (csf_lfd_is_responsive()) {
    echo "LFD is running\n";
}
?>
```

## Logging

### View Main Log
```bash
tail -f /var/log/csf/csf.log
```

### View Blocked Events
```bash
tail -f /var/log/csf/csf.blocked.log
```

### View Audit Log
```bash
tail -f /var/log/csf/audit.log
```

## Cron Jobs

Add to crontab for maintenance:

```bash
# Update blocklists hourly
0 * * * * php /path/to/csf/bin/update-blocklists.php

# Cleanup logs daily
0 0 * * * php /path/to/csf/bin/cleanup-logs.php

# Export stats weekly
0 1 * * 0 php /path/to/csf/bin/export-stats.php

# Cleanup GeoIP cache monthly
0 2 1 * * php /path/to/csf/bin/cleanup-geoip.php
```

## Troubleshooting

### Firewall Not Working
```php
<?php
$health = csf_health_check();
if (!$health['healthy']) {
    foreach ($health['errors'] as $error) {
        echo "ERROR: $error\n";
    }
}
?>
```

### Check LFD Connection
```php
<?php
if (csf_lfd_is_responsive(5)) {
    echo "LFD is responsive\n";
} else {
    echo "LFD is not responding\n";
}
?>
```

### Test API Connection
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://your-domain.com/csf/api/status
```

### Enable Debug Logging
```php
<?php
csf_init(true); // Enable debug mode
?>
```

## Common Tasks

### Block Entire Country
```php
<?php
csf_geoip_block_country('CN');
csf_geoip_block_country('RU');
?>
```

### Get Top Attackers
```php
<?php
$attackers = csf_ddos_get_top_attackers(10);
foreach ($attackers as $attacker) {
    echo $attacker['ip'] . ": " . $attacker['count'] . " attempts\n";
}
?>
```

### Get Port Scan Activity
```php
<?php
$scanners = csf_portscan_get_active_scanners(10);
foreach ($scanners as $scanner) {
    echo $scanner['ip'] . " scanned " . $scanner['unique_ports'] . " ports\n";
}
?>
```

## Security Notes

1. **Protect API Key**: Store in environment variables, not in code
2. **File Permissions**: Keep CSF files readable only by web server
3. **Audit Logs**: Regularly review audit logs for suspicious activity
4. **User Accounts**: Use strong passwords, avoid default admin
5. **Backups**: Backup `/etc/csf/` configuration regularly
6. **Updates**: Keep blocklists up-to-date for effectiveness

## Getting Help

- Check `/var/log/csf/csf.log` for detailed error messages
- Review `README.md` for comprehensive documentation
- Check function documentation in module files (PHPDoc comments)
- Enable debug mode in `csf_init(true)` for verbose logging

## Next Steps

1. Configure `/etc/csf/csf.conf` for your needs
2. Add trusted IPs to `/etc/csf/csf.allow`
3. Set up blocklists you want to use
4. Test API access with your API key
5. Configure cron jobs for automation
6. Monitor `/var/log/csf/csf.log` for activity
7. Review firewall status regularly

---

For detailed information, refer to the full documentation in `README.md`
