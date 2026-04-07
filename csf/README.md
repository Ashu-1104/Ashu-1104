# CSF Firewall - PHP Fork for Webuzo

**Version:** 14.0.0-PHP  
**Architecture:** PHP 7.4+ with C daemon (LFD) support

## Overview

This is a complete PHP translation of ConfigServer Firewall (CSF) designed for integration with Webuzo hosting control panel. The firewall logic is implemented in PHP while keeping the high-performance Login Failure Daemon (LFD) in C for real-time monitoring.

## Architecture

```
CSF PHP (Management Layer)          LFD C (Daemon Layer)
├── Configuration Management   <->  ├── Real-time Log Analysis
├── IP Rules Management             ├── Attack Detection  
├── Blocklists                      ├── Auto-blocking
├── Statistics & Reporting          └── Performance Monitoring
├── REST API                    
├── Web UI                          Command Interface
└── Admin Functions            <->  /var/lib/csf/cmd/
```

## Directory Structure

```
csf/
├── includes/                    # Core PHP modules
│   ├── csf.core.php            # Main initialization
│   ├── csf.conf.php            # Configuration management
│   ├── csf.logging.php         # Logging functions
│   ├── csf.validate.php        # Input validation
│   ├── csf.file.php            # File operations
│   ├── csf.lfd.php             # LFD daemon communication
│   ├── csf.iptables.php        # iptables integration
│   ├── csf.ports.php           # Port management
│   ├── csf.geoip.php           # GeoIP blocking
│   ├── csf.portscan.php        # Port scan detection
│   ├── csf.ddos.php            # DDoS protection
│   ├── csf.blocklists.php      # Blocklist management
│   ├── csf.stats.php           # Statistics & reporting
│   ├── csf.api.php             # REST API
│   ├── csf.admin.php           # Admin functions
│   └── csf.html.php            # UI helpers
├── index.php                    # Main entry point
└── README.md                    # This file

/etc/csf/                       # Configuration files
├── csf.conf                    # Main configuration
├── csf.allow                   # Whitelist
├── csf.deny                    # Blacklist
├── csf.ignore                  # Ignore rules
└── blocklists.json             # Blocklist configuration

/var/lib/csf/                   # Runtime data
├── cmd/                        # LFD command queue
├── log/                        # Log files
├── stats/                      # Statistics
├── geoip/                      # GeoIP data
├── portscan/                   # Port scan data
├── ddos/                       # DDoS tracking
├── blocklists/                 # Downloaded blocklists
└── api/                        # API rate limiting
```

## Core Modules

### 1. Configuration (csf.conf.php)
- Load/save configuration from `/etc/csf/csf.conf`
- Default values for all settings
- Config validation

### 2. Logging (csf.logging.php)
- Structured logging to `/var/log/csf/`
- Log rotation and cleanup
- Multiple log types (main, blocked, access, system)

### 3. Validation (csf.validate.php)
- IP address validation (IPv4/IPv6, CIDR)
- Port validation
- Input sanitization
- Security checks

### 4. File Operations (csf.file.php)
- Atomic file writes with locking
- Safe read/write operations
- Directory creation
- Permissions management

### 5. LFD Communication (csf.lfd.php)
- Command queue in `/var/lib/csf/cmd/`
- Commands: BLOCK, UNBLOCK, RESTART, etc.
- Command status checking
- Queue management

### 6. iptables Integration (csf.iptables.php)
- Generate iptables rules
- Whitelist/Blacklist management
- Rule persistence
- Atomic rule updates

### 7. Port Management (csf.ports.php)
- TCP/UDP port rules
- Inbound/outbound rules
- Port range support
- Rule templates

### 8. GeoIP Blocking (csf.geoip.php)
- IP to Country lookup
- MaxMind/IP2Location API support
- GeoIP cache
- Country-based blocking rules

### 9. Port Scan Detection (csf.portscan.php)
- Track port scan attempts
- Pattern analysis
- Auto-blocking on threshold
- Scan history cleanup

### 10. DDoS Protection (csf.ddos.php)
- Connection rate monitoring
- HTTP flood detection
- Pattern recognition
- Automatic mitigation

### 11. Blocklists (csf.blocklists.php)
- Manage third-party blocklists
- Support for multiple sources
- Auto-update scheduling
- Spamhaus, AbuseIPDB, StopForumSpam, etc.

### 12. Statistics (csf.stats.php)
- Block/connection tracking
- Daily/weekly/monthly statistics
- Report generation
- Export to JSON/CSV/TXT

### 13. REST API (csf.api.php)
- Endpoints for all CSF operations
- Bearer token authentication
- Rate limiting
- JSON responses

### 14. Admin Functions (csf.admin.php)
- User management with bcrypt hashing
- Configuration updates
- Audit logging
- System information

### 15. UI Helpers (csf.html.php)
- Bootstrap 5 components
- Form builders
- Status badges
- Modal dialogs

## Configuration

### Basic Setup

```php
<?php
require_once '/path/to/csf/includes/csf.core.php';
csf_init();

// Enable firewall
csf_admin_enable();

// Add whitelist entry
csf_iptables_add_ip('192.168.1.0/24', 'ALLOW', 'Local network');

// Block an IP
csf_iptables_add_ip('1.2.3.4', 'BLOCK', 'Malicious activity');
?>
```

### Configuration File (`/etc/csf/csf.conf`)

```ini
ENABLED=1
LFD_ENABLE=1
PT_ENABLE=1
PT_LIMIT=10
PT_BLOCK=1
DDOS_ENABLE=1
DDOS_LIMIT=100
API_ENABLE=1
```

## REST API

### Authentication
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://webuzo.example.com/csf/api/status
```

### Endpoints

#### Status
```bash
GET /csf/api/status
```

#### Block IP
```bash
POST /csf/api/ips/block
{
  "ip": "1.2.3.4",
  "reason": "Suspicious activity"
}
```

#### Get Blocked IPs
```bash
GET /csf/api/ips/blocked
```

#### Port Rules
```bash
GET /csf/api/rules
POST /csf/api/rules/add
DELETE /csf/api/rules/22
```

#### Blocklists
```bash
GET /csf/api/blocklists
POST /csf/api/blocklists/update/spamhaus_drop
```

#### GeoIP
```bash
GET /csf/api/geoip/lookup/1.2.3.4
POST /csf/api/geoip/block
{
  "country": "CN"
}
```

#### Statistics
```bash
GET /csf/api/stats/status
GET /csf/api/stats/blocks
GET /csf/api/stats/report
```

#### Logs
```bash
GET /csf/api/logs/100
```

## LFD Integration

Commands are queued in `/var/lib/csf/cmd/` for the C daemon to process:

```bash
# Block an IP
echo "BLOCK|1.2.3.4|Malicious" > /var/lib/csf/cmd/block_1234567890

# Unblock an IP
echo "UNBLOCK|1.2.3.4" > /var/lib/csf/cmd/unblock_1234567890

# Restart firewall
echo "RESTART" > /var/lib/csf/cmd/restart_1234567890

# Configuration update
echo "CONFIG_UPDATE" > /var/lib/csf/cmd/config_1234567890
```

## Security Features

### Input Validation
- All IP addresses validated
- CIDR ranges checked
- Port numbers verified
- URL validation for blocklists

### File Security
- Atomic writes with file locking
- Safe permission management
- Temporary file cleanup
- Directory traversal prevention

### API Security
- Bearer token authentication
- Timing-safe comparison (hash_equals)
- Rate limiting per API key
- Request validation

### Password Security
- bcrypt hashing (cost 12)
- Password verification functions
- Salt generation
- No plaintext storage

## Logging

All operations logged to `/var/log/csf/`:

```
csf.log              # Main firewall logs
csf.blocked.log      # Blocked IP events
csf.access.log       # Web UI access
audit.log            # Administrative actions
```

Log format:
```
[TIMESTAMP] [MODULE] [LEVEL] Message
[2026-04-07 14:30:45] [IPTABLES] [INFO] Blocked IP 1.2.3.4: Malicious activity
```

## Monitoring

### Check Firewall Status
```php
<?php
$status = csf_stats_get_status();
var_dump($status);
?>
```

### Get Active Blockers
```php
<?php
$blocked = csf_iptables_get_blocked_ips();
foreach ($blocked as $ip => $reason) {
    echo "$ip: $reason\n";
}
?>
```

### Port Scan Detection
```php
<?php
$scanners = csf_portscan_get_active_scanners(10);
foreach ($scanners as $scanner) {
    echo "IP: {$scanner['ip']}, Ports: {$scanner['unique_ports']}\n";
}
?>
```

## Performance Considerations

1. **File-based Storage**: Configuration and data stored in JSON/text files
2. **Atomic Operations**: All writes use locking to prevent corruption
3. **Caching**: Configuration cached in memory during execution
4. **Cleanup**: Old logs, cache files automatically cleaned
5. **Rate Limiting**: API requests limited to prevent abuse

## LFD Daemon Requirements

The C daemon (LFD) must be running for:
- Real-time log analysis
- Automatic IP blocking
- Port scan detection
- Login failure tracking

C daemon communicates via command queue at `/var/lib/csf/cmd/`

## Code Style

Following Webuzo conventions:
- PHPDoc comments for all functions
- Input validation on all parameters
- Error handling with logging
- Consistent naming conventions
- Security-first approach

## Version Compatibility

- **PHP**: 7.4+ (8.0+ recommended)
- **Database**: File-based (JSON/text)
- **OS**: Linux (iptables support required)
- **LFD**: C daemon version 14.0+

## Future Enhancements

- [ ] Database backend support (MySQL/PostgreSQL)
- [ ] Web UI dashboard
- [ ] Mobile app integration
- [ ] Machine learning threat detection
- [ ] Advanced rule templates
- [ ] Multi-server clustering

## Support & Contributing

For issues, feature requests, or contributions related to this PHP fork, please contact the Webuzo development team.

## License

Follows original CSF license terms with PHP fork modifications.

---

**Last Updated:** 2026-04-07  
**Maintained by:** Webuzo Team
