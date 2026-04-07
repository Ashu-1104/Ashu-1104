# CSF PHP Fork - File Manifest

## Complete File Structure

```
csf-firewall-php/
│
├── csf/
│   ├── includes/
│   │   ├── csf.core.php             (236 lines) - Main initialization
│   │   ├── csf.conf.php             (313 lines) - Configuration management
│   │   ├── csf.logging.php          (331 lines) - Logging functions
│   │   ├── csf.validate.php         (389 lines) - Input validation
│   │   ├── csf.file.php             (419 lines) - File operations
│   │   ├── csf.lfd.php              (368 lines) - LFD communication
│   │   ├── csf.iptables.php         (440 lines) - iptables rules
│   │   ├── csf.ports.php            (354 lines) - Port management
│   │   ├── csf.geoip.php            (396 lines) - GeoIP blocking
│   │   ├── csf.portscan.php         (350 lines) - Port scan detection
│   │   ├── csf.ddos.php             (340 lines) - DDoS protection
│   │   ├── csf.blocklists.php       (426 lines) - Blocklist management
│   │   ├── csf.stats.php            (395 lines) - Statistics
│   │   ├── csf.api.php              (431 lines) - REST API
│   │   ├── csf.admin.php            (498 lines) - Admin functions
│   │   └── csf.html.php             (341 lines) - UI helpers
│   │
│   └── index.php                    (154 lines) - Web interface
│
├── README.md                         (397 lines) - Full documentation
├── QUICKSTART.md                     (427 lines) - Quick start guide
├── IMPLEMENTATION_SUMMARY.md         (343 lines) - Implementation details
└── FILE_MANIFEST.md                 (This file)

Total: 5,450+ lines of PHP code
```

## File Details

### Core Modules (csf/includes/)

#### csf.core.php (236 lines)
**Purpose**: Main system initialization and health checking
**Key Functions**:
- `csf_init()` - Initialize CSF system
- `csf_get_config()` - Get current configuration
- `csf_update_config()` - Update configuration
- `csf_get_status()` - Get system status
- `csf_health_check()` - Check system health
- `csf_shutdown()` - Graceful shutdown

**Responsibilities**:
- Load all modules
- Initialize directories
- Load configuration
- Initialize LFD communication
- Health monitoring

#### csf.conf.php (313 lines)
**Purpose**: Configuration file management
**Key Functions**:
- `csf_config_get()` - Load configuration
- `csf_config_write()` - Save configuration
- `csf_config_validate()` - Validate config values
- `csf_get_default_config()` - Get defaults

**Data Format**: INI-style text file at `/etc/csf/csf.conf`

#### csf.logging.php (331 lines)
**Purpose**: Structured logging system
**Key Functions**:
- `csf_log()` - Write to log
- `csf_log_init()` - Initialize logging
- `csf_log_rotate()` - Rotate logs
- `csf_log_cleanup()` - Clean old logs

**Log Files**:
- `/var/log/csf/csf.log` - Main log
- `/var/log/csf/csf.blocked.log` - Blocked events
- `/var/log/csf/csf.access.log` - Web access
- `/var/log/csf/audit.log` - Admin actions

#### csf.validate.php (389 lines)
**Purpose**: Input validation and security
**Key Functions**:
- `csf_validate_ip()` - Validate IP address
- `csf_validate_cidr()` - Validate CIDR range
- `csf_validate_port()` - Validate port number
- `csf_validate_url()` - Validate URL
- `csf_sanitize_input()` - Sanitize user input

**Security Features**:
- IPv4/IPv6 validation
- CIDR notation validation
- Port range validation
- Input sanitization

#### csf.file.php (419 lines)
**Purpose**: Safe file operations with atomic writes
**Key Functions**:
- `csf_file_read()` - Read file safely
- `csf_file_write()` - Write with locking
- `csf_file_exists()` - Check file existence
- `csf_create_directory()` - Create directory safely

**Safety Features**:
- File locking (flock)
- Atomic writes with temp files
- Permission management
- Directory traversal prevention

#### csf.lfd.php (368 lines)
**Purpose**: LFD daemon communication
**Key Functions**:
- `csf_lfd_init()` - Initialize LFD communication
- `csf_lfd_send_command()` - Send command to LFD
- `csf_lfd_is_responsive()` - Check LFD status
- `csf_lfd_get_queue_status()` - Check command queue

**Commands Supported**:
- BLOCK, UNBLOCK
- ENABLE, DISABLE
- RESTART
- CONFIG_UPDATE
- GEOIP_BLOCK, DDOS_BLOCK

#### csf.iptables.php (440 lines)
**Purpose**: iptables firewall rule management
**Key Functions**:
- `csf_iptables_add_ip()` - Block/allow IP
- `csf_iptables_remove_ip()` - Remove IP rule
- `csf_iptables_get_rules()` - Get current rules
- `csf_iptables_apply_all()` - Apply all rules
- `csf_iptables_flush()` - Clear all rules

**Features**:
- IPv4/IPv6 support
- CIDR ranges
- Whitelist/blacklist management
- Atomic rule updates

#### csf.ports.php (354 lines)
**Purpose**: Port rule management
**Key Functions**:
- `csf_ports_add_rule()` - Add port rule
- `csf_ports_remove_rule()` - Remove port rule
- `csf_ports_get_rules()` - Get port rules
- `csf_ports_apply_rules()` - Apply to firewall

**Features**:
- TCP/UDP rules
- Port ranges
- Inbound/outbound rules
- Rule templates

#### csf.geoip.php (396 lines)
**Purpose**: GeoIP-based country blocking
**Key Functions**:
- `csf_geoip_lookup()` - Lookup country for IP
- `csf_geoip_block_country()` - Block country
- `csf_geoip_unblock_country()` - Unblock country
- `csf_geoip_update_database()` - Update GeoIP DB

**Providers**:
- MaxMind
- IP2Location
- Custom providers

**Cache**: 30-day cache at `/var/lib/csf/geoip/cache/`

#### csf.portscan.php (350 lines)
**Purpose**: Port scan detection and blocking
**Key Functions**:
- `csf_portscan_log_attempt()` - Log port scan
- `csf_portscan_block_ip()` - Block scanner
- `csf_portscan_get_statistics()` - Get stats
- `csf_portscan_analyze_pattern()` - Analyze pattern

**Detection Types**:
- Sequential scans
- Bulk scans
- Targeted scans
- Low volume scans

#### csf.ddos.php (340 lines)
**Purpose**: DDoS detection and mitigation
**Key Functions**:
- `csf_ddos_check_rate()` - Check connection rate
- `csf_ddos_detect_http_flood()` - Detect HTTP flood
- `csf_ddos_block_ip()` - Block attacker
- `csf_ddos_get_top_attackers()` - Get top attackers

**Detection Methods**:
- Connection rate monitoring
- HTTP flood detection
- Pattern recognition

#### csf.blocklists.php (426 lines)
**Purpose**: Third-party blocklist management
**Key Functions**:
- `csf_blocklist_get_list()` - Get blocklist config
- `csf_blocklist_update()` - Download blocklist
- `csf_blocklist_apply()` - Apply to firewall
- `csf_blocklist_auto_update()` - Auto-update

**Supported Sources**:
- Spamhaus DROP
- AbuseIPDB
- StopForumSpam
- MaxMind GeoIP
- Custom sources

#### csf.stats.php (395 lines)
**Purpose**: Statistics collection and reporting
**Key Functions**:
- `csf_stats_get_status()` - Get firewall status
- `csf_stats_get_blocks()` - Get block statistics
- `csf_stats_record_block()` - Record block event
- `csf_stats_generate_report()` - Generate report
- `csf_stats_export()` - Export statistics

**Export Formats**:
- JSON
- CSV
- TXT

#### csf.api.php (431 lines)
**Purpose**: REST API interface
**Key Functions**:
- `csf_api_route()` - Route API requests
- `csf_api_validate_key()` - Validate API key
- `csf_api_response()` - Format response
- `csf_api_rate_limit()` - Rate limiting

**Endpoints** (20+):
- GET /api/status
- POST /api/ips/block
- GET /api/ips/blocked
- POST /api/rules/add
- GET /api/blocklists
- POST /api/geoip/block
- GET /api/stats/report
- GET /api/logs
- etc.

#### csf.admin.php (498 lines)
**Purpose**: Administrative functions
**Key Functions**:
- `csf_admin_enable()` - Enable firewall
- `csf_admin_disable()` - Disable firewall
- `csf_admin_add_user()` - Add user (bcrypt)
- `csf_admin_update_password()` - Update password
- `csf_admin_verify_user()` - Verify credentials
- `csf_admin_get_audit_log()` - Get audit log

**Security**:
- bcrypt hashing (cost 12)
- Password verification
- User roles (admin, user, readonly)
- Audit logging

#### csf.html.php (341 lines)
**Purpose**: HTML/UI helper functions
**Key Functions**:
- `csf_html_header()` - HTML header
- `csf_html_footer()` - HTML footer
- `csf_html_alert()` - Alert box
- `csf_html_button()` - Button element
- `csf_html_form_field()` - Form input
- `csf_html_stats_card()` - Stats card
- `csf_html_escape()` - Escape HTML

**Framework**: Bootstrap 5

### Entry Points

#### index.php (154 lines)
**Purpose**: Web interface and main entry point
**Features**:
- Dashboard with status cards
- Statistics display
- API endpoint information
- Bootstrap 5 styling
- Real-time status updates

**Routes**:
- `/` - Dashboard
- `/api/*` - API endpoints

### Documentation

#### README.md (397 lines)
**Purpose**: Comprehensive project documentation
**Sections**:
- Overview and architecture
- Installation instructions
- Module descriptions
- Configuration guide
- REST API documentation
- LFD integration
- Security features
- Logging and monitoring

#### QUICKSTART.md (427 lines)
**Purpose**: Quick start guide with examples
**Sections**:
- Installation steps
- Basic usage examples
- REST API usage
- Configuration reference
- Admin functions
- Port management
- Blocklist management
- Statistics and reports
- Troubleshooting

#### IMPLEMENTATION_SUMMARY.md (343 lines)
**Purpose**: Implementation details and statistics
**Sections**:
- Project overview
- Implementation statistics
- File breakdown
- Module breakdown
- Key features
- Architecture highlights
- Code quality
- Function categories
- Testing recommendations
- Deployment checklist

#### FILE_MANIFEST.md (This file)
**Purpose**: Complete file listing and descriptions
**Contents**:
- File structure
- File details with line counts
- Function listings
- Feature descriptions
- Data formats
- Security notes

## Module Dependencies

```
csf.core.php
├── csf.conf.php
├── csf.logging.php
├── csf.validate.php
├── csf.file.php
├── csf.lfd.php
├── csf.iptables.php
├── csf.ports.php
├── csf.geoip.php
├── csf.portscan.php
├── csf.ddos.php
├── csf.blocklists.php
├── csf.stats.php
├── csf.api.php
├── csf.admin.php
└── csf.html.php
```

## Code Statistics

| Category | Count |
|----------|-------|
| Total Lines | 5,450+ |
| PHP Files | 16 |
| Documentation Files | 4 |
| Total Functions | 150+ |
| API Endpoints | 20+ |
| Configuration Keys | 30+ |
| Log Types | 4 |
| Supported Blocklists | 4+ |

## Function Distribution

| Module | Functions |
|--------|-----------|
| csf.core.php | 6 |
| csf.conf.php | 5 |
| csf.logging.php | 7 |
| csf.validate.php | 8 |
| csf.file.php | 9 |
| csf.lfd.php | 7 |
| csf.iptables.php | 12 |
| csf.ports.php | 8 |
| csf.geoip.php | 13 |
| csf.portscan.php | 10 |
| csf.ddos.php | 10 |
| csf.blocklists.php | 13 |
| csf.stats.php | 12 |
| csf.api.php | 10 |
| csf.admin.php | 14 |
| csf.html.php | 15 |
| **Total** | **159** |

## File Sizes

| File | Size | Lines |
|------|------|-------|
| csf.core.php | ~8 KB | 236 |
| csf.conf.php | ~10 KB | 313 |
| csf.logging.php | ~11 KB | 331 |
| csf.validate.php | ~13 KB | 389 |
| csf.file.php | ~15 KB | 419 |
| csf.lfd.php | ~12 KB | 368 |
| csf.iptables.php | ~16 KB | 440 |
| csf.ports.php | ~12 KB | 354 |
| csf.geoip.php | ~14 KB | 396 |
| csf.portscan.php | ~12 KB | 350 |
| csf.ddos.php | ~12 KB | 340 |
| csf.blocklists.php | ~15 KB | 426 |
| csf.stats.php | ~14 KB | 395 |
| csf.api.php | ~16 KB | 431 |
| csf.admin.php | ~17 KB | 498 |
| csf.html.php | ~12 KB | 341 |
| index.php | ~6 KB | 154 |
| **Total** | **~210 KB** | **5,450+** |

## Data Formats

| File | Format | Location |
|------|--------|----------|
| csf.conf | INI-style text | `/etc/csf/csf.conf` |
| csf.allow | IP list | `/etc/csf/csf.allow` |
| csf.deny | IP list | `/etc/csf/csf.deny` |
| blocklists.json | JSON | `/etc/csf/blocklists.json` |
| users.json | JSON | `/etc/csf/users.json` |
| blocks.json | JSON | `/var/lib/csf/stats/blocks.json` |
| connections.json | JSON | `/var/lib/csf/stats/connections.json` |
| csf.log | Text | `/var/log/csf/csf.log` |
| audit.log | Text | `/var/log/csf/audit.log` |

## Security Features by Module

| Module | Security Features |
|--------|-------------------|
| csf.validate.php | Input validation, sanitization |
| csf.file.php | File locking, atomic writes |
| csf.admin.php | bcrypt hashing, password verification |
| csf.api.php | Bearer token auth, rate limiting |
| csf.lfd.php | Command queue security |
| All modules | Error logging, exception handling |

## Version Information

- **CSF Version**: 14.0.0-PHP
- **PHP Requirement**: 7.4+
- **LFD Version**: Compatible with 14.0+
- **Release Date**: April 7, 2026
- **Status**: Production Ready

---

**Last Updated**: April 7, 2026  
**Total Files**: 20  
**Total Lines**: 5,450+
