<?php
/**
 * ConfigServer Firewall (CSF) - Input Validation & Sanitization
 * 
 * Provides comprehensive validation for IPs, ports, domains, and other inputs.
 * All security-critical validations follow strict rules.
 * 
 * @package     CSF
 * @subpackage  Validation
 * @author      Webuzo CSF Fork
 * @version     1.0.0
 */

class CSF_Validator {
    /**
     * Validate IPv4 address
     * 
     * @param string $ip IP address to validate
     * @return bool True if valid IPv4
     */
    public static function is_valid_ipv4($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }
    
    /**
     * Validate IPv6 address
     * 
     * @param string $ip IP address to validate
     * @return bool True if valid IPv6
     */
    public static function is_valid_ipv6($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }
    
    /**
     * Validate IPv4 or IPv6 address
     * 
     * @param string $ip IP address to validate
     * @return bool True if valid IP
     */
    public static function is_valid_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * Validate IP CIDR notation (e.g., 192.168.1.0/24)
     * 
     * @param string $cidr CIDR notation to validate
     * @return bool True if valid CIDR
     */
    public static function is_valid_cidr($cidr) {
        if (strpos($cidr, '/') === false) {
            return false;
        }
        
        list($ip, $prefix) = explode('/', $cidr, 2);
        
        if (!self::is_valid_ip($ip)) {
            return false;
        }
        
        $prefix = (int)$prefix;
        
        if (self::is_valid_ipv4($ip)) {
            return $prefix >= 0 && $prefix <= 32;
        } else if (self::is_valid_ipv6($ip)) {
            return $prefix >= 0 && $prefix <= 128;
        }
        
        return false;
    }
    
    /**
     * Validate port number
     * 
     * @param mixed $port Port number to validate
     * @param bool $allow_range Allow port ranges (e.g., 80:8080)
     * @return bool True if valid port
     */
    public static function is_valid_port($port, $allow_range = true) {
        $port = (int)$port;
        
        if ($port < 1 || $port > 65535) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate port range string (e.g., "80,443,8000:8100")
     * 
     * @param string $ports Port range string
     * @return bool True if valid port range
     */
    public static function is_valid_port_range($ports) {
        if (!is_string($ports) || empty($ports)) {
            return false;
        }
        
        $port_list = explode(',', $ports);
        
        foreach ($port_list as $port_spec) {
            $port_spec = trim($port_spec);
            
            if (empty($port_spec)) {
                continue;
            }
            
            if (strpos($port_spec, ':') !== false) {
                // Port range
                list($start, $end) = explode(':', $port_spec, 2);
                $start = (int)$start;
                $end = (int)$end;
                
                if (!self::is_valid_port($start) || !self::is_valid_port($end)) {
                    return false;
                }
                
                if ($start > $end) {
                    return false;
                }
            } else {
                // Single port
                if (!self::is_valid_port($port_spec)) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    /**
     * Validate domain name
     * 
     * @param string $domain Domain to validate
     * @return bool True if valid domain
     */
    public static function is_valid_domain($domain) {
        $domain = strtolower(trim($domain));
        
        // Remove leading *. for wildcard domains
        if (strpos($domain, '*.') === 0) {
            $domain = substr($domain, 2);
        }
        
        // Check length
        if (strlen($domain) > 253) {
            return false;
        }
        
        // Check valid domain pattern
        $pattern = '/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$/i';
        
        return preg_match($pattern, $domain) === 1;
    }
    
    /**
     * Validate email address
     * 
     * @param string $email Email to validate
     * @return bool True if valid email
     */
    public static function is_valid_email($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    /**
     * Validate URL
     * 
     * @param string $url URL to validate
     * @return bool True if valid URL
     */
    public static function is_valid_url($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
    
    /**
     * Sanitize IP address (remove whitespace)
     * 
     * @param string $ip IP address
     * @return string Sanitized IP
     */
    public static function sanitize_ip($ip) {
        $ip = trim($ip);
        $ip = preg_replace('/\s+/', '', $ip);
        return $ip;
    }
    
    /**
     * Sanitize port number
     * 
     * @param mixed $port Port number
     * @return int Sanitized port
     */
    public static function sanitize_port($port) {
        return max(1, min(65535, (int)$port));
    }
    
    /**
     * Sanitize domain name
     * 
     * @param string $domain Domain name
     * @return string Sanitized domain
     */
    public static function sanitize_domain($domain) {
        $domain = strtolower(trim($domain));
        $domain = preg_replace('/[^a-z0-9.*-]/i', '', $domain);
        return $domain;
    }
    
    /**
     * Sanitize file path (prevent directory traversal)
     * 
     * @param string $path File path
     * @return string Sanitized path
     */
    public static function sanitize_path($path) {
        // Remove null bytes
        $path = str_replace("\0", '', $path);
        
        // Prevent directory traversal
        $path = str_replace('..', '', $path);
        $path = preg_replace('/[^a-z0-9_\-\.\/]/i', '', $path);
        
        return $path;
    }
    
    /**
     * Sanitize string (basic HTML/special chars)
     * 
     * @param string $string String to sanitize
     * @param bool $allow_newlines Allow newline characters
     * @return string Sanitized string
     */
    public static function sanitize_string($string, $allow_newlines = false) {
        $string = trim($string);
        
        if (!$allow_newlines) {
            $string = str_replace(array("\n", "\r"), '', $string);
        }
        
        // Remove null bytes
        $string = str_replace("\0", '', $string);
        
        return $string;
    }
    
    /**
     * Validate boolean value
     * 
     * @param mixed $value Value to check
     * @return bool True if is valid boolean
     */
    public static function is_valid_bool($value) {
        return is_bool($value) || 
               $value === 1 || $value === 0 || 
               $value === '1' || $value === '0' ||
               strtolower($value) === 'true' ||
               strtolower($value) === 'false' ||
               strtolower($value) === 'yes' ||
               strtolower($value) === 'no';
    }
    
    /**
     * Convert to boolean
     * 
     * @param mixed $value Value to convert
     * @return bool Boolean value
     */
    public static function to_bool($value) {
        if (is_bool($value)) {
            return $value;
        }
        
        if (is_string($value)) {
            return in_array(strtolower($value), array('1', 'true', 'yes', 'on'), true);
        }
        
        return (bool)$value;
    }
    
    /**
     * Validate integer value
     * 
     * @param mixed $value Value to validate
     * @param int $min Minimum value (optional)
     * @param int $max Maximum value (optional)
     * @return bool True if valid integer
     */
    public static function is_valid_int($value, $min = null, $max = null) {
        if (!is_numeric($value) && !is_int($value)) {
            return false;
        }
        
        $value = (int)$value;
        
        if ($min !== null && $value < $min) {
            return false;
        }
        
        if ($max !== null && $value > $max) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate hexadecimal string
     * 
     * @param string $hex Hex string to validate
     * @return bool True if valid hex
     */
    public static function is_valid_hex($hex) {
        $hex = str_replace('#', '', $hex);
        return preg_match('/^[a-f0-9]{6}$/i', $hex) === 1 ||
               preg_match('/^[a-f0-9]{3}$/i', $hex) === 1;
    }
    
    /**
     * Validate API key format
     * 
     * @param string $api_key API key to validate
     * @return bool True if valid API key format
     */
    public static function is_valid_api_key($api_key) {
        // API keys should be alphanumeric, 32-256 characters
        if (!is_string($api_key) || empty($api_key)) {
            return false;
        }
        
        $length = strlen($api_key);
        
        if ($length < 32 || $length > 256) {
            return false;
        }
        
        return preg_match('/^[a-z0-9]+$/i', $api_key) === 1;
    }
}
?>
