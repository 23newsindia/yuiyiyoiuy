<?php

class SecurityWAF {
    private static $instance = null;
    private $blocked_ips_cache = array();
    private $request_limit;
    private $blacklist_threshold;
    
    public function __construct() {
        if (!get_option('security_enable_waf', true)) {
            return;
        }
        
        $this->request_limit = (int)get_option('security_waf_request_limit', 100);
        $this->blacklist_threshold = (int)get_option('security_waf_blacklist_threshold', 5);
        
        // Cache blocked IPs
        $this->blocked_ips_cache = get_option('waf_blocked_ips', array());
        
        $this->init();
    }

    private function ensure_table_exists() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            violation_type varchar(50) NOT NULL,
            request_uri text NOT NULL,
            timestamp datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY ip_timestamp (ip_address, timestamp)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    private function init() {
        add_action('init', array($this, 'waf_check'), 1);
        add_action('admin_init', array($this, 'schedule_cleanup'));
    }

    public function waf_check() {
        $ip = $this->get_client_ip();
        
        if ($this->is_ip_blocked($ip)) {
            $this->block_request('IP Blocked');
        }

        if ($this->is_rate_limited($ip)) {
            $this->log_violation($ip, 'Rate Limit Exceeded');
            $this->block_request('Rate Limit Exceeded');
        }

        $this->check_attack_patterns($ip);
    }

    private function is_rate_limited($ip) {
        $transient_key = 'waf_rate_limit_' . md5($ip);
        $requests = get_transient($transient_key);
        
        if ($requests === false) {
            set_transient($transient_key, 1, 60); // Start counting, expire in 60 seconds
            return false;
        }
        
        if ($requests >= $this->request_limit) {
            return true;
        }
        
        set_transient($transient_key, $requests + 1, 60);
        return false;
    }

    private function check_attack_patterns($ip) {
        // Check for SQL injection
        if ($this->detect_sql_injection()) {
            $this->log_violation($ip, 'SQL Injection Attempt');
            $this->block_request('Invalid Request');
        }

        // Check for XSS
        if ($this->detect_xss()) {
            $this->log_violation($ip, 'XSS Attempt');
            $this->block_request('Invalid Request');
        }

        // Check for file inclusion
        if ($this->detect_file_inclusion()) {
            $this->log_violation($ip, 'File Inclusion Attempt');
            $this->block_request('Invalid Request');
        }
    }

    private function detect_sql_injection() {
        $patterns = array(
            '/union\s+select/i',
            '/exec\s*\(/i',
            '/INFORMATION_SCHEMA/i',
            '/into\s+outfile/i'
        );
        
        return $this->check_patterns($patterns);
    }

    private function detect_xss() {
        $patterns = array(
            '/<script.*?>.*?<\/script>/is',
            '/javascript:/i',
            '/onload=/i',
            '/onerror=/i'
        );
        
        return $this->check_patterns($patterns);
    }

    private function detect_file_inclusion() {
        $patterns = array(
            '/\.\.\//i',
            '/etc\/passwd/i',
            '/include\s*\(/i',
            '/require\s*\(/i'
        );
        
        return $this->check_patterns($patterns);
    }

    private function check_patterns($patterns) {
        static $input = null;
        
        if ($input === null) {
            $input = array(
                $_SERVER['REQUEST_URI'],
                file_get_contents('php://input'),
                implode(' ', $_GET),
                implode(' ', $_POST),
                implode(' ', $_COOKIE)
            );
        }
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, implode(' ', $input))) {
                return true;
            }
        }
        return false;
    }


    private function log_violation($ip, $type) {
        global $wpdb;
        
        // Ensure table exists before logging
        $this->ensure_table_exists();
        
        try {
            $wpdb->insert(
                $this->table_name,
                array(
                    'ip_address' => $ip,
                    'violation_type' => $type,
                    'request_uri' => $_SERVER['REQUEST_URI'],
                    'timestamp' => current_time('mysql')
                ),
                array('%s', '%s', '%s', '%s')
            );

            if ($wpdb->last_error) {
                error_log('WAF Log Error: ' . $wpdb->last_error);
                return;
            }

            // Check for blacklist threshold
            $violations = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name} 
                WHERE ip_address = %s 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
                $ip
            ));

            if ($violations >= $this->blacklist_threshold) {
                $this->blacklist_ip($ip);
            }
        } catch (Exception $e) {
            error_log('WAF Exception: ' . $e->getMessage());
        }
    }

    private function blacklist_ip($ip) {
        $blocked_ips = get_option('waf_blocked_ips', array());
        if (!in_array($ip, $blocked_ips)) {
            $blocked_ips[] = $ip;
            update_option('waf_blocked_ips', $blocked_ips);
        }
    }

    public function is_ip_blocked($ip) {
        return in_array($ip, $this->blocked_ips_cache);
    }

    private function block_request($reason) {
        status_header(403);
        die('Access Denied: ' . $reason);
    }

    private function get_client_ip() {
        return isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? 
               $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
    }

    public function schedule_cleanup() {
        if (!wp_next_scheduled('waf_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'waf_cleanup_logs');
        }
    }

    public function cleanup_logs() {
        global $wpdb;
        
        // Remove logs older than 30 days
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
    }
}