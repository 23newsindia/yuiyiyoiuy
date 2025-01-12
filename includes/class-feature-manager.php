<?php
// includes/class-feature-manager.php

if (!defined('ABSPATH')) {
    exit;
}

class FeatureManager {
    private $excluded_paths_cache = null;
    private static $is_admin = null;
    private $options_cache = array();
  
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }

    public function init() {
        // Initialize is_admin check once
        if (self::$is_admin === null) {
            self::$is_admin = is_admin();
        }

        $this->manage_feeds();
        $this->manage_oembed();
        $this->manage_pingback();
        $this->manage_wp_json();
        $this->manage_rsd();
        $this->manage_wp_generator();
        $this->manage_php_access();
        $this->manage_url_security();
        
        // Add the query string removal with better performance
        if (get_option('security_remove_query_strings', false)) {
            add_action('parse_request', array($this, 'remove_query_strings'), 1);
        }
    }
  
  
   public function remove_query_strings() {
        // Skip if admin or no query string
        if (self::$is_admin || empty($_SERVER['QUERY_STRING'])) {
            return;
        }

        $request_uri = $_SERVER['REQUEST_URI'];
        $path = parse_url($request_uri, PHP_URL_PATH);
        
        // Skip if no query string in URL
        if (strpos($request_uri, '?') === false) {
            return;
        }

        // Check excluded paths efficiently
        $request_path = trim($path, '/');
        foreach ($this->get_excluded_paths() as $excluded) {
            if (empty($excluded)) {
                continue;
            }
            
            // Check if path starts with excluded path or matches exactly
            if (strpos($request_path, $excluded) === 0 || 
                $request_path === $excluded || 
                strpos($request_path, $excluded . '/') === 0) {
                return;
            }
        }

        // Preserve essential WP query vars if needed
        $essential_vars = array('p', 'page_id', 'cat', 'tag', 'post_type');
        $preserved_vars = array();
        foreach ($essential_vars as $var) {
            if (isset($_GET[$var])) {
                $preserved_vars[$var] = $_GET[$var];
            }
        }

        // Build the redirect URL
        $redirect_url = $path;
        if (!empty($preserved_vars)) {
            $redirect_url .= '?' . http_build_query($preserved_vars);
        }

        // Only redirect if URL is different
        if ($redirect_url !== $request_uri) {
            // Use 307 to preserve POST data and indicate temporary redirect
            wp_redirect($redirect_url, 307);
            exit;
        }
    }

    private function manage_feeds() {
        if (get_option('security_remove_feeds', false)) {
            remove_action('wp_head', 'feed_links', 2);
            remove_action('wp_head', 'feed_links_extra', 3);
            add_action('do_feed', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rdf', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rss', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rss2', array($this, 'disable_feeds'), 1);
            add_action('do_feed_atom', array($this, 'disable_feeds'), 1);
        }
    }

    public function disable_feeds() {
        wp_die(__('RSS Feeds are disabled for security reasons.', 'security-plugin'));
    }

    private function manage_oembed() {
        if (get_option('security_remove_oembed', false)) {
            remove_action('wp_head', 'wp_oembed_add_discovery_links');
            remove_action('wp_head', 'wp_oembed_add_host_js');
            remove_filter('oembed_dataparse', 'wp_filter_oembed_result', 10);
            remove_action('rest_api_init', 'wp_oembed_register_route');
            add_filter('embed_oembed_discover', '__return_false');
        }
    }

    private function manage_pingback() {
        if (get_option('security_remove_pingback', false)) {
            remove_action('wp_head', 'pingback_link');
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', array($this, 'remove_pingback_header'));
            add_filter('xmlrpc_methods', array($this, 'remove_xmlrpc_methods'));
        }
    }

    public function remove_pingback_header($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function remove_xmlrpc_methods($methods) {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    private function manage_wp_json() {
        if (get_option('security_remove_wp_json', false)) {
            remove_action('wp_head', 'rest_output_link_wp_head');
            remove_action('template_redirect', 'rest_output_link_header', 11);
            remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
            add_filter('rest_enabled', '__return_false');
            add_filter('rest_jsonp_enabled', '__return_false');
        }
    }

    private function manage_rsd() {
        if (get_option('security_remove_rsd', false)) {
            remove_action('wp_head', 'rsd_link');
        }
    }

    private function manage_wp_generator() {
        if (get_option('security_remove_wp_generator', false)) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }
    }

    private function manage_php_access() {
        if (!is_admin()) {
            add_action('init', array($this, 'block_direct_php_access'));
        }
    }

    public function block_direct_php_access() {
        $request_uri = $_SERVER['REQUEST_URI'];
        
        if (preg_match('/\.php$/i', $request_uri)) {
            $current_path = trim($request_uri, '/');
            $excluded_php_paths = explode("\n", get_option('security_excluded_php_paths', ''));
            
            foreach ($excluded_php_paths as $excluded_path) {
                $excluded_path = trim($excluded_path, '/');
                if (!empty($excluded_path) && strpos($current_path, $excluded_path) === 0) {
                    return;
                }
            }
            
            $this->send_403_response();
        }
    }
  
  
  

    private function manage_url_security() {
        if (!is_admin()) {
            add_action('init', array($this, 'check_url_security'));
        }
    }

    public function check_url_security() {
        $current_url = $_SERVER['REQUEST_URI'];
        
        // Check excluded paths
        $excluded_paths = explode("\n", get_option('security_excluded_paths', ''));
        foreach ($excluded_paths as $path) {
            $path = trim($path);
            if (!empty($path) && strpos($current_url, $path) !== false) {
                return;
            }
        }

        // Check blocked patterns
        $blocked_patterns = explode("\n", get_option('security_blocked_patterns', ''));
        foreach ($blocked_patterns as $pattern) {
            $pattern = trim($pattern);
            if (!empty($pattern) && strpos($current_url, $pattern) !== false) {
                $this->send_403_response('Security Error: Blocked Pattern Detected');
            }
        }

        // Remove query strings if enabled
        if (get_option('security_remove_query_strings', false) && !empty($_SERVER['QUERY_STRING'])) {
            wp_redirect(home_url(remove_query_arg(array_keys($_GET))), 301);
            exit;
        }
    }
  
  

    private function send_403_response($message = '403 Forbidden') {
        status_header(403);
        nocache_headers();
        header('HTTP/1.1 403 Forbidden');
        header('Status: 403 Forbidden');
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
        }
        die($message);
    }

    // Additional utility methods
    public function is_feature_enabled($feature) {
        return get_option('security_' . $feature, false);
    }

      private function get_excluded_paths() {
        if ($this->excluded_paths_cache === null) {
            $paths = get_option('security_excluded_paths', '');
            if (empty($paths)) {
                $this->excluded_paths_cache = array();
                return array();
            }

            $this->excluded_paths_cache = array_filter(
                array_map(
                    function($path) {
                        return rtrim(trim($path), '/');
                    },
                    explode("\n", $paths)
                )
            );
        }
        return $this->excluded_paths_cache;
    }

    public function get_blocked_patterns() {
        return array_filter(array_map('trim', explode("\n", get_option('security_blocked_patterns', ''))));
    }
}
