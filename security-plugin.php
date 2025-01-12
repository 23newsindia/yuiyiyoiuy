<?php
/*
Plugin Name: Custom Security Plugin
Description: Security plugin with URL exclusion, blocking, and comprehensive security features
Version: 1.2
Author: Your Name
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load components
require_once plugin_dir_path(__FILE__) . 'includes/class-waf.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-headers.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-consent.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-sanitization.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-feature-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-settings.php';

class CustomSecurityPlugin {
    private $waf;
    private $headers;
    private $cookie_consent;
    private $sanitization;
    private $feature_manager;
    private $settings;

    public function __construct() {
        $this->init_components();
        $this->add_hooks();
    }

    private function init_components() {
        $this->waf = new SecurityWAF();
        $this->headers = new SecurityHeaders();
        $this->cookie_consent = new CookieConsent();
        $this->sanitization = new SecuritySanitization();
        $this->feature_manager = new FeatureManager();
        $this->settings = new SecuritySettings();
    }

    private function add_hooks() {
        add_action('admin_menu', array($this->settings, 'add_admin_menu'));
        // Removed the incorrect hook for check_security
        add_action('plugins_loaded', array($this->feature_manager, 'init'));
        add_action('admin_init', array($this->settings, 'register_settings'));
        add_action('init', array($this->headers, 'add_security_headers'));
    }
}

// Initialize the plugin
$custom_security_plugin = new CustomSecurityPlugin();