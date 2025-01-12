<?php

// includes/class-headers.php
class SecurityHeaders {
    private static $headers_sent = false;
    
    public function add_security_headers() {
        if (self::$headers_sent || headers_sent() || !get_option('security_enable_xss', true)) {
            return;
        }
        
        self::$headers_sent = true;
        $this->set_csp_headers();
        $this->set_security_headers();
    }


    private function set_csp_headers() {
        header("Content-Security-Policy: ".
            "default-src 'self' *.google.com *.doubleclick.net; " .
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.googleapis.com *.gstatic.com *.google.com *.doubleclick.net *.googleadservices.com *.google-analytics.com; " .
            "style-src 'self' 'unsafe-inline' *.googleapis.com; " .
            "img-src 'self' data: *.googleapis.com *.gstatic.com *.google.com *.doubleclick.net secure.gravatar.com; " .
            "font-src 'self' data: *.gstatic.com; " .
            "connect-src 'self' *.google.com *.doubleclick.net; " .
            "frame-src 'self' *.google.com *.doubleclick.net; " .
            "object-src 'none'; " .
            "upgrade-insecure-requests"
        );
    }

    private function set_security_headers() {
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: same-origin');
        header('Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
        header_remove('Server');
    }
}
