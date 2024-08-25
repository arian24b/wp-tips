<?php
/*
Plugin Name: Log Requests
Description: A plugin to log all requests to a text file.
Version: 1.0
Author: Your Name
*/

function log_request() {
    // مسیر فایل لاگ
    $log_file = WP_CONTENT_DIR . '/uploads/request_logs.txt';

    // لینک فعلی را دریافت کنید
    $current_url = home_url( add_query_arg( null, null ) );

    // اطلاعات درخواست را ذخیره کنید
    $log_entry = date( 'Y-m-d H:i:s' ) . " - " . $current_url . " - IP: " . $_SERVER['REMOTE_ADDR'] . "\n";

    // نوشتن در فایل لاگ
    file_put_contents( $log_file, $log_entry, FILE_APPEND );
}

// اجرای تابع هنگام بارگذاری هر صفحه
add_action( 'wp_head', 'log_request' );