
---
## Autocomplete-Virtual-and-Downloadable-Orders
```php
function custom_woocommerce_auto_complete_virtual_orders( $order_id ) {
  // if in admin area, exit
  if ( is_admin() ) {
    return;
  }

  // if there is no order id, exit
  if ( !$order_id ) {
    return;
  }

  // get the order and its items
  $order = wc_get_order( $order_id );
  $items = $order->get_items();

  // if there are no items, exit
  if ( 0 >= count( $items ) ) {
    return;
  }

  // initialize variables
  $has_non_virtual_product = false;

  // go through each item
  foreach ( $items as $item ) {
    // get the product object based on product id
    $product = wc_get_product( $item->get_product_id() );

    // check if the product is non-virtual and non-downloadable
    if ( !$product->is_virtual() && !$product->is_downloadable() ) {
      $has_non_virtual_product = true;
      break; // exit the loop if a non-virtual, non-downloadable product is found
    }
  }

  // if the order contains a non-virtual, non-downloadable product
  if ( $has_non_virtual_product ) {
    // set the order status to processing
    $order->update_status( 'processing' );
  } else {
    // set the order status to completed
    $order->update_status( 'completed' );
  }
}

add_action( 'woocommerce_order_status_changed', 'custom_woocommerce_auto_complete_virtual_orders', 9999, 1 );
```
---
## Automatically-Add-Gift-Product-to-Cart
```php
// Add free gifted product for specific cart subtotal
add_action( 'woocommerce_before_calculate_totals', 'check_free_gifted_product_1000000' );
function check_free_gifted_product_1000000( $cart ) {
if ( is_admin() && ! defined( 'DOING_AJAX' ) )
return;

// Settings
$free_product_id = 123; // GIFT PRODUCT ID
$targeted_subtotal = 100000; // MINIMUM AMOUNT OF CART

$cart_subtotal = 0; // Initializing

// Loop through cart items (first loop)
foreach ( $cart->get_cart() as $cart_item_key => $cart_item ){
// When free product is in cart
if ( $free_product_id == $cart_item['variation_id'] ) {
$free_key = $cart_item_key;
$free_qty = $cart_item['quantity'];
$cart_item['data']->set_price(0); // Optionally set the price to zero
} elseif(38736 != $cart_item['product_id']) {
$cart_subtotal += $cart_item['line_total'] + $cart_item['line_tax'];
}
}

// If subtotal match and free product is not already in cart, add it
if ( ! isset($free_key) && $cart_subtotal >= $targeted_subtotal ) {
$cart->add_to_cart( $free_product_id );
}
// If subtotal doesn't match and free product is already in cart, remove it
elseif ( isset($free_key) && $cart_subtotal < $targeted_subtotal ) { $cart->remove_cart_item( $free_key );
}
// Keep free product quantity to 1.
elseif ( isset($free_qty) && $free_qty > 1 ) {
$cart->set_quantity( $free_key, 1 );
}
}





// Display free gifted product price to zero on minicart
add_filter( 'woocommerce_cart_item_price', 'change_minicart_free_gifted_item_price_1000000', 10, 3 );
function change_minicart_free_gifted_item_price_1000000( $price_html, $cart_item, $cart_item_key ) {
$free_product_id = 123; // GIFT PRODUCT ID

if( $cart_item['variation_id'] == $free_product_id ) {
return wc_price( 0 );
}
return $price_html;
}
```
---
## User-Registration-Date-Shortcode
```php
function display_user_register_date () {
  global $wp_query;
  $registered = date_i18n( "m M, Y", strtotime( get_the_author_meta( 'user_registered', get_current_user_id() ) ) );
  return $registered;
}

add_shortcode('user_register_date', 'display_user_register_date');
```
---
## Unset-Website-Field-in-Comment-Form
```php
add_filter('comment_form_default_fields', 'unset_url_field_comments');
function unset_url_field_comments($fields){
    if(isset($fields['url']))
       unset($fields['url']);
       return $fields;
}
```
---
## Translation-Function
```php
add_filter( 'gettext', 'my_translate_strings', 999, 3 );

function my_translate_strings( $translated, $text, $domain ) {

$translated = str_ireplace( 'ORIGINAL_TEXT', 'TRANSLATED_TEXT', $translated );

// ETC.

return $translated;
}
```
---
## SpeedUp-WordPress-Dashboard
```php
function TheTextHasString($text, $string) {
return strpos($text, $string) !== false;
}


function BlockExternalHostRequests ($false, $parsed_args, $url) {
$blockedHosts = [
'github.com',
'yoast.com',
'api.wordpress.org',
'w.org',
'yoa.st',
'unyson.io',
'siteorigin.com',
'elementor.com',
'woocommerce.com'

];

foreach ( $blockedHosts as $host ) {
if ( !empty($host) && TheTextHasString($url, $host) ) {
return [
'headers' => '',
'body' => '',
'response' => '',
'cookies' => '',
'filename' => ''
];
}
}

return $false;
}
add_filter('pre_http_request', 'BlockExternalHostRequests', 10, 3);
```
---
## Secure-WP-Admin-Login-Page
```php
/* Step 1: Create a new login page in WP root(public_html) with a PHP extension (FILE_NAME.php) and add the code provided below to this file: */
<?php
setcookie("FILE_NAME", 0123456789);
header("Location: wp-login.php");

/* Step 1 Description:
Please replace "FILE_NAME" with the name of the PHP file you created. The file name should only include the name without the PHP extension.
For example, I chose this name for my PHP File: WP-MyWeb@Dm!n
You can modify the 10-digit number between 0 and 9 to any value you prefer, keeping it as a 10-digit number.
*/

/***************************************************************************************************************/

/* Step 2: Modify your .htaccess file by adding the following code to it: */
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteCond %{HTTP_COOKIE} !^.*WP\-MyWeb@Dm!n=0123456789.*$ [NC]
RewriteRule wp-login.php - [F]
</IfModule>

/* Step 2 Description:
Please replace "WP-MyWeb@Dm!n" in line 4 with the name of your PHP file. Also, instead of the number range from 0 to 9, insert the actual value you set in your PHP file.
If your PHP file name follows a similar structure to the example I provided (with a hyphen after "WP"), you should add a backslash after "WP" in line 4 of the htaccess code.
After making these changes, attempting to access the previous addresses of wp-admin or wp-login will result in a 403 error.
Going forward, the new address to access the login page of your website will be:

yourdomain/YOUR_PHP_FILE_NAME.php

Replace "YOUR_PHP_FILE_NAME" with the name of the PHP file you created in step 1. For example, in my case:
https://example.com/WP-MyWeb@Dm!n.php
*/

/***************************************************************************************************************/

/* Important note:
When selecting a name for your PHP file, you have the flexibility to use special characters like @, _, !, and others.
However, based on the tests conducted, certain characters such as # and $ can cause issues. If your file name includes these problematic characters, accessing the page may result in a 404 error.
Unfortunately, the reason behind this specific behavior is unknown. It is advisable to avoid using # and $ in your PHP file names to ensure smooth access to the page.
*/
```
---
## Reorder-WooCommerce-Checkout-Fields
```php
add_filter( 'woocommerce_checkout_fields', 'reorder_fields' );
 
function reorder_fields( $checkout_fields ) {
    $checkout_fields['billing']['billing_first_name']['priority'] = 1;
    $checkout_fields['billing']['billing_last_name']['priority'] = 2;
$checkout_fields['billing']['billing_phone']['priority'] = 3;
    $checkout_fields['billing']['billing_email']['priority'] = 4;
    $checkout_fields['billing']['billing_state']['priority'] = 5;
    $checkout_fields['billing']['billing_city']['priority'] = 6;
    $checkout_fields['billing']['billing_address_1']['priority'] = 7;
    $checkout_fields['billing']['billing_postcode']['priority'] = 8;

	return $checkout_fields;
}
```
---
## Remove-WordPress-Version-Number
```php
function remove_wp_version_rss() {
 return'';
 }
add_filter('the_generator','remove_wp_version_rss');
```
---
## Remove-Author-Default-Sitemap
```php
/* Step 1: Remove Author Sitemap */

function remove_author_category_pages_from_sitemap($provider, $name)
{
    if ('users' === $name) {
        return false;
    }
    return $provider;
}

add_filter('wp_sitemaps_add_provider', 'remove_author_category_pages_from_sitemap', 10, 2);

/***************************************************************************************************************/

/* Step 2: Redirect Author Page to 404 */

// Redirect Author Page to 404
function rn_redirect_author_page() {
  global $wp_query;

  if ( is_author() ) {
    // Redirect to 404 error page
    $wp_query->set_404();
    status_header(404);
  }
}
add_action( 'template_redirect', 'rn_redirect_author_page');
```
---
## Redirect-User-to-Home-Page-After-Logout
```php
add_action('wp_logout','auto_redirect_after_logout');
function auto_redirect_after_logout(){
  wp_safe_redirect( home_url() );
  exit();
}
```
---
## Redirect-to-Previous-Page-After-Login-or-Registration
```php
// Start global session for saving the referer URL

function start_session() {

if (!session_id()) {

session_start();

}

}

add_action('init', 'start_session', 1);

  

// Get referer URL and save it

function redirect_url() {

if (!is_user_logged_in()) {

$_SESSION['referer_url'] = wp_get_referer();

} else {

session_destroy();

}

}

add_action('template_redirect', 'redirect_url');

  

// Login redirect

function login_redirect() {

if (isset($_SESSION['referer_url'])) {

wp_redirect($_SESSION['referer_url']);

} elseif (isset($_GET['redirect_to'])) {

wp_redirect($_GET['redirect_to']);

} else {

wp_redirect(home_url('/my-account/'));

}

exit();

}

add_filter('woocommerce_login_redirect', 'login_redirect', 1100, 2);

  

// Registration redirect

function registration_redirect($redirect) {

if (isset($_SESSION['referer_url'])) {

$redirect = $_SESSION['referer_url'];

unset($_SESSION['referer_url']);

}

return $redirect;

}

add_filter('woocommerce_registration_redirect', 'registration_redirect');
```
---
## onlyFreeShippingActie
```php
add_filter('woocommerce_package_rates', 'custom_shipping_method_disable_others', 10, 2);

function custom_shipping_method_disable_others($rates, $package) {
    // Exception Method
    $Exception_Shipping = 15;
    
    // Check If Free Shipping is Available
    $free_shipping_available = false;
    foreach ($rates as $rate_key => $rate) {
        if ('free_shipping' === $rate->method_id) {
            $free_shipping_available = true;
            break;
        }
    }

    // Deactive Other Method
    if ($free_shipping_available) {
        foreach ($rates as $rate_key => $rate) {
            if ('free_shipping' !== $rate->method_id && $Exception_Shipping != $rate->instance_id) {
                unset($rates[$rate_key]);
            }
        }
    }

    return $rates;
}
```
---
## Iranian-National-Code-Field-in-WC-Checkout
```php
//The function of checking the accuracy of the national code
function  check_national_code($code) {
    if( !preg_match('/^[0-9]{10}$/',$code) )
        return false;
    for( $i=0; $i<10; $i++ )
        if( preg_match('/^'.$i.'{10}$/',$code) )
            return false;
        for( $i=0,$sum=0;$i<9;$i++ )
            $sum += ((10-$i) * intval(substr($code, $i,1)));
    $ret = $sum%11;
    $parity = intval(substr($code, 9,1));
    if( ($ret<2 && $ret==$parity) || ($ret>=2 && $ret==11-$parity) )
        return true;
     
    return false;
}


// Adding national code field to WooCommerce Checkout page
function add_custom_national_code_field() {
    echo '<div class="form-row form-row-wide woocommerce-additional-fields__field-wrapper">
                <label for="billing_national_code">' . __('کد ملی', 'your-theme-domain') . ' <span class="required">*</span></label>
                <span class="woocommerce-input-wrapper"><input type="text" class="input-text" name="billing_national_code" id="billing_national_code" value="' . esc_attr(isset($_POST['billing_national_code']) ? $_POST['billing_national_code'] : '') . '" /></span>
        </div>';
}
add_action('woocommerce_after_checkout_billing_form', 'add_custom_national_code_field');
  

function validate_custom_national_code_field() {
    $code = isset($_POST['billing_national_code']) ? sanitize_text_field($_POST['billing_national_code']) : '';
  
    if (!empty($code) && ! check_national_code($code)) {
        wc_add_notice( __( 'کد ملی وارد شده معتبر نمی باشد!' ), 'error' );
    }
}
add_action('woocommerce_checkout_process', 'validate_custom_national_code_field');


// Saved national code in the order
function save_custom_national_code_field($order_id) {
    if (!empty($_POST['billing_national_code'])) {
        update_post_meta($order_id, 'billing_national_code', sanitize_text_field($_POST['billing_national_code']));
    }
}
add_action('woocommerce_checkout_update_order_meta', 'save_custom_national_code_field');


//Display the national code in the orders section of the admin
function  checkout_field_display_admin_order_meta($order){
    echo '<p><strong>'.__('کد ملی').':</strong> ' . get_post_meta( $order->id, 'billing_national_code', true ) . '</p>';
}
add_action( 'woocommerce_admin_order_data_after_billing_address', 'checkout_field_display_admin_order_meta', 10, 1 );
```
---
## index-Custom-WordPress-Login
![Custom WordPress Login](https://github.com/Arminjamali/Custom-WordPress-Login/blob/main/thumb.jpg)


**Repository Description:**

## Custom WordPress Login and Redirect Code

This code snippet enhances the WordPress login process, offering advanced redirection features based on user roles and a predefined hash parameter. The snippet includes a custom rewrite rule and query variable for additional flexibility.

### Features:

- **Custom Login Redirect:**
  - Redirects administrators to the WordPress admin dashboard upon login.
  - Allows for custom redirection for users with a specific hash parameter (`mylogin`).

- **Prevent Default WP Login Redirect:**
  - Prevents automatic redirection to the default WordPress login page.
  - Displays a 404 error if users attempt to access `wp-login.php` without the necessary parameters.

- **Custom Rewrite Rule:**
  - Adds a custom rewrite rule for the endpoint `wp-armin`.

- **Custom Query Variable:**
  - Introduces a custom query variable (`mylogin`) for handling special login scenarios.

- **Template Redirect:**
  - Redirects users to `wp-login.php` with a hashed value when the custom query variable is set to `true`.

### Usage:

1. Integrate the code into your WordPress theme's `functions.php` file or create a custom plugin.
2. Customize the code behavior by modifying the provided functions.
3. Access the login page using the custom endpoint: `your-site.com/wp-armin`.
4. Utilize the `mylogin` query parameter with the hashed value (`6666`) for special login scenarios.

### Important Note:

Understand the implications of modifying the login and redirection process. This code is intended for educational purposes and should be used cautiously in production environments.

### Disclaimer:

This code snippet is provided as-is without any warranty. Use at your own risk. Feel free to integrate, modify, or use the code for your specific WordPress customization needs.
```php
<?php

function custom_login_redirect($redirect_to, $request, $user)
{
    // Set the default redirect page to the home URL
    $redirect_page = home_url();

    // If the user is an administrator, redirect to the admin URL
    if (is_array($user->roles) && in_array('administrator', $user->roles)) {
        return admin_url();
    }

    // Check if the mylogin parameter is present and matches a predefined hash, if yes, return the current redirect_to value
    if (isset($_GET['mylogin']) && $_GET['mylogin'] == password_hash('6666', PASSWORD_BCRYPT)) {
        return $redirect_to; // Or any desired value for no redirection
    }

    // Check if the user is an administrator and redirect to the admin URL
    if (is_array($user->roles) && in_array('administrator', $user->roles)) {
        return admin_url();
    }

    // Return the default redirect page
    return $redirect_page;
}

function prevent_wp_login_redirect()
{
    // If the user is trying to access wp-login.php and the armin cookie is not set, return a 404 error
    if (strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false && !is_user_logged_in()) {
        if (!isset($_GET['mylogin']) && $_POST == array()) {
            status_header(404);
            wp_die('404 Not Found - Page not found', '404 Not Found');
        }
    }
}

add_filter('login_redirect', 'custom_login_redirect', 10, 3);
add_action('init', 'prevent_wp_login_redirect');

function custom_rewrite_rule()
{
    // Add a custom rewrite rule for the endpoint wp-armin
    add_rewrite_rule('^wp-armin/?$', 'index.php?mylogin=true', 'top');
}

add_action('init', 'custom_rewrite_rule');

function custom_query_vars($query_vars)
{
    // Add the custom query variable mylogin
    $query_vars[] = 'mylogin';
    return $query_vars;
}

add_filter('query_vars', 'custom_query_vars');

function custom_template_redirect()
{
    // Check if the mylogin query variable is set to true, then redirect to wp-login.php with the hashed value
    $my_login = get_query_var('mylogin');
    if ($my_login === 'true') {
        $mylogin_value = password_hash('6666', PASSWORD_BCRYPT);
        $redirect_url = add_query_arg('mylogin', $mylogin_value, home_url('/wp-login.php'));
        wp_redirect($redirect_url);
        exit();
    }
}

add_action('template_redirect', 'custom_template_redirect');
```
---
## Google-reCAPTCHA-for-Comments-Form
```php
/* DON'T FORGET TO INSERT YOUR SITE KEY AND YOUR SECRET KEY IN THE BELOW LINES! */

function enqueue_recaptcha_script() {
    if (is_singular('post') && comments_open()) {
        wp_enqueue_script('recaptcha', 'https://www.google.com/recaptcha/api.js', array(), null, true);
    }
}
add_action('wp_enqueue_scripts', 'enqueue_recaptcha_script');

function wpb_move_comment_field_to_bottom( $fields ) {
    $comment_field = $fields['comment'];
    unset( $fields['comment'] );
    $fields['comment'] = $comment_field;

    if (is_singular('post') && comments_open()) {
        $site_key = 'YOUR_SITE_KEY'; // Replace with your reCaptcha site key
        $fields['recaptcha'] = '<div class="comment-form-recaptcha" style="margin-bottom: 20px">';
        $fields['recaptcha'] .= '<div class="g-recaptcha" data-sitekey="' . $site_key . '"></div>';
        $fields['recaptcha'] .= '</div>';
    }

    return $fields;
}
add_filter( 'comment_form_fields', 'wpb_move_comment_field_to_bottom' );

function verify_comment_captcha($commentdata) {
    if (is_singular('post') && comments_open()) {
        $secret_key = 'YOUR_SECRET_KEY'; // Replace with your reCaptcha secret key
        $captcha = $_POST['g-recaptcha-response'];
        $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$secret_key}&response={$captcha}");
        $response = json_decode($response);

        if (!$response->success) {
            wp_die(__('Error: Captcha verification failed.'));
        }
    }

    return $commentdata;
}
add_filter('preprocess_comment', 'verify_comment_captcha');
```
---
## Google-reCAPTCHA
```php
function my_recaptcha_key() {
    $sitekey = "YOUR_SITE_KEY";
    $secretkey = "YOUR_SECRET_KEY";
    return explode(",", $sitekey . "," . $secretkey);
}

/* DON'T FORGET TO INSERT YOUR SITE KEY AND YOUR SECRET KEY IN THE ABOVE LINES! */

/*
 * Add reCaptcha on WordPress Admin Login Page Without Plugin
 */
function login_style() {
    // Check if the current page is wp-login.php
    if (basename($_SERVER['PHP_SELF']) === 'wp-login.php') {
        wp_register_script('login-recaptcha', 'https://www.google.com/recaptcha/api.js', false, NULL);
        wp_enqueue_script('login-recaptcha');
    }
}
add_action('login_enqueue_scripts', 'login_style');

function add_recaptcha_on_login_page() {
    // Check if the current page is wp-login.php
    if (basename($_SERVER['PHP_SELF']) === 'wp-login.php') {
        echo '<div class="g-recaptcha brochure__form__captcha" data-sitekey="' . my_recaptcha_key()[0] . '"></div>';
    }
}
add_action('login_form', 'add_recaptcha_on_login_page');

function captcha_login_check($user, $password) {
    // Check if the current page is wp-login.php
    if (basename($_SERVER['PHP_SELF']) === 'wp-login.php') {
        if (!empty($_POST['g-recaptcha-response'])) {
            $secret = my_recaptcha_key()[1];
            $ip = $_SERVER['REMOTE_ADDR'];
            $captcha = $_POST['g-recaptcha-response'];
            $rsp = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret=' . $secret . '&response=' . $captcha . '&remoteip=' . $ip);
            $valid = json_decode($rsp, true);
            if ($valid["success"] == true) {
                return $user;
            } else {
                return new WP_Error('Captcha Invalid', __('<center>Captcha Invalid! Please check the captcha!</center>'));
            }
        } else {
            return new WP_Error('Captcha Invalid', __('<center>Captcha Invalid! Please check the captcha!</center>'));
        }
    } else {
        return $user;
    }
}
add_action('wp_authenticate_user', 'captcha_login_check', 10, 2);
```
---
## Free-Shipping-Notification-Remaining-Amount
```php
/**
 * Show a message at the cart/checkout displaying
 * how much to go for free shipping.
 */
function my_custom_wc_free_shipping_notice() {

	if ( ! is_cart() ) { // Remove partial if you don't want to show it on cart/checkout
		return;
	}

	$packages = WC()->cart->get_shipping_packages();
	$package = reset( $packages );
	$zone = wc_get_shipping_zone( $package );
	global $woocommerce;

	$cart_total = WC()->cart->get_displayed_subtotal();
	if ( WC()->cart->display_prices_including_tax() ) {
		$cart_total = round( $cart_total - ( WC()->cart->get_discount_total() + WC()->cart->get_discount_tax() ), wc_get_price_decimals() );
	} else {
		$cart_total = round( $cart_total - WC()->cart->get_discount_total(), wc_get_price_decimals() );
	}
	foreach ( $zone->get_shipping_methods( true ) as $k => $method ) {
		$min_amount = $method->get_option( 'min_amount' );

        if ( $woocommerce->cart->cart_contents_count != 0 && $method->id == 'free_shipping' && ! empty( $min_amount ) && $cart_total < $min_amount ) {
			$remaining = $min_amount - $cart_total;
			wc_add_notice( sprintf( 'Add %s more to get free shipping!', wc_price( $remaining ) ) );
		}
	}

}
add_action( 'wp', 'my_custom_wc_free_shipping_notice' );
```
---
## ForcedCheckoutLogin
```php 
<?php 

// This code is utilized by the Forced Login Page Lock plugin, ensuring that users log in before accessing the checkout page.

add_action('template_redirect', 'redirect_to_my_account_if_not_logged_in');

function redirect_to_my_account_if_not_logged_in() {
    // If the user is not logged in and is on the checkout page
    if (!is_user_logged_in() && is_checkout()) {
        // Redirect to the My Account page
        wp_redirect(wc_get_page_permalink('myaccount'));
        exit;
    }
}

add_action('woocommerce_login_redirect', 'redirect_to_checkout_after_login');

function redirect_to_checkout_after_login($redirect_to) {
    // If the user logged in from the checkout page
    if (strpos($redirect_to, 'checkout') !== false) {
        // Redirect to the checkout page
        return wc_get_checkout_url();
    }
    // Otherwise, return the remaining redirects
    return $redirect_to;
}


?>
```
---
## Display-Notice-on-WooCommerce-Checkout-Page
```php
add_action( 'woocommerce_before_checkout_form', 'skyverge_add_checkout_success', 9 );
function skyverge_add_checkout_success() {
	wc_print_notice( __( ' YOUR_TEXT', 'woocommerce' ), 'error' );
}
```
---
## Disable-HTML-Tags-in-Comments
```php
function convert_comment_html_entities($comment_text) {
    $comment_text = htmlspecialchars($comment_text);
    $comment_text = make_clickable($comment_text);
    return $comment_text;
}

function disable_comment_links($comment_text) {
    $comment_text = strip_tags($comment_text);
    return $comment_text;
}

add_filter('comment_text', 'convert_comment_html_entities', 10, 1);
add_filter('comment_text', 'disable_comment_links', 20, 1);
```
---
## Disable-Gutenberg
```php
/** Function 1 **/

if (version_compare($GLOBALS['wp_version'], '5.0-beta', '>')) {
	
	// WP > 5 beta
	add_filter('use_block_editor_for_post_type', '__return_false', 100);
	
} else {
	
	// WP < 5 beta
	add_filter('gutenberg_can_edit_post_type', '__return_false');
	
}

****************************************

/** Function 2 **/

// Disable Gutenberg on the back end.
add_filter( 'use_block_editor_for_post', '__return_false' );

// Disable Gutenberg for widgets.
add_filter( 'use_widgets_block_editor', '__return_false' );

add_action( 'wp_enqueue_scripts', function() {
    // Remove CSS on the front end.
    wp_dequeue_style( 'wp-block-library' );

    // Remove Gutenberg theme.
    wp_dequeue_style( 'wp-block-library-theme' );

    // Remove inline global CSS on the front end.
    wp_dequeue_style( 'global-styles' );

    // Remove classic-themes CSS for backwards compatibility for button blocks.
    wp_dequeue_style( 'classic-theme-styles' );
}, 20 );

****************************************

/** Function 3 **/
// If you want to disable Gutenberg for a specific post type, use the code below:

add_filter( 'use_block_editor_for_post_type', function( $enabled, $post_type ) {
    return 'your_post_type' === $post_type ? false : $enabled;
}, 10, 2 );
```
---
## Disable-All-Updates
```php
function remove_core_updates(){
    global $wp_version;return(object) array('last_checked'=> time(),'version_checked'=> $wp_version,);
}
add_filter('pre_site_transient_update_core','remove_core_updates'); // disable updates for WordPress itself (WP Core)
add_filter('pre_site_transient_update_plugins','remove_core_updates'); // disable updates for all plugins
add_filter('pre_site_transient_update_themes','remove_core_updates'); // disable updates for all themes
```
## benchmark
```php
<?php

/**
 * PHP Script to benchmark PHP and MySQL-Server.
 *
 * inspired by / thanks to:
 * - www.php-benchmark-script.com (Alessandro Torrisi)
 * - www.webdesign-informatik.de
 *
 * @license MIT
 */

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------
set_time_limit(120); // 2 minutes

$options = [];

// Show or hide the server name and IP address
$showServerName = false;

// Optional: mysql performance test
//$options['db.host'] = '';
//$options['db.user'] = '';
//$options['db.pw'] = '';
//$options['db.name'] = '';

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
// check performance
$benchmarkResult = test_benchmark($options);

// benchmark.php?json
if (isset($_GET['json'])) {
    // Json output
    header('Content-Type', 'application/json');
    echo json_encode($benchmarkResult, JSON_PRETTY_PRINT);
} else {
    // html output
    echo print_html_result($benchmarkResult, $showServerName);
}

exit;

// -----------------------------------------------------------------------------
// Benchmark functions
// -----------------------------------------------------------------------------

function test_benchmark(array $settings)
{
    $result = [];
    $result['version'] = '1.6';
    $result['sysinfo']['time'] = date('Y-m-d H:i:s');
    $result['sysinfo']['php_version'] = PHP_VERSION;
    $result['sysinfo']['platform'] = PHP_OS;
    $result['sysinfo']['server_name'] = $_SERVER['SERVER_NAME'];
    $result['sysinfo']['server_addr'] = $_SERVER['SERVER_ADDR'];
    $result['sysinfo']['xdebug'] = in_array('xdebug', get_loaded_extensions());

    $timeStart = microtime(true);

    test_math($result);
    test_string($result);
    test_loops($result);
    test_ifelse($result);

    $result['benchmark']['calculation'] = timer_diff($timeStart) . ' sec.';

    if (isset($settings['db.host'])) {
        test_mysql($result, $settings);
    }

    $result['benchmark']['total'] = timer_diff($timeStart) . ' sec.';

    return $result;
}

function test_math(&$result, $count = 99999)
{
    $timeStart = microtime(true);

    for ($i = 0; $i < $count; $i++) {
        sin($i);
        asin($i);
        cos($i);
        acos($i);
        tan($i);
        atan($i);
        abs($i);
        floor($i);
        exp($i);
        is_finite($i);
        is_nan($i);
        sqrt($i);
        log10($i);
    }

    $result['benchmark']['math'] = timer_diff($timeStart) . ' sec.';
}

function test_string(&$result, $count = 99999)
{
    $timeStart = microtime(true);

    $string = 'the quick brown fox jumps over the lazy dog';
    for ($i = 0; $i < $count; $i++) {
        addslashes($string);
        chunk_split($string);
        metaphone($string);
        strip_tags($string);
        md5($string);
        sha1($string);
        strtoupper($string);
        strtolower($string);
        strrev($string);
        strlen($string);
        soundex($string);
        ord($string);
    }
    $result['benchmark']['string'] = timer_diff($timeStart) . ' sec.';
}

function test_loops(&$result, $count = 999999)
{
    $timeStart = microtime(true);
    for ($i = 0; $i < $count; ++$i) {
    }

    $i = 0;
    while ($i < $count) {
        ++$i;
    }

    $result['benchmark']['loops'] = timer_diff($timeStart) . ' sec.';
}

function test_ifelse(&$result, $count = 999999)
{
    $timeStart = microtime(true);
    for ($i = 0; $i < $count; $i++) {
        if ($i == -1) {
        } elseif ($i == -2) {
        } else {
            if ($i == -3) {
            }
        }
    }
    $result['benchmark']['ifelse'] = timer_diff($timeStart) . ' sec.';
}

function test_mysql(&$result, $settings)
{
    $timeStart = microtime(true);

    $link = mysqli_connect($settings['db.host'], $settings['db.user'], $settings['db.pw']);
    $result['benchmark']['mysql_connect'] = timer_diff($timeStart) . ' sec.';

    mysqli_select_db($link, $settings['db.name']);
    $result['benchmark']['mysql_select_db'] = timer_diff($timeStart) . ' sec.';

    $dbResult = mysqli_query($link, 'SELECT VERSION() as version;');
    $arr_row = mysqli_fetch_array($dbResult);
    $result['sysinfo']['mysql_version'] = $arr_row['version'];
    $result['benchmark']['mysql_query_version'] = timer_diff($timeStart) . ' sec.';

    $query = "SELECT BENCHMARK(1000000, AES_ENCRYPT('hello', UNHEX('F3229A0B371ED2D9441B830D21A390C3')));";
    mysqli_query($link, $query);
    $result['benchmark']['mysql_query_benchmark'] = timer_diff($timeStart) . ' sec.';

    mysqli_close($link);

    $result['benchmark']['mysql_total'] = timer_diff($timeStart) . ' sec.';

    return $result;
}

function timer_diff($timeStart)
{
    return number_format(microtime(true) - $timeStart, 3);
}

function print_html_result(array $data, bool $showServerName = true)
{
    echo "<!DOCTYPE html>\n<html><head>\n";
    echo "<style>
       table a:link {
        color: #666;
        font-weight: bold;
        text-decoration:none;
    }
    table a:visited {
        color: #999999;
        font-weight:bold;
        text-decoration:none;
    }
    table a:active,
    table a:hover {
        color: #bd5a35;
        text-decoration:underline;
    }
    table {
        font-family:Arial, Helvetica, sans-serif;
        color:#666;
        font-size:12px;
        text-shadow: 1px 1px 0px #fff;
        background:#eaebec;
        margin:20px;
        border:#ccc 1px solid;
        -moz-border-radius:3px;
        -webkit-border-radius:3px;
        border-radius:3px;
        -moz-box-shadow: 0 1px 2px #d1d1d1;
        -webkit-box-shadow: 0 1px 2px #d1d1d1;
        box-shadow: 0 1px 2px #d1d1d1;
    }
    table th {
        padding:8px 15px 8px 8px;
        border-top:1px solid #fafafa;
        border-bottom:1px solid #e0e0e0;
        text-align: left;
        background: #ededed;
        background: -webkit-gradient(linear, left top, left bottom, from(#ededed), to(#ebebeb));
        background: -moz-linear-gradient(top,  #ededed,  #ebebeb);
    }
    table th:first-child {
        text-align: left;
        padding-left:10px;
    }
    table tr:first-child th:first-child {
        -moz-border-radius-topleft:3px;
        -webkit-border-top-left-radius:3px;
        border-top-left-radius:3px;
    }
    table tr:first-child th:last-child {
        -moz-border-radius-topright:3px;
        -webkit-border-top-right-radius:3px;
        border-top-right-radius:3px;
    }
    table tr {
        padding-left:10px;
    }
    table td:first-child {
        text-align: left;
        padding-left:10px;
        border-left: 0;
    }
    table td {
        padding:8px;
        border-top: 1px solid #ffffff;
        border-bottom:1px solid #e0e0e0;
        border-left: 1px solid #e0e0e0;
        background: #fafafa;
        background: -webkit-gradient(linear, left top, left bottom, from(#fbfbfb), to(#fafafa));
        background: -moz-linear-gradient(top,  #fbfbfb,  #fafafa);
    }
    table tr.even td {
        background: #f6f6f6;
        background: -webkit-gradient(linear, left top, left bottom, from(#f8f8f8), to(#f6f6f6));
        background: -moz-linear-gradient(top,  #f8f8f8,  #f6f6f6);
    }
    table tr:last-child td {
        border-bottom:0;
    }
    table tr:last-child td:first-child {
        -moz-border-radius-bottomleft:3px;
        -webkit-border-bottom-left-radius:3px;
        border-bottom-left-radius:3px;
    }
    table tr:last-child td:last-child {
        -moz-border-radius-bottomright:3px;
        -webkit-border-bottom-right-radius:3px;
        border-bottom-right-radius:3px;
    }
    table tr:hover td {
        background: #f2f2f2;
        background: -webkit-gradient(linear, left top, left bottom, from(#f2f2f2), to(#f0f0f0));
        background: -moz-linear-gradient(top,  #f2f2f2,  #f0f0f0);	
    }
    </style>
    </head>
    <body>";

    $result = '<table cellspacing="0">';
    $result .= '<thead><tr><th>System Info</th><th></th></tr></thead>';
    $result .= '<tbody>';
    $result .= '<tr class="even"><td>Version</td><td>' . h($data['version']) . '</td></tr>'."\n";
    $result .= '<tr class="even"><td>Time</td><td>' . h($data['sysinfo']['time']) . '</td></tr>'."\n";

    if (!empty($data['sysinfo']['xdebug'])) {
        // You are running the benchmark with xdebug enabled. This has a major impact on runtime performance.
        $result .= '<tr class="even"><td>Xdebug</td><td><span style="color: darkred">'
            . h('Warning: Xdebug is enabled!')
            . '</span></td></tr>';
    }

    $result .= '<tr class="even"><td>PHP Version</td><td>' . h($data['sysinfo']['php_version']) . '</td></tr>'."\n";
    $result .= '<tr class="even"><td>Platform</td><td>' . h($data['sysinfo']['platform']) . '</td></tr>'."\n";

    if ($showServerName == true) {
        $result .= '<tr class="even"><td>Server name</td><td>' . h($data['sysinfo']['server_name']) . '</td></tr>'."\n";
        $result .= '<tr class="even"><td>Server address</td><td>' . h($data['sysinfo']['server_addr']) . '</td></tr>'."\n";
    }

    $result .= '</tbody>';

    $result .= '<thead><tr><th>Benchmark</th><th></th></tr></thead>';
    $result .= '<tbody>';
    $result .= '<tr><td>Math</td><td>' . h($data['benchmark']['math']) . '</td></tr>'."\n";
    $result .= '<tr><td>String</td><td>' . h($data['benchmark']['string']) . '</td></tr>'."\n";
    $result .= '<tr><td>Loops</td><td>' . h($data['benchmark']['loops']) . '</td></tr>'."\n";
    $result .= '<tr><td>If Else</td><td>' . h($data['benchmark']['ifelse']) . '</td></tr>'."\n";
    $result .= '<tr class="even"><td>Calculation total</td><td>' . h(
            $data['benchmark']['calculation']
        ) . '</td></tr>';
    $result .= '</tbody>';

    if (isset($data['sysinfo']['mysql_version'])) {
        $result .= '<thead><tr><th>MySQL</th><th></th></tr></thead>';
        $result .= '<tbody>';
        $result .= '<tr><td>MySQL Version</td><td>' . h($data['sysinfo']['mysql_version']) . '</td></tr>'."\n";
        $result .= '<tr><td>MySQL Connect</td><td>' . h($data['benchmark']['mysql_connect']) . '</td></tr>'."\n";
        $result .= '<tr><td>MySQL Select DB</td><td>' . h($data['benchmark']['mysql_select_db']) . '</td></tr>'."\n";
        $result .= '<tr><td>MySQL Query Version</td><td>' . h($data['benchmark']['mysql_query_version']) . '</td></tr>'."\n";
        $result .= '<tr><td>MySQL Benchmark</td><td>' . h($data['benchmark']['mysql_query_benchmark']) . '</td></tr>'."\n";
        $result .= '<tr class="even"><td>MySQL Total</td><td>' . h($data['benchmark']['mysql_total']) . '</td></tr>'."\n";
        $result .= '</tbody>';
    }

    $result .= '<thead><tr><th>Total</th><th>' . h($data['benchmark']['total']) . '</th></tr></thead>';
    $result .= '</table>';

    echo $result;

    echo "\n</body></html>";
}

function h($v)
{
    return htmlentities($v);
}
```
---
## Change-Address-Field-Label-and-Placeholder-in-Checkout
```php
add_filter('woocommerce_default_address_fields', 'override_default_address_checkout_fields', 20, 1);
function override_default_address_checkout_fields( $address_fields ) {
    $address_fields['address_1']['placeholder'] = 'YOUR_PLACEHOLDER';
	$address_fields['address_1']['label'] = 'YOUR_LABEL';
    return $address_fields;
}
```
---
## Change-default-error-messages
```php
function my_custom_error_messages() {
    if (strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false) {
        global $errors;
        $err_codes = $errors->get_error_codes();

        // Invalid username.
        if (in_array('invalid_username', $err_codes)) {
            $error = '<strong>Error</strong>: Something Wrong!';
        }

        // Invalid username.
        if (in_array('empty_username', $err_codes)) {
            $error = '<strong>Error</strong>: Something Wrong!';
        }

        // Incorrect password.
        if (in_array('incorrect_password', $err_codes)) {
            $error = '<strong>Error</strong>: Something Wrong!';
        }

        if (in_array('empty_password', $err_codes)) {
            $error = '<strong>Error</strong>: Something Wrong!';
        }

        if (in_array('invalid_email', $err_codes)) {
            $error = '<strong>Error</strong>: Something Wrong!';
        }

        return $error;
    } else {
        return '';
    }
}

add_filter('login_errors', 'my_custom_error_messages');
```
---
## customDeliveryTime
```php
<?php

function delivery_checkout_field( $checkout ) {
    date_default_timezone_set('Asia/Tehran');
    
    $current_time = time(); 
    $time_now = date( 'H:i:s', $current_time ); 
    $is_before_noon = date( 'H', $current_time ) < 12;

    // تابع برای بررسی تعطیلی با استفاده از API
    function is_holiday($date) {
        $url = "https://holidayapi.ir/jalali/" . $date;
        $response = wp_remote_get($url);
        if (is_wp_error($response)) {
            return false;
        }
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        if (isset($data['is_holiday']) && $data['is_holiday']) {
            return true;
        }
        return false;
    }

    // پیدا کردن سه روز غیر تعطیل
    $dates = [];
    $day_increment = 0;
    while (count($dates) < 3) {
        $date_to_check = strtotime("+$day_increment days", $current_time);
        $date_to_check_jalali = jdate('Y/m/d', $date_to_check);
        if ($is_before_noon || $day_increment > 0) {
            if (!is_holiday($date_to_check_jalali)) {
                $dates[] = [
                    'date' => $date_to_check_jalali,
                    'day_name' => jdate('l', $date_to_check)
                ];
            }
        }
        $day_increment++;
    }

    // تعریف بازه‌های زمانی
    $time_slots = [
        '16:30-18:00',
        '18:00-19:30',
        '19:30-21:00'
    ];

     //رندر فیلد
    echo '<div id="delivery_checkout_field"><h2>' . __('زمان ارسال پیکی') . '</h2>';
    echo '<div class="woocommerce-input-wrapper">';
    echo '<ul class="nav nav-tabs" role="tablist">';

    foreach ($dates as $key => $date_info) {
        $active_class = $key === 0 ? 'active' : '';
        echo '<li role="presentation" class="' . esc_attr($active_class) . '"><a href="#tab_' . esc_attr($key) . '" aria-controls="tab_' . esc_attr($key) . '" role="tab" data-toggle="tab">' . esc_html($date_info['day_name'] . ' - ' . $date_info['date']) . '</a></li>';
    }

    echo '</ul>';
    echo '<div class="tab-content">';

    foreach ($dates as $key => $date_info) {
        $active_class = $key === 0 ? 'active' : '';
        echo '<div role="tabpanel" class="tab-pane ' . esc_attr($active_class) . '" id="tab_' . esc_attr($key) . '">';
        foreach ($time_slots as $slot) {
            $checked_attr = $key === 0 && $slot === $time_slots[0] ? 'checked="checked"' : '';
            echo '<div class="date-item">';
            echo '<input type="radio" class="input-radio" value="' . esc_attr($date_info['date'] . ' ' . $slot) . '" name="delivery_field" id="delivery_field_' . esc_attr($date_info['date'] . '_' . $slot) . '" ' . $checked_attr . '>';
            echo '<label for="delivery_field_' . esc_attr($date_info['date'] . '_' . $slot) . '" class="radio">' . esc_html($slot) . '</label>';
            echo '</div>';
        }
        echo '</div>';
    }

    echo '</div>'; 
    echo '</div>'; 
    echo '</div>'; 
}

add_action( 'woocommerce_after_order_notes', 'delivery_checkout_field' );
function delivery_checkout_tab_styles() {
    if(!is_checkout()){
      return;
    }
    echo '<style>
        .nav-tabs {
            border-bottom: 1px solid #ddd;
            margin-bottom: 15px;
        }
        .nav-tabs li {
            float: left;
            margin-bottom: -1px;
        }
        .nav-tabs li a {
            margin-right: 2px;
            line-height: 1.42857143;
            border: 1px solid transparent;
            border-radius: 4px 4px 0 0;
            padding: 10px;
        }
        .nav-tabs li a:hover {
            border-color: #eee #eee #ddd;
        }
        .nav-tabs .active a {
            color: #555;
            cursor: default;
            background-color: #fff;
            border: 1px solid #ddd;
            border-bottom-color: transparent;
        }
        .tab-content > .tab-pane {
            display: none;
        }
        .tab-content > .active {
            display: block;
        }
    </style>';
}
add_action('wp_head', 'delivery_checkout_tab_styles');




function delivery_checkout_script() {
    if ( is_checkout() ) {
        ?>
        <script type="text/javascript">
            document.addEventListener("DOMContentLoaded", function() {
                var tabLinks = document.querySelectorAll(".nav-tabs li a");
                var tabPanes = document.querySelectorAll(".tab-content .tab-pane");
    
                tabLinks.forEach(function(link) {
                    link.addEventListener("click", function(e) {
                        e.preventDefault();
    
                        tabLinks.forEach(function(item) {
                            item.parentElement.classList.remove("active");
                        });
    
                        tabPanes.forEach(function(pane) {
                            pane.classList.remove("active");
                        });
    
                        this.parentElement.classList.add("active");
                        document.querySelector(this.getAttribute("href")).classList.add("active");
                    });
                });
            });
            jQuery(document).ready(function($) {
                function toggleCustomField() {
                    var shippingMethod = $('input[name^="shipping_method"]:checked').val();
                  // جایگزین flat_rate:3 با آی‌دی روش ارسال پیکی خود
                    if (shippingMethod === 'flat_rate:9') { 
                        $('#delivery_checkout_field').show();
                    } else {
                        $('#delivery_checkout_field').hide();
                    }
                }
                toggleCustomField();
                $('body').on('change', 'input[name^="shipping_method"]', function() {
                    toggleCustomField();
                });
            });
        </script>
        <?php
    }
}
add_action( 'wp_footer', 'delivery_checkout_script' );
function delivery_checkout_field_update_order_meta( $order_id ) {
    if ( ! empty( $_POST['delivery_field'] ) ) {
        update_post_meta( $order_id, 'Custom Field', sanitize_text_field( $_POST['delivery_field'] ) );
    }
}
add_action( 'woocommerce_checkout_update_order_meta', 'delivery_checkout_field_update_order_meta' );

function delivery_checkout_field_display_admin_order_meta($order){
    $delivery_field = get_post_meta( $order->get_id(), 'Custom Field', true );
    if ( ! empty( $delivery_field ) ) {
        echo '<p><strong>' . __( 'زمان ارسال انتخابی' ) . ':</strong> ' . $delivery_field . '</p>';
    }
}
add_action( 'woocommerce_admin_order_data_after_billing_address', 'delivery_checkout_field_display_admin_order_meta', 10, 1 );
```
---
## customModalByIP
```php
<?php
// get country by id
function get_user_country_from_ip2location_api()
{
    $api_url = 'https://api.ip2location.io/v2/?ip=';
    $api_key = 'your_api_key';
    $user_ip = $_SERVER['REMOTE_ADDR'];

    $full_api_url = $api_url . $user_ip . '&key=' . $api_key;

    $response = wp_remote_get($full_api_url);

    if (is_wp_error($response)) {
        return 'Error: Could not get data';
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body);

    if (isset($data->country_code)) {
        return $data->country_code;
    } else {
        return 'Error: Country information not received';
    }
}
// get lang by country
function get_lang(){
    $country=get_user_country_from_ip2location_api();
    if ($country) {
        switch ($country) {
            case "DJ":
            case "ER":
            case "ET":

                $lang = "aa";
                break;

            case "AE":
            case "BH":
            case "DZ":
            case "EG":
            case "IQ":
            case "JO":
            case "KW":
            case "LB":
            case "LY":
            case "MA":
            case "OM":
            case "QA":
            case "SA":
            case "SD":
            case "SY":
            case "TN":
            case "YE":

                $lang = "ar";
                break;

            case "AZ":

                $lang = "az";
                break;

            case "BY":

                $lang = "be";
                break;

            case "BG":

                $lang = "bg";
                break;

            case "BD":

                $lang = "bn";
                break;

            case "BA":

                $lang = "bs";
                break;

            case "CZ":

                $lang = "cs";
                break;

            case "DK":

                $lang = "da";
                break;

            case "AT":
            case "CH":
            case "DE":
            case "LU":

                $lang = "de";
                break;

            case "MV":

                $lang = "dv";
                break;

            case "BT":

                $lang = "dz";
                break;

            case "GR":

                $lang = "el";
                break;

            case "AG":
            case "AI":
            case "AQ":
            case "AS":
            case "AU":
            case "BB":
            case "BW":
            case "CA":
            case "GB":
            case "IE":
            case "KE":
            case "NG":
            case "NZ":
            case "PH":
            case "SG":
            case "US":
            case "ZA":
            case "ZM":
            case "ZW":

                $lang = "en";
                break;

            case "AD":
            case "AR":
            case "BO":
            case "CL":
            case "CO":
            case "CR":
            case "CU":
            case "DO":
            case "EC":
            case "ES":
            case "GT":
            case "HN":
            case "MX":
            case "NI":
            case "PA":
            case "PE":
            case "PR":
            case "PY":
            case "SV":
            case "UY":
            case "VE":

                $lang = "es";
                break;

            case "EE":

                $lang = "et";
                break;

            case "IR":

                $lang = "fa";
                break;

            case "FI":

                $lang = "fi";
                break;

            case "FO":

                $lang = "fo";
                break;

            case "BE":
            case "FR":
            case "SN":

                $lang = "fr";
                break;

            case "IL":

                $lang = "he";
                break;

            case "IN":

                $lang = "hi";
                break;

            case "HR":

                $lang = "hr";
                break;

            case "HT":

                $lang = "ht";
                break;

            case "HU":

                $lang = "hu";
                break;

            case "AM":

                $lang = "hy";
                break;

            case "ID":

                $lang = "id";
                break;

            case "IS":

                $lang = "is";
                break;

            case "IT":

                $lang = "it";
                break;

            case "JP":

                $lang = "ja";
                break;

            case "GE":

                $lang = "ka";
                break;

            case "KZ":

                $lang = "kk";
                break;

            case "GL":

                $lang = "kl";
                break;

            case "KH":

                $lang = "km";
                break;

            case "KR":

                $lang = "ko";
                break;

            case "KG":

                $lang = "ky";
                break;

            case "UG":

                $lang = "lg";
                break;

            case "LA":

                $lang = "lo";
                break;

            case "LT":

                $lang = "lt";
                break;

            case "LV":

                $lang = "lv";
                break;

            case "MG":

                $lang = "mg";
                break;

            case "MK":

                $lang = "mk";
                break;

            case "MN":

                $lang = "mn";
                break;

            case "MY":

                $lang = "ms";
                break;

            case "MT":

                $lang = "mt";
                break;

            case "MM":

                $lang = "my";
                break;

            case "NP":

                $lang = "ne";
                break;

            case "AW":
            case "NL":

                $lang = "nl";
                break;

            case "NO":

                $lang = "no";
                break;

            case "PL":

                $lang = "pl";
                break;

            case "AF":

                $lang = "ps";
                break;

            case "AO":
            case "BR":
            case "PT":

                $lang = "pt";
                break;

            case "RO":

                $lang = "ro";
                break;

            case "RU":
            case "UA":

                $lang = "ru";
                break;

            case "RW":

                $lang = "rw";
                break;

            case "AX":

                $lang = "se";
                break;

            case "SK":

                $lang = "sk";
                break;

            case "SI":

                $lang = "sl";
                break;

            case "SO":

                $lang = "so";
                break;

            case "AL":

                $lang = "sq";
                break;

            case "ME":
            case "RS":

                $lang = "sr";
                break;

            case "SE":

                $lang = "sv";
                break;

            case "TZ":

                $lang = "sw";
                break;

            case "LK":

                $lang = "ta";
                break;

            case "TJ":

                $lang = "tg";
                break;

            case "TH":

                $lang = "th";
                break;

            case "TM":

                $lang = "tk";
                break;

            case "CY":
            case "TR":

                $lang = "tr";
                break;

            case "PK":

                $lang = "ur";
                break;

            case "UZ":

                $lang = "uz";
                break;

            case "VN":

                $lang = "vi";
                break;

            case "CN":
            case "HK":
            case "TW":

                $lang = "zh";
                break;

            default:
                break;
        }
    }

    return $lang;

}


function my_custom_modal_hook()
{
// langs array
    $langs = array(
        'ar' => array(
            'title' => 'عزيزي العميل،',
            'content' => '
				شكرًا لاختيارك لنا لشرائك.
				انقر هنا للدخول إلى صفحة المنتجات.
				لضمان أصالة متجرنا الإلكتروني، يمكنك الاستفسار من موقع الشركة المصنعة الأصلي (olivari.it).
				تواصل مع خبرائنا من خلال صفحة الاتصال بنا لمزيد من المعلومات.
				'

        ),

        'en' => array(
            'title' => 'Dear customer,',
            'content' => "Thank you for choosing us for your purchase.
							Click here to enter the products page.
							To ensure the authenticity of the our webstore, you can inquire from the original manufacturer's website (olivari.it).
							Get in touch with our experts through our contact page for more information."
        ),

        'de' => array(
            'title' => 'Lieber Kunde,',
            'content' => "Vielen Dank, dass Sie uns für Ihren Einkauf gewählt haben.
							Klicken Sie hier, um zur Produktseite zu gelangen.
							Um die Echtheit unseres Webshops sicherzustellen, können Sie sich auf der Website des Originalherstellers (olivari.it) informieren.
							Kontaktieren Sie unsere Experten über unsere Kontaktseite für weitere Informationen."
        )
    );

// set lang content
    $lang = get_lang();
    if (array_key_exists($lang, $langs)) {
        $my_title = $langs[$lang]['title'];
        $my_content = $langs[$lang]['content'];
    } else {
        $my_title = $langs['en']['title'];
        $my_content = $langs['en']['content'];
    }
// modal show
    $cookie_expiry = time() + 86400;
    if (!isset($_COOKIE['custom_modal_shown'])) {
        ?>

        <div class="my-overlay"></div>

        <div class="my-modal">
            <div class="my-modal-content">
                <span class="my-close">&times;</span>
                <h2><?php echo $my_title ?></h2>
                <p><?php echo $my_content ?></p>
            </div>
        </div>
        <style>
            .my-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0, 0, 0, 0.5);
                display: none;
                align-content
                z-index: 999;

            }

            .my-modal {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background-color: white;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
                display: none;
                width: 40%;
                z-index: 9999;

            }

            .my-modal-content {
                text-align: center;
            }

            .my-close {
                position: absolute;
                top: 10px;
                right: 10px;
                cursor: pointer;
                color: darkred;
                font-size: 2rem;
            }

            .my-modal-content h2 {
                font-weight: 700;
                border-bottom: 1px solid lightgray;
                padding-bottom: 1rem;
            }

        </style>
        <script>
            jQuery(document).ready(function () {
                // نمایش مدال
                jQuery('.my-overlay, .my-modal').fadeIn();

                // بستن مدال
                jQuery('.my-close, .my-overlay').on('click', function () {
                    jQuery('.my-overlay, .my-modal').fadeOut();
                });
            });
            document.cookie = 'custom_modal_shown=true; expires=<?php echo gmdate('D, d M Y H:i:s', $cookie_expiry) . ' GMT'; ?>; path=/';

        </script>
        <?php

    }
}

add_action('wp_footer', 'my_custom_modal_hook');
```
---
## log requests
# benchmark-php

This is a PHP benchmark script to compare the runtime speed of PHP and MySQL. 
This project is inspired by www.php-benchmark-script.com (Alessandro Torrisi) 
an www.webdesign-informatik.de. In my point of view this script is more 
correct and comparable for different servers.

## Screenshot

![benchmark_v12](https://user-images.githubusercontent.com/781074/36862772-286568de-1d88-11e8-98c5-6340f8ea3415.jpg)

## Setup

Upload benchmark.php and execute it:<br>

HTML response:

http://www.example.com/benchmark.php

JSON response:

http://www.example.com/benchmark.php?json

## MySQL Setup (optional)

* Open benchmark.php
* Edit this lines

```php
$options['db.host'] = 'hostname';
$options['db.user'] = 'username';
$options['db.pw'] = 'password';
$options['db.name'] = 'database';
```

* Upload and run the script

```php
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
```