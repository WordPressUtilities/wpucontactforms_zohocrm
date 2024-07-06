<?php
defined('ABSPATH') || die;
/*
Plugin Name: WPU Contact Forms ZohoCRM
Plugin URI: https://github.com/WordPressUtilities/wpucontactforms_zohocrm
Update URI: https://github.com/WordPressUtilities/wpucontactforms_zohocrm
Description: Connect WPU Contact Forms to ZohoCRM
Version: 0.521
Author: darklg
Author URI: https://darklg.me/
Text Domain: wpucontactforms_zohocrm
Domain Path: /lang
Requires at least: 6.2
Requires PHP: 8.0
Network: Optional
License: MIT License
License URI: https://opensource.org/licenses/MIT
*/

class WPUContactFormsZohoCRM {
    public $redirect_uri;
    public $plugin_description;
    public $adminpages;
    public $settings_details;
    public $settings;
    public $basecron;
    public $settings_update;
    private $plugin_version = '0.5.2';
    private $plugin_settings = array(
        'id' => 'wpucontactforms_zohocrm',
        'name' => 'WPU Contact Forms - ZohoCRM'
    );
    private $messages = false;
    private $api_version = 'v2';
    private $settings_obj;

    public function __construct() {
        add_filter('plugins_loaded', array(&$this, 'plugins_loaded'));
    }

    public function plugins_loaded() {
        $this->redirect_uri = admin_url('admin.php?page=wpucontactforms_zohocrm-main');

        # TRANSLATION
        $lang_dir = dirname(plugin_basename(__FILE__)) . '/lang/';
        if (!load_plugin_textdomain('wpucontactforms_zohocrm', false, $lang_dir)) {
            load_muplugin_textdomain('wpucontactforms_zohocrm', $lang_dir);
        }
        $this->plugin_description = __('Connect WPU Contact Forms to ZohoCRM', 'wpucontactforms_zohocrm');

        # CUSTOM PAGE
        $admin_pages = array(
            'main' => array(
                'has_form' => false,
                'icon_url' => 'dashicons-admin-generic',
                'menu_name' => $this->plugin_settings['name'],
                'name' => $this->plugin_settings['name'],
                'settings_link' => true,
                'settings_name' => __('Settings', 'wpucontactforms_zohocrm'),
                'function_content' => array(&$this,
                    'page_content__main'
                )
            )
        );
        $pages_options = array(
            'id' => $this->plugin_settings['id'],
            'level' => 'manage_options',
            'basename' => plugin_basename(__FILE__)
        );
        // Init admin page
        require_once __DIR__ . '/inc/WPUBaseAdminPage/WPUBaseAdminPage.php';
        $this->adminpages = new \wpucontactforms_zohocrm\WPUBaseAdminPage();
        $this->adminpages->init($pages_options, $admin_pages);
        # SETTINGS
        $this->settings_details = array(
            # Admin page
            'create_page' => false,
            'plugin_basename' => plugin_basename(__FILE__),
            # Default
            'plugin_name' => $this->plugin_settings['name'],
            'plugin_id' => $this->plugin_settings['id'],
            'option_id' => $this->plugin_settings['id'] . '_options',
            'sections' => array(
                'app' => array(
                    'name' => __('App Settings', 'wpucontactforms_zohocrm')
                ),
                'plugin' => array(
                    'name' => __('Plugin Settings', 'wpucontactforms_zohocrm')
                ),
                'token' => array(
                    'name' => __('Token Settings', 'wpucontactforms_zohocrm')
                )
            )
        );
        $this->settings = array(
            'client_id' => array(
                'label' => __('Client ID', 'wpucontactforms_zohocrm'),
                'section' => 'app'
            ),
            'client_secret' => array(
                'label' => __('Client Secret', 'wpucontactforms_zohocrm'),
                'section' => 'app'
            ),
            'update_records' => array(
                'label' => __('Update Records', 'wpucontactforms_zohocrm'),
                'type' => 'select',
                'section' => 'plugin',
                'datas' => array(
                    0 => __('No', 'wpucontactforms_zohocrm'),
                    1 => __('Yes', 'wpucontactforms_zohocrm')
                )
            ),
            'access_token' => array(
                'label' => __('Access token', 'wpucontactforms_zohocrm'),
                'section' => 'token'
            ),
            'expires_in' => array(
                'label' => __('Token expiration', 'wpucontactforms_zohocrm'),
                'section' => 'token'
            ),
            'last_update' => array(
                'label' => __('Last update', 'wpucontactforms_zohocrm'),
                'section' => 'token'
            ),
            'refresh_token' => array(
                'label' => __('Refresh token', 'wpucontactforms_zohocrm'),
                'section' => 'token'
            ),
            'accounts_server' => array(
                'label' => __('Accounts server', 'wpucontactforms_zohocrm'),
                'section' => 'token'
            ),
            'api_domain' => array(
                'label' => __('API Domain', 'wpucontactforms_zohocrm'),
                'section' => 'token'
            )
        );
        require_once __DIR__ . '/inc/WPUBaseSettings/WPUBaseSettings.php';
        $this->settings_obj = new \wpucontactforms_zohocrm\WPUBaseSettings($this->settings_details, $this->settings);
        require_once __DIR__ . '/inc/WPUBaseCron/WPUBaseCron.php';
        $this->basecron = new \wpucontactforms_zohocrm\WPUBaseCron(array(
            'pluginname' => $this->plugin_settings['name'],
            'cronhook' => 'wpucontactforms_zohocrm__cron_hook',
            'croninterval' => 3600
        ));
        add_action('wpucontactforms_zohocrm__cron_hook', array(&$this,
            'wpucontactforms_zohocrm__cron_hook'
        ), 99);

        # MESSAGES
        if (is_admin()) {
            require_once __DIR__ . '/inc/WPUBaseMessages/WPUBaseMessages.php';
            $this->messages = new \wpucontactforms_zohocrm\WPUBaseMessages($this->plugin_settings['id']);
        }

        # Update
        require_once __DIR__ . '/inc/WPUBaseUpdate/WPUBaseUpdate.php';
        $this->settings_update = new \wpucontactforms_zohocrm\WPUBaseUpdate(
            'WordPressUtilities',
            'wpucontactforms_zohocrm',
            $this->plugin_version);

        # Action contactform
        add_action('wpucontactforms_submit_contactform', array(&$this, 'wpucontactforms_submit_contactform'), 10, 2);

    }

    public function wpucontactforms_zohocrm__cron_hook() {
        /* Refresh token */
        $this->refresh_token();
    }

    /* Add a message */
    public function set_message($id, $message, $group = 'updated') {
        if (!$this->messages) {
            error_log($id . ' - ' . $message);
            return;
        }
        $this->messages->set_message($id, $message, $group);
    }

    public function page_content__main() {
        $settings = $this->settings_obj->get_settings();
        $api_create_url = 'https://api-console.zoho.eu/add';
        $connect_url = 'https://accounts.zoho.com/oauth/' . $this->api_version . '/auth?' . http_build_query(array(
            'scope' => 'ZohoCRM.modules.ALL,ZohoCRM.settings.ALL,ZohoCRM.users.ALL,ZohoCRM.org.ALL,aaaserver.profile.ALL,ZohoCRM.settings.functions.all,ZohoCRM.notifications.all,ZohoCRM.coql.read,ZohoCRM.files.create,ZohoCRM.bulk.all',
            'response_type' => 'code',
            'access_type' => 'offline',
            'client_id' => $settings['client_id'],
            'redirect_uri' => $this->redirect_uri
        ));

        if (isset($_GET['code'], $_GET['accounts-server']) && filter_var($_GET['accounts-server'], FILTER_VALIDATE_URL) !== FALSE) {
            $this->set_access_token($_GET['code'], $_GET['accounts-server']);
        } elseif (isset($_GET['refresh_token'])) {
            $this->refresh_token();
            if ($this->get_token_validity() == 'valid') {
                $this->set_message('token_updated', __('Token was successfully updated.', 'wpucontactforms_zohocrm'), 'updated');
            }
            $this->redirect_to_default_page();
        } else {
            $token_validity = $this->get_token_validity();
            $refresh_token_link = '<p><a class="button-primary" href="' . add_query_arg('refresh_token', '1', $this->redirect_uri) . '">' . __('Refresh your access token', 'wpucontactforms_zohocrm') . '</a></p>';
            if (isset($settings['last_update']) && $settings['last_update']) {
                echo '<p>' . sprintf(__('Last update: %s ago.', 'wpucontactforms_zohocrm'), human_time_diff($settings['last_update'])) . '</p>';
            }
            if ($token_validity == 'invalid') {
                /* Instructions */
                echo '<div class="notice notice-error"><p>' . __('No application installed', 'wpucontactforms_zohocrm') . '</p></div>';
                echo '<p>' . sprintf(__('Please <a target="_blank" href="%s">create an new Server-based application here</a> and specify the following redirect_uri : <br /><strong contenteditable>%s</strong>', 'wpucontactforms_zohocrm'), $api_create_url, $this->redirect_uri) . '</p>';
                echo '<p>' . __('Get the client ID and client Secret and paste it below.', 'wpucontactforms_zohocrm') . '</p>';
                echo '<hr />';
            } elseif ($token_validity == 'expired-token') {
                echo $refresh_token_link;
                echo '<hr />';
            } elseif ($token_validity != 'valid') {
                echo '<p><a class="button-primary" href="' . $connect_url . '">' . __('Connect to your account', 'wpucontactforms_zohocrm') . '</a></p>';
                echo '<hr />';
            } else {
                echo '<div class="notice updated"><p>' . __('Connection seems to work', 'wpucontactforms_zohocrm') . '</p></div>';
                echo $refresh_token_link;
                echo '<hr />';
            }
        }

        echo '<form action="' . admin_url('options.php') . '" method="post">';
        settings_fields($this->settings_details['option_id']);
        do_settings_sections($this->settings_details['plugin_id']);
        submit_button(__('Save Changes', 'wpucontactforms_zohocrm'));
        echo '</form>';
    }

    /* ----------------------------------------------------------
      Contact
    ---------------------------------------------------------- */

    public function wpucontactforms_submit_contactform($form) {
        $zoho_data = array();
        foreach ($form->contact_fields as $field_id => $field) {
            if (isset($field['zohocrm_field_name'])) {
                $zoho_data[$field['zohocrm_field_name']] = $field['value'];
            }
        }

        if ($zoho_data) {
            $this->create_or_update_lead($zoho_data);
        }
    }

    /* ----------------------------------------------------------
      API
    ---------------------------------------------------------- */

    public function get_token_validity() {
        $settings = $this->settings_obj->get_settings();
        if (!isset($settings['client_id'], $settings['client_secret'], $settings['refresh_token'], $settings['access_token']) || !$settings['client_id'] || !$settings['client_secret']) {
            return 'invalid';
        }
        if (!$settings['refresh_token']) {
            return 'missing-refresh-token';
        }
        if (!$settings['access_token'] || !$settings['expires_in'] || ($settings['expires_in'] && $settings['expires_in'] < time())) {
            return 'expired-token';
        }
        return 'valid';
    }

    public function refresh_token() {
        $settings = $this->settings_obj->get_settings();
        if (!isset($settings['client_id'], $settings['client_secret'], $settings['refresh_token']) || !$settings['client_id'] || !$settings['client_secret'] || !$settings['refresh_token']) {
            return false;
        }
        $server_output = wp_remote_post($settings['accounts_server'] . "/oauth/" . $this->api_version . "/token", array(
            'body' => array(
                'grant_type' => 'refresh_token',
                'refresh_token' => $settings['refresh_token'],
                'client_id' => $settings['client_id'],
                'client_secret' => $settings['client_secret']
            )
        ));
        if (is_wp_error($server_output)) {
            $this->set_message('token_error', __('An error occured while refreshing the token.', 'wpucontactforms_zohocrm'), 'error');
            return false;
        }
        $output_body = json_decode(wp_remote_retrieve_body($server_output));
        if (!isset($output_body->access_token) || !$output_body->access_token) {
            $this->set_message('token_do_not_exists', __('The response did not contain a token.', 'wpucontactforms_zohocrm'), 'error');
            $this->settings_obj->update_setting('refresh_token', '');
            $this->settings_obj->update_setting('access_token', '');
            return false;
        }
        $this->update_tokens_from_response($output_body);
    }

    public function create_or_update_lead($data = array()) {
        if (!is_array($data)) {
            $data = array();
        }

        if (!isset($data['Lead_Source'])) {
            $data['Lead_Source'] = get_site_url();
        }

        $token_validity = $this->get_token_validity();
        if ($token_validity == 'expired-token') {
            $this->refresh_token();
        }

        $settings = $this->settings_obj->get_settings();
        $access_token = $this->settings_obj->get_setting('access_token');
        $api_domain = $this->settings_obj->get_setting('api_domain');
        $update_records = $this->settings_obj->get_setting('update_records');

        if (!$access_token) {
            return false;
        }

        /* If an email exists : try to update record */
        if (isset($data['Email']) && is_email($data['Email']) && $update_records) {
            $req_search_lead = $this->build_request('/Leads/search?criteria=(Email:equals:' . urlencode($data['Email']) . ')', 'GET');

            if (!is_wp_error($req_search_lead)) {
                $lead_details = json_decode(wp_remote_retrieve_body($req_search_lead), true);
                if (is_array($lead_details) && isset($lead_details['data'], $lead_details['data'][0])) {
                    $data['id'] = $lead_details['data'][0]['id'];
                    return $this->update_lead($data);
                }
            }
        }

        return $this->create_lead($data);
    }

    private function update_lead($data) {
        $req = $this->build_request('/Leads', 'PUT', $data);
        return $this->api_is_successful_req($req);
    }

    private function create_lead($data) {
        $req = $this->build_request('/Leads', 'POST', $data);
        return $this->api_is_successful_req($req);
    }

    public function build_request($endpoint, $method, $data = array()) {
        $access_token = $this->settings_obj->get_setting('access_token');
        $api_domain = $this->settings_obj->get_setting('api_domain');

        $query = array(
            'method' => $method,
            'headers' => array(
                'Authorization' => 'Zoho-oauthtoken ' . $access_token
            )
        );

        if (in_array($method, array('POST', 'PUT'))) {
            $query['headers']['Content-Type'] = 'application/json';
            $query['headers']['cache-control'] = 'no-cache';
        }

        if (!empty($data)) {
            $query['body'] = json_encode(array('data' => array($data)));
        }

        $req = wp_remote_request($api_domain . '/crm/' . $this->api_version . $endpoint, $query);
        return $req;
    }

    public function api_is_successful_req($req) {
        if (is_wp_error($req)) {
            error_log('Error : ' . $req->get_error_message());
            return false;
        }
        $req_body = wp_remote_retrieve_body($req);
        $req_details = json_decode($req_body, true);
        return (is_array($req_details) && isset($req_details['data'], $req_details['data'][0]));
    }

    public function set_access_token($code, $accounts_server) {
        $settings = $this->settings_obj->get_settings();
        $this->settings_obj->update_setting('accounts_server', $accounts_server);

        $server_output = wp_remote_post($accounts_server . "/oauth/" . $this->api_version . "/token", array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $settings['client_id'],
                'client_secret' => $settings['client_secret'],
                'redirect_uri' => $this->redirect_uri
            )
        ));

        if (!is_wp_error($server_output)) {
            $this->update_tokens_from_response(wp_remote_retrieve_body($server_output));
            $this->set_message('token_updated', __('Token was successfully updated.', 'wpucontactforms_zohocrm'), 'updated');
            $this->redirect_to_default_page();
        } else {
            echo '<p>' . __('There was an error', 'wpucontactforms_zohocrm') . '</p>';
            echo '<pre>';
            var_dump($server_output);
            echo '</pre>';
        }
    }

    public function update_tokens_from_response($server_output) {
        if (!is_object($server_output)) {
            $server_output = json_decode($server_output);
        }
        if (isset($server_output->access_token) && $server_output->access_token) {
            $this->settings_obj->update_setting('access_token', $server_output->access_token);
        }
        if (isset($server_output->expires_in) && $server_output->expires_in) {
            $this->settings_obj->update_setting('last_update', time());
            $this->settings_obj->update_setting('expires_in', time() + intval($server_output->expires_in, 10));
        }
        if (isset($server_output->refresh_token) && $server_output->refresh_token) {
            $this->settings_obj->update_setting('refresh_token', $server_output->refresh_token);
        }
        if (isset($server_output->api_domain) && $server_output->api_domain) {
            $this->settings_obj->update_setting('api_domain', $server_output->api_domain);
        }
    }

    public function redirect_to_default_page() {
        echo '<script>document.location.href="' . $this->redirect_uri . '"; </script>';
        die;
    }

}

$WPUContactFormsZohoCRM = new WPUContactFormsZohoCRM();
