<?php
defined('ABSPATH') || die;
if (!defined('WP_UNINSTALL_PLUGIN')) {
    die;
}

/* Delete options */
$options = array(
    'wpucontactforms_zohocrm_options',
    'wpucontactforms_zohocrm__cron_hook_croninterval',
    'wpucontactforms_zohocrm__cron_hook_lastexec'
);
foreach ($options as $opt) {
    delete_option($opt);
    delete_site_option($opt);
}
