<?php

/**
 * Plugin Name:     HfH Shibboleth
 * Description:     Shibboleth Integration for Pressbooks
 * Author:          Sarah Frederickx, Stephan Müller, Lukas Kaiser & Matthias Nötzli
 * Copyright:       © 2017, ETH Zurich, D-HEST, Stephan J. Müller, Lukas Kaiser
 * Text Domain:     hfh-shibboleth
 * Domain Path:     /languages
 * Version:         1.0.2
 *
 * @package         HfH_Shibboleth
 */

namespace HfH\Shibboleth;

use WP_Error;
use WP_User;

if (!defined('ABSPATH')) {
    return;
}

if (!defined('HFH_SHIBBOLETH_URL')) {
    define('HFH_SHIBBOLETH_URL', plugin_dir_url(__FILE__));
}

class Plugin
{
    private static $instance = false;

    public static function get_instance()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        add_action('admin_init', array($this, 'add_subscriber_settings'), 11);
        add_filter('login_url', array($this, 'set_login_url_to_main_site'), 9, 3);
        add_filter('shibboleth_authenticate_user', array($this, 'prevent_shibboleth_subsite_login'), 10, 2);
        add_filter('authenticate', array($this, 'set_home_orgs'), 9999, 3);
        add_filter('user_has_cap', array($this, 'grant_permissions'), 10, 4);
    }

    /**
     * Add admin menu entry to allow users from certain organizations to subscribe.
     */
    function add_subscriber_settings()
    {
        register_setting(
            'privacy_settings',
            'shibboleth_subscriber',
            'absint' // input sanitizer
        );
        add_settings_field(
            'shibboleth_subscriber',
            __('Wer darf lesen (wenn Sichtbarkeit auf Privat)?', 'hfh-shibboleth'),
            array($this, 'subscriber_callback'),
            'privacy_settings',
            'privacy_settings_section'
        );
    }

    /**
     * Render menu entry to allow users from certain organizations to subscribe.
     */
    function subscriber_callback($args)
    {
        $sel = get_option('shibboleth_subscriber');
        echo '<select name="shibboleth_subscriber" class="shibboleth_subscriber">';
        echo '<option value="0"' . ($sel == 0 ? ' selected = "selected"' : '') . '>' . __('Niemand', 'pressbooks') . '</option>';
        echo '<option value="1"' . ($sel == 1 ? ' selected = "selected"' : '') . '>' . __('HfH Angehörige', 'pressbooks') . '</option>';
        echo '<option value="2"' . ($sel == 2 ? ' selected = "selected"' : '') . '>' . __('HfH and PHZH Angehörige', 'pressbooks') . '</option>';
        echo '<option value="3"' . ($sel == 3 ? ' selected = "selected"' : '') . '>' . __('SWITCHaai', 'pressbooks') . '</option>';
        echo '<option value="4"' . ($sel == 4 ? ' selected = "selected"' : '') . '>' . __('UZH Angehörige', 'pressbooks') . '</option>';
        echo '<option value="5"' . ($sel == 5 ? ' selected = "selected"' : '') . '>' . __('FHNW Angehörige', 'pressbooks') . '</option>';
        echo '<option value="6"' . ($sel == 6 ? ' selected = "selected"' : '') . '>' . __('ZHAW Angehörige', 'pressbooks') . '</option>';
        echo '</select>';
    }

    /**
     * Set a user's home orgs during authentication
     */
    function set_home_orgs($user, $username, $password)
    {
        if ($user instanceof WP_User && get_user_meta($user->ID, 'shibboleth_account', true) && isset($_SERVER['homeOrganization'])) {
            $orgs = explode(';', $_SERVER['homeOrganization']);
            update_user_meta($user->ID, 'shibboleth_home_orgs', $orgs);
        }
        return $user;
    }

    /**
     * Grants users of selected organizations subscriber privileges automatically.
     *
     * @author Stephan Müller
     */
    function grant_permissions($allcaps, $cap, $args, $user)
    {
        if (!in_array('read', $cap)) {
            return $allcaps;
        }
        $grant = false;

        // If the book is public and the user is not yet a subscriber, grant them the subscriber role
        $book_is_public = (!empty(get_option('blog_public'))) ? 1 : 0;
        if ($book_is_public  && !in_array('subscriber', $user->roles)) {
            $grant = true;
        }

        /*
         If the user does not have the read capabilityß,
         check their organisations and grant the subscriber role according to the configured option
        */
        if (empty($allcaps['read']) && in_array('read', $cap)) {
            $orgs = get_user_meta($user->ID, 'shibboleth_home_orgs', true);
            if (empty($orgs)) {
                $orgs = array();
            }
            $mode  = get_option('shibboleth_subscriber');
            $hfh   = in_array('hfh.ch', $orgs);
            $phzh  = in_array('phzh.ch', $orgs);
            $uzh   = in_array('uzh.ch', $orgs);
            $fhnw  = in_array('fhnw.ch', $orgs);
            $zhaw  = in_array('zhaw.ch', $orgs);
            if ($mode == 1) {
                $grant = $hfh;
            } elseif ($mode == 2) {
                $grant = $hfh | $phzh;
            } elseif ($mode == 3) {
                $grant = !empty(get_user_meta($user->ID, 'shibboleth_account'));
            } elseif ($mode == 4) {
                $grant = $uzh;
            } elseif ($mode == 5) {
                $grant = $fhnw;
            } elseif ($mode == 6) {
                $grant = $zhaw;
            }
        }

        if ($grant) {
            $user->add_role('subscriber');
            $role    = get_role('subscriber');
            $allcaps = array_merge($allcaps, $role->capabilities);
        }

        return $allcaps;
    }

    /**
     * Set login url of subsites to main site login url.
     */
    function set_login_url_to_main_site($login_url, $redirect, $force_reauth)
    {
        if (!is_main_site()) {
            $login_url = network_site_url('wp-login.php', 'login');
            if (!empty($redirect)) {
                $login_url = add_query_arg('redirect_to', urlencode($redirect), $login_url);
            }
            if ($force_reauth) {
                $login_url = add_query_arg('reauth', '1', $login_url);
            }
        }
        return $login_url;
    }

    /**
     * Prevent users from login in directly on subsite
     */
    function prevent_shibboleth_subsite_login($auth, $username)
    {
        return is_main_site() ? null : new WP_Error('subsite', "Shibboleth login from subsite is not allowed.");
    }
}

Plugin::get_instance();
