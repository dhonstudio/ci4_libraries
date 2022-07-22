<?php

namespace Assets\Ci4_libraries;

use Assets\Ci4_libraries\DhonRequest;
use CodeIgniter\Cookie\Cookie;
use DateTime;

date_default_timezone_set('Asia/Jakarta');

class DhonHit
{
    /**
     * Set session name.
     */
    public $session_name = 'DShC13v';

    /**
     * Connect to DhonRequest library.
     */
    public $dhonrequest;

    /**
     * Set id address.
     */
    protected $id_address;

    /**
     * Set id entity.
     */
    protected $id_entity;

    /**
     * Set id session.
     */
    protected $id_session;

    /**
     * Set id source.
     */
    protected $id_source;

    /**
     * Set id page.
     */
    protected $id_page;

    /**
     * Set baseurl.
     */
    public $base_url;

    public function __construct($params)
    {
        require __DIR__ . '/DhonRequest.php';

        $this->dhonrequest  = new DhonRequest;
        $this->dhonrequest->api_url = $params['api_url'];
        $this->dhonrequest->auth = $params['auth'];
    }

    /**
     * Get Hit from user info.
     * 
     * @return void
     */
    public function collect()
    {
        $this->_getHit();
    }

    /**
     * Post the Hit.
     * 
     * @return void
     */
    private function _getHit()
    {
        //~ ip_address
        $ip_address =
            !empty($_SERVER["HTTP_X_CLUSTER_CLIENT_IP"]) ? $_SERVER["HTTP_X_CLUSTER_CLIENT_IP"]
            : (!empty($_SERVER["HTTP_X_CLIENT_IP"]) ? $_SERVER["HTTP_X_CLIENT_IP"]
                : (!empty($_SERVER["HTTP_CLIENT_IP"]) ? $_SERVER["HTTP_CLIENT_IP"]
                    : (!empty($_SERVER["HTTP_X_FORWARDED_FOR"]) ? $_SERVER["HTTP_X_FORWARDED_FOR"]
                        : (!empty($_SERVER["HTTP_X_FORWARDED"]) ? $_SERVER["HTTP_X_FORWARDED"]
                            : (!empty($_SERVER["HTTP_FORWARDED_FOR"]) ? $_SERVER["HTTP_FORWARDED_FOR"]
                                : (!empty($_SERVER["HTTP_FORWARDED"]) ? $_SERVER["HTTP_FORWARDED"]
                                    : (!empty($_SERVER["REMOTE_ADDR"]) ? $_SERVER["REMOTE_ADDR"]
                                        : '::0'
                                    )))))));

        if (ENVIRONMENT !== 'development') {
            foreach (explode(',', $ip_address) as $ip) {
                $ip = trim($ip); // just to be safe

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    $ip_address = $ip;
                }
            }
        }

        //~ entity
        $entity = isset($_SERVER['HTTP_USER_AGENT']) ? htmlentities($_SERVER['HTTP_USER_AGENT']) : 'BOT';

        //~ session
        $session_prefix = '__m-';
        $session_secure = ENVIRONMENT === 'production' ? true : false;

        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            helper('text');
            helper('cookie');

            $session_value  = random_string('alnum', 32) . $ip_address;
            $session_cookie = (new Cookie($this->session_name))
                ->withValue($session_value)
                ->withPrefix($session_prefix)
                ->withExpires(new DateTime('+104 weeks'))
                ->withPath('/')
                ->withDomain('')
                ->withSecure($session_secure)
                ->withHTTPOnly(true)
                ->withSameSite(Cookie::SAMESITE_LAX);

            if (!get_cookie($session_prefix . $this->session_name) || get_cookie($session_prefix . $this->session_name) === '' || get_cookie($session_prefix . $this->session_name) === null) {
                set_cookie($session_cookie);
            } else {
                $session_value = get_cookie($session_prefix . $this->session_name);
            }
        } else {
            $session_value = "BOT";
        }

        //~ source
        $source_value       = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : $this->base_url;

        //~ page
        if ($_GET) {
            $get_join = [];
            foreach ($_GET as $key => $value) {
                array_push($get_join, $key . '=' . $value);
            }
            $get = '?' . implode('&', $get_join);
        } else {
            $get = '';
        }
        $page_value     = uri_string() ? uri_string() . $get : '/';

        //~ hit
        $this->dhonrequest->post('gethit', [
            'address'   => $ip_address,
            'entity'    => $entity,
            'session'   => $session_value,
            'source'    => $source_value,
            'page'      => $page_value,
            'created_at' => date("Y-m-d H:i:s", time())
        ]);
    }
}
