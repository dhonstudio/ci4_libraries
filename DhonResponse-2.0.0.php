<?php

namespace Assets\Ci4_libraries;

date_default_timezone_set('Asia/Jakarta');

use App\Models\ApiaddressModel;
use App\Models\ApiendpointModel;
use App\Models\ApientityModel;
use App\Models\ApilogModel;
use App\Models\ApisessionModel;
use App\Models\ApiusersModel;
use CodeIgniter\Cookie\Cookie;
use CodeIgniter\HTTP\Response;
use DateTime;

class DhonResponse
{
    /**
     * Enabler basic authorization.
     * 
     * @var boolean
     */
    public $basic_auth = true;

    /**
     * CORS.
     * 
     * @var string
     */
    public $cors = '*';

    /**
     * Model in use.
     */
    public $model;

    /**
     * Request method.
     * 
     * @var string
     */
    public $method;

    /**
     * Column name to search where (GET WHERE).
     * 
     * @var string
     */
    public $column;

    /**
     * Sort enabler.
     * 
     * @var boolean
     */
    public $sort;

    /**
     * Result from response.
     */
    public $data;

    /**
     * Api_users.
     */
    protected $api_user = [
        'id_user' => 1,
        'level' => 4
    ];

    protected $response;
    protected $message;
    protected $total;

    protected $result;

    protected $apiusersModel;
    protected $apiaddressModel;
    protected $apientityModel;
    protected $apisessionModel;
    protected $apiendpointModel;
    protected $apilogModel;







    /**
     * Cookie session name for API.
     * 
     * @var string
     */
    public $session_name   = 'DSaL13v';

    /**
     * Cookie session expire.
     * 
     * @var string
     */
    public $session_expire = '+104 weeks';

    /**
     * Dhon Studio library for connect API.
     * 
     * @var DhonRequest
     */
    public $dhonrequest;

    /**
     * Enabler cache.
     *
     * @var boolean
     */
    public $cache_on;

    /**
     * Cache engine.
     *
     * @var \CodeIgniter\Cache\CacheInterface
     */
    public $cache;

    /**
     * Cache name.
     *
     * @var string
     */
    public $cache_name;

    /**
     * Cache value.
     */
    public $cache_value;

    /**
     * Cache CRUD effect.
     *
     * @var int
     */
    public $cache_crud = 0;

    /**
     * Cache endpoint effected.
     *
     * @var string[]
     */
    public $effected;

    /**
     * Enabler sqllite.
     *
     * @var boolean
     */
    public $sqllite_on;











    /**
     * Username to verify password.
     * 
     * @var string
     */
    public $username;

    /**
     * Password to verify password.
     * 
     * @var string
     */
    public $password;

    /**
     * SQLLite value.
     */
    public $sqllite_value;



    /**
     * Request service.
     */
    protected $request;








    public function __construct()
    {
        $this->response = service('response');
        $this->response->setHeader('Content-type', 'application/json');
        $this->response->setHeader('Access-Control-Allow-Origin', $this->cors);
        $this->response->setStatusCode(Response::HTTP_OK);

        $this->request = service('request');

        helper('filesystem');
    }

    private function _check_auth()
    {
        $this->apiusersModel = new ApiusersModel();

        if (isset($_SERVER['PHP_AUTH_USER'])) {
            $this->api_user = $this->apiusersModel->where('username', $_SERVER['PHP_AUTH_USER'])->first();
            if (!$this->api_user || !password_verify($_SERVER['PHP_AUTH_PW'], $this->api_user['password'])) {
                $this->response->setStatusCode(Response::HTTP_UNAUTHORIZED);
                $this->send();
            }
        } else {
            $this->response->setStatusCode(Response::HTTP_UNAUTHORIZED);
            $this->send();
        }
    }

    /**
     * Collect data from db.
     */
    public function collect(bool $send = true)
    {
        if ($this->basic_auth) $this->_check_auth();

        if ($this->api_user['level'] > 0) {
            if ($this->method == 'GET') $this->_get();
            else if ($this->method == 'GETALL') $this->_get("all");
            else if ($this->method == 'POST') $this->_post();
            else if ($this->method == 'PUT') {
                if ($this->api_user['level'] > 2) {
                    $data = [];
                    foreach ($this->model->allowedFields as $field) {
                        $data[$field] = $this->request->getPost($field);
                    }

                    $edit_id    = $this->request->getPost($this->model->primaryKey);
                    $result     = $this->model->where($this->model->primaryKey, $edit_id)->first();

                    if ($result) {
                        $this->model->update($edit_id, $data);
                        if ($this->sqllite_on) {
                            $this->sqllite_gen();
                        }
                        $this->data = $result;
                    } else {
                        $this->response->setStatusCode(Response::HTTP_BAD_REQUEST);
                        $this->message = 'Id not found';
                    }
                } else {
                    $this->response->setStatusCode(Response::HTTP_METHOD_NOT_ALLOWED);
                    $this->message = 'Only GET and POST allowed';
                }
            } else if ($this->method == 'DELETE') {
                if ($this->api_user['level'] > 3) {
                    $id = $this->request->getGet($this->model->primaryKey) ? $this->request->getGet($this->model->primaryKey) : $this->request->getGet('id');
                    $result = $this->model->where($this->model->primaryKey, $id)->first();

                    if ($result) {
                        $this->model->delete($id);
                        if ($this->sqllite_on) {
                            $this->sqllite_gen();
                        }

                        $db = \Config\Database::connect($this->model->DBGroup);
                        $db->query("ALTER TABLE {$this->model->table} AUTO_INCREMENT = 1");

                        $this->data = $result;
                    } else {
                        $this->response->setStatusCode(Response::HTTP_BAD_REQUEST);
                        $this->message = 'ID not found';
                    }
                } else {
                    $this->response->setStatusCode(Response::HTTP_METHOD_NOT_ALLOWED);
                    $this->message = 'Only GET, POST, and PUT allowed';
                }
            } else if ($this->method == 'PASSWORD_VERIFY') {
                $username   = $this->request->getGet($this->username);
                $password   = $this->request->getGet($this->password);

                $user       = $this->model->where($this->username, $username)->first();

                if ($user) {
                    $this->data = password_verify($password, $user[$this->password]) ? [true] : [false];
                } else {
                    $this->response->setStatusCode(Response::HTTP_NOT_FOUND);
                    $this->message = 'Username not found';
                }
            } else {
                $result = $this->sqllite_value ? json_decode($this->sqllite_value, TRUE) : $this->model->findAll();

                if ($this->sort) {
                    $result = $this->_sort($result);
                }

                $this->total    = count($result) == 0 ? [0] : count($result);
                $this->data     = $result == [] ? "Array()" : $result;
            }
        } else {
            $this->response->setStatusCode(Response::HTTP_METHOD_NOT_ALLOWED);
            $this->message = 'Authorization issue';
        }

        if ($send) $this->send();
    }

    private function _get($total_result = "one")
    {
        $value = $_GET[$this->column];

        if ($value) {
            if ($total_result == "one") {
                $result = $this->model->where($this->column, $value)->first();

                $this->data = $result == [] ? "null" : $result;
            } else {
                $result = $this->model->where($this->column, $value)->findAll();

                if ($this->sort) $result = $this->_sort($result);

                $this->data = $result == [] ? "Array()" : $result;
            }
        } else {
            $this->response->setStatusCode(Response::HTTP_BAD_REQUEST);
            $this->message = 'Require some variable to get';
        }
    }

    private function _post()
    {
        if ($this->api_user['level'] > 1) {
            $data = [];

            foreach ($this->model->allowedFields as $field) {
                if ($field == 'password_hash') {
                    if ($_POST[$field]) {
                        $data[$field] = password_hash($_POST[$field], PASSWORD_DEFAULT);
                    } else {
                        $data[$field] = $_POST[$field];
                    }
                } else {
                    $data[$field] = $_POST[$field];
                }
            }

            if (!$this->model->preventDuplicate || !$this->model->where($this->model->preventDuplicate, $_POST[$this->model->preventDuplicate])->first()) {
                $insert_id  = $this->model->insert($data);
                if ($insert_id) {
                    $this->data = $this->model->where($this->model->primaryKey, $insert_id)->first();
                } else {
                    $this->response->setStatusCode(Response::HTTP_BAD_REQUEST);
                    $this->message = 'Require some filed to post';
                }
            } else {
                $this->response->setStatusCode(Response::HTTP_BAD_REQUEST);
                $this->message = 'Duplicate detected';
            }
        } else {
            $this->response->setStatusCode(Response::HTTP_METHOD_NOT_ALLOWED);
            $this->message = 'Only GET allowed';
        }
    }

    private function _sort($result)
    {
        $this->sort_by  = $_GET['sort_by'];
        $sort_method    = $_GET['sort_method'];
        if ($this->sort_by) {
            if ($sort_method && $sort_method == "DESC") {
                usort($result, function ($x, $y) {
                    return $y[$this->sort_by] <=> $x[$this->sort_by];
                });
            } else {
                usort($result, function ($x, $y) {
                    return $x[$this->sort_by] <=> $y[$this->sort_by];
                });
            }
        }

        return $result;
    }

    /**
     * Send final response.
     */
    public function send()
    {
        $this->result['status']   = $this->response->getStatusCode();
        $this->result['response'] = $this->response->getReasonPhrase();

        $this->message ? $this->result['message'] = $this->message : false;
        $this->total ? ($this->result['total'] = $this->total == [0] ? 0 : $this->total) : false;

        $this->data ? ($this->result['data'] = $this->data === [false] ? false
            : ($this->data === [true] ? true
                : ($this->data === "Array()" ? []
                    : ($this->data === "null" ? null : $this->data))))
            : false;

        $finalResult = json_encode($this->result, JSON_NUMERIC_CHECK);

        $this->response->setBody($finalResult);

        if (isset($_SERVER['HTTP_USER_AGENT'])) $this->_hit();

        $this->response->send();
        exit;
    }

    /**
     * Delete cache because CRUD action.
     */
    public function crud_effect(array $effected)
    {
        foreach ($effected as $key => $value) {
            $this->cache->deleteMatching(urlencode($value) . '*');
        }
    }

    /**
     * Create and Update SQLLite.
     */
    public function sqllite_gen()
    {
        $folder_location    = ROOTPATH . "writable/lite/";
        $file               = $folder_location . $this->model->table . '.json';

        if (!is_dir($folder_location)) {
            mkdir($folder_location, 0777, true);
        }
        if (!file_exists($file) || $this->method == 'POST' || $this->method == 'PUT' || $this->method == 'DELETE') {
            $this->sqllite_value = json_encode($this->model->findAll(), JSON_NUMERIC_CHECK);
            write_file($file, $this->sqllite_value);
        } else {
            $this->sqllite_value = file_get_contents($file);
        }
    }


    /**
     * Identify API requester.
     */
    private function _hit()
    {
        $this->apiaddressModel  = new ApiaddressModel();
        $this->apientityModel   = new ApientityModel();
        $this->apisessionModel  = new ApisessionModel();
        $this->apiendpointModel = new ApiendpointModel();
        $this->apilogModel      = new ApilogModel();

        // api_address
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

        $address    = $this->apiaddressModel->where('ip_address', $ip_address)->first();
        $id_address = empty($address) ? $this->apiaddressModel->insert([
            'ip_address'    => $ip_address,
            'ip_info'       => $this->dhonrequest->curl("http://ip-api.com/json/{$ip_address}")
        ]) : $address['id_address'];

        // api_entity
        $entity = isset($_SERVER['HTTP_USER_AGENT']) ? htmlentities($_SERVER['HTTP_USER_AGENT']) : 'REQUEST';

        $entities   = $this->apientityModel->findAll();
        $entity_key = array_search($entity, array_column($entities, 'entity'));
        $entity_av  = !empty($entities) ? ($entity_key > -1 ? $entities[$entity_key] : 0) : 0;
        $id_entity  = $entity_av === 0 ? $this->apientityModel->insert([
            'entity' => $entity,
        ]) : $entity_av['id'];

        // api_session
        $session_prefix = '__m-';
        $session_secure = false;

        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            helper('text');
            helper('cookie');

            $session_value  = random_string('alnum', 32);
            $session_cookie = (new Cookie($this->session_name))
                ->withValue($session_value)
                ->withPrefix($session_prefix)
                ->withExpires(new DateTime($this->session_expire))
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
            $session_value = "REQUEST";
        }

        $session   = $this->apisessionModel->where('session', $session_value)->first();
        $id_session = empty($session) ? $this->apisessionModel->insert([
            'session' => $session_value,
        ]) : $session['id_session'];

        // api_endpoint
        if ($_GET) {
            $get_join = [];
            foreach ($_GET as $key => $value) {
                array_push($get_join, $key . '=' . $value);
            }
            $get = '?' . implode('&', $get_join);
        } else {
            $get = '';
        }
        $endpoint = uri_string() . $get;

        $endpoints      = $this->apiendpointModel->where('endpoint', $endpoint)->first();
        $id_endpoint    = empty($endpoints) ? $this->apiendpointModel->insert([
            'endpoint' => $endpoint,
        ]) : $endpoints['id_endpoint'];

        // api_log
        $action = $this->method == 'GET' ? 2
            : ($this->method == 'POST' ? 3
                : ($this->method == 'PUT' ? 4
                    : ($this->method == 'DELETE' ? 5
                        : ($this->method == 'PASSWORD_VERIFY' ? 6 : 1))));

        $success    = $this->response->getStatusCode() == 200 ? 1 : 0;
        $error      = $this->response->getStatusCode() == 200 ? 0 : $this->response->getStatusCode();
        $message    = isset($this->message) ? $this->message : '';

        $this->apilogModel->insert([
            'id_user'       => $this->api_user['id_user'],
            'address'       => $id_address,
            'entity'        => $id_entity,
            'session'       => $id_session,
            'endpoint'      => $id_endpoint,
            'action'        => $action,
            'success'       => $success,
            'error'         => $error,
            'message'       => $message,
            'created_at'    => date('Y-m-d H:i:s', time())
        ]);
    }
}
