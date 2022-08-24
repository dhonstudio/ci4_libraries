<?php

namespace Assets\Ci4_libraries;

date_default_timezone_set('Asia/Jakarta');

use CodeIgniter\Controller;
use CodeIgniter\HTTP\Response;

class DhonAPI extends Controller
{
    public $column;
    public $value;

    public $data;

    protected $response;
    protected $request;

    protected $autowrapper;
    protected $method;
    protected $fromquery;

    protected $message;
    protected $result;

    protected $error;

    public function __construct()
    {
        $this->response = service('response');
        $this->request = service('request');
    }

    public function AutoWrapper()
    {
        $this->autowrapper = true;
        return;
    }

    public function HttpGet()
    {
        $this->method = 'GET';
        return;
    }

    public function FromQuery($column)
    {
        $this->fromquery = true;
        $this->column = $column;
        $this->value = $this->request->getGet($column);
        return;
    }

    public function send()
    {
        if ($this->method == 'GET') {
            if ($this->fromquery && !$this->value) {
                $this->response->setStatusCode(Response::HTTP_BAD_REQUEST);
                $this->message = "Require some variable to get";
            }
        }

        if ($this->response->getStatusCode() == 200) {
            if ($this->autowrapper) $this->result = ['data' => $this->data];
            else $this->result = $this->data;
        } else {
            $this->result = ['message' => $this->message];
        }

        $this->response->setJSON($this->result)->send();
        exit;
    }
}
