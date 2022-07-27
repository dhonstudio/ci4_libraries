<?php

namespace Assets\Ci4_libraries;

class DhonRequest
{
    /**
     * API URL.
     * 
     * @var string
     */
    public $api_url;

    /**
     * API auth if use basic auth.
     * 
     * @var string[]
     */
    public $api_auth;

    /**
     * CURL requester.
     */
    protected $client;

    public function __construct($params)
    {
        $this->api_url  = $params['api_url'];
        $this->api_auth = $params['api_auth'];

        $this->client   = \Config\Services::curlrequest();
    }

    /**
     * Request GET to URL Endpoint.
     */
    public function get(string $endpoint)
    {
        return json_decode(json_decode($this->client->get($this->api_url . $endpoint, [
            'auth' => $this->api_auth,
        ])->getJSON()), TRUE);
    }

    /**
     * Request POST to URL Endpoint.
     */
    public function post(string $endpoint, array $params)
    {
        return json_decode(json_decode($this->client->post($this->api_url . $endpoint, [
            'auth' => $this->api_auth,
            'form_params' => $params,
        ])->getJSON()), TRUE);
    }

    /**
     * Request CURL to an URL.
     */
    public function curl(string $url)
    {
        return json_decode($this->client->get($url)->getJSON());
    }
}
