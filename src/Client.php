<?php

namespace Psecio\Vaultlib;

class Client
{
    protected $httpClient;
    protected $baseUrl;
    protected $accessToken;

    /**
     * Initialize the object with the access token and base URL for requests
     *
     * @param string $accessToken Access token to make requests
     * @param string $baseUrl Base URL for all requests
     */
    public function __construct($accessToken, $baseUrl)
    {
        $this->httpClient = $this->buildClient($accessToken, $baseUrl);
        $this->baseUrl = $baseUrl;
        $this->accessToken = $accessToken;
    }

    /**
     * Get the current HTTP client
     *
     * @return \GuzzleHttp\Client instance
     */
    public function getClient()
    {
        return $this->httpClient;
    }

    /**
     * Check to see if the vault is currently sealed
     *
     * @return boolean True if sealed, false if not
     */
    public function isSealed()
    {
        $response = $this->getClient()->request('GET', '/v1/sys/seal-status');
        $body = $this->getFullBody($response->getBody());

        return (!isset($body['sealed']) || $body['sealed'] === true) ? true : false;
    }

    /**
     * Seal the vault with the provided key
     *
     * @param string $key Key to use to seal the vault
     * @param boolean $reset
     * @throws \Exception If there is an error on the request
     * @return boolean Success/fail of the seal operation
     */
    public function seal($key, $reset = false)
    {
        $reset = ($reset === false) ? 'false' : 'true';
        try {
            $response = $this->getClient()->request('PUT', '/v1/sys/seal', [
                'body' => '{"key":"'.$key.'","reset": '.$reset.'}'
            ]);
            if ($response->getStatusCode() == 204) {
                return true;
            }
        } catch (\Exception $e) {
            throw new \Exception(join(", ", $this->parseErrors($e)));
        }
        return false;
    }

    /**
     * Unseal the vault
     *
     * @param string $key The key to use for unsealing
     * @param boolean $reset
     * @return boolean Success/fail of the unseal action
     */
    public function unseal($key, $reset = false)
    {
        $reset = ($reset === false) ? 'false' : 'true';
        $response = $this->getClient()->request('PUT', '/v1/sys/unseal', [
            'body' => '{"key":"'.$key.'","reset": '.$reset.'}'
        ]);
        if ($response->getStatusCode() == 204) {
            return true;
        }
        return false;
    }
    
    /**
     * Get the full body contents of the provided response instance
     *
     * @param \GuzzleHttp\Psr7\Stream $responseBody Stream instance
     * @throws \Exception If there was an error parsin the JSON response
     * @return string Body contents
     */
    public function getFullBody(\GuzzleHttp\Psr7\Stream $responseBody)
    {
        $responseBody->seek(0);
        $output = json_decode(trim($responseBody->getContents()), true);
        if ($output === null) {
            throw new \Exception('Error parsing response JSON ('.json_last_error().')');
        }

        return $output;
    }

    /**
     * Parse the errors from the provided exception
     *
     * @param \Exception $exception Exception instance
     * @return array Set of error messages (strings)
     */
    public function parseErrors($exception)
    {
        $body = $exception->getResponse()->getBody()->getContents();
        return json_decode($body, true)['errors'];
    }
    
    /**
     * Get the secret value for the provided key
     *
     * @param string $secretKey Key to locate in the vault
     * @throws \Exception If secret is not found
     * @throws \Exception If error on GET request
     * @return mixed Returns value if found or false
     */
    public function getSecret($secretKey)
    {
        try {
            $response = $this->getClient()->request('GET', '/v1/secret/data/'.$secretKey);
            return $this->getFullBody($response->getBody());

        } catch (\Exception $e) {
            $status = $e->getResponse()->getStatusCode();
            if ($status == 404) {
                throw new \Exception('Secret "'.$secretKey.'" not found');
            }

            throw new \Exception(join(", ", $this->parseErrors($e)));
        }
        return false;
    }

    /**
     * Used for both setting a new secret and updating one
     *
     * @param string $secretKey Key to set secret value on
     * @param mixed $data Data to set on secret key
     * @return string Response body from save
     */
    public function setSecret($secretKey, array $data) : array
    {
        $data = ['data' => $data];

        $response = $this->getClient()->request('POST', '/v1/secret/data/'.$secretKey, [
            'json' => $data
        ]);
        return $this->getFullBody($response->getBody());
    }

    /**
     * Delete the secret defined by the provided key
     *
     * @param string $secretKey Key name
     * @return string Response message
     */
    public function deleteSecret($secretKey)
    {
        $response = $this->getClient()->request('DELETE', '/v1/secret/data/'.$secretKey);
        if ($response->getStatusCode() == 204) {
            return true;
        }

        return $this->getFullBody($response->getBody());
    }

    /**
     * Get the listing of the values in the provided key
     *
     * @param string $secretKey Key name
     * @throws \Exception If error on list request
     */
    public function getList($secretKey)
    {
        $client = $this->getClient();
        $request = new \GuzzleHttp\Psr7\Request('LIST', $this->baseUrl.'/v1/secret/metadata/'.$secretKey, [
            'headers' => [
                'X-Vault-Token' => $this->accessToken,
                'Accept' => 'application/json',
            ]
        ]);

        try {
            $result = $client->send($request);
            return $this->getFullBody($result->getBody());
        } catch (\Exception $e) {
            $status = $e->getResponse()->getStatusCode();
            if ($status == 404) {
                throw new \Exception('List for "'.$secretKey.'" not found');
            }

            throw new \Exception(join(", ", $this->parseErrors($e)));
        }

        
    }

    /**
     * Get the metadata for the provided key name
     *
     * @param string $secretKey Key name
     * @return string Response text (includes metadata)
     */
    public function getSecretMeta($secretKey)
    {
        $response = $this->getClient()->request('GET', '/v1/secret/metadata/'.$secretKey);
        return $this->getFullBody($response->getBody());
    }

    /**
     * Build the HTTP client with the provided token and URL
     *
     * @param string $accessToken Vault access token
     * @param string $baseUrl Base URL of the remote Vault system (include port)
     * @return \GuzzleHttp\Client instance
     */
    public function buildClient($accessToken, $baseUrl)
    {
        $client = new \GuzzleHttp\Client([
            'base_uri' => $baseUrl,
            'timeout'  => 2.0,
            'headers' => [
                'X-Vault-Token' => $accessToken,
                'Accept' => 'application/json',
            ]
        ]);
        return $client;
    }
}