<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 06/11/19
 * Time: 20:37
 */

namespace App;


use App\Entity\User;
use Symfony\Component\HttpClient\HttpClient;

class CertificateManager
{
    private const CA_CORE_URL = "https://localhost:8080";
    private const GET_CERTIFICATE_ENDPOINT = "/getCert";
    private const GET_REVOKED_LIST_ENDPOINT = "/revokeList";
    private const REVOKE_CERTIFICATE_ENDPOINT = "/revokeCert";
    private const GET_ADMIN_INFO = "/getAdminInfos";
    private const CERT_NAME = "/cacore.pem";

    public const STATUS_FIELD = "status";
    public const DATA_FIELD = "data";
    public const VALID_REQUEST = "VALID";

    public static function requestCertificate(User $user)
    {
        // Request's data
        $data = [
            "name" => $user->getUsername(),
            "email" => $user->getEmail()
        ];
        $payload = json_encode($data);

        $url = self::CA_CORE_URL . self::GET_CERTIFICATE_ENDPOINT;
        $cert = dirname(__DIR__) . self::CERT_NAME;

        $client = HttpClient::create();
        $response = $client->request(
            'POST',
            $url,
            [
                'headers' => [
                    "Content-Type" => "application/json",
                    "Content-Length" => strlen($payload)
                ],
                'body' => $payload,
                'verify_peer' => 0,
                'verify_host' => FALSE,
                'cafile' => $cert,
            ]
        );

        self::checkValidity($response->toArray());

        return $response->toArray()[self::DATA_FIELD];
    }

    public static function getRevokationList(): array
    {
        $url = self::CA_CORE_URL . self::GET_REVOKED_LIST_ENDPOINT;
        $cert = dirname(__DIR__) . self::CERT_NAME;

        $client = HttpClient::create();
        $response = $client->request(
            'GET',
                    $url,
                    [
                        'verify_peer' => 0,
                        'verify_host' => FALSE,
                        'cafile' => $cert,
                    ]
        );

        var_dump($response->toArray());
        self::checkValidity($response->toArray());

        return $response->toArray()["serials"];
    }

    public static function revokeCertificate(User $user)
    {
        $data = [
            "email" => $user->getEmail()
        ];
        $payload = json_encode($data);

        $url = self::CA_CORE_URL . self::REVOKE_CERTIFICATE_ENDPOINT;
        $cert = dirname(__DIR__) . self::CERT_NAME;


        $client = HttpClient::create();
        $response = $client->request(
            'POST',
            $url,
            [
                'headers' => [
                    "Content-Type" => "application/json",
                    "Content-Length" => strlen($payload)
                ],
                'body' => $payload,
                'verify_peer' => 0,
                'verify_host' => FALSE,
                'cafile' => $cert,
            ]
        );

        self::checkValidity($response->toArray());

        return $response->toArray()[self::DATA_FIELD];
    }

    public static function getAdminInfo() {
        $url = self::CA_CORE_URL . self::GET_ADMIN_INFO;
        $cert = dirname(__DIR__) . self::CERT_NAME;

        $client = HttpClient::create();
        $response = $client->request(
            'GET',
            $url,
            [
                'verify_peer' => 0,
                'verify_host' => FALSE,
                'cafile' => $cert,
            ]
        );

        self::checkValidity($response->toArray());

        return $response->toArray();
    }

    private static function checkValidity(array $response) {
        if ($response[self::STATUS_FIELD] != self::VALID_REQUEST) {
            throw new \Exception($response["data"]);
        }
    }
}