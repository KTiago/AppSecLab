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
    private const CA_CORE_URL = "https://ca_core:8080";
    private const GET_CERTIFICATE_ENDPOINT = "/getCert";
    private const REVOKE_CERTIFICATE_ENDPOINT = "/revokeCert";
    private const GET_ADMIN_INFO = "/getAdminInfos";
    private const CERT_NAME = "/ca.cert.pem";

    private function getCaSharedSecret(): string
    {
        return $_SERVER['CA_SHARED_SECRET'];
    }

    private function request(array $data, string $endpoint): array {
        $data = array_merge(["pw" => self::getCaSharedSecret()], $data);
        $payload = json_encode($data);

        $url = self::CA_CORE_URL . $endpoint;
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
                'verify_peer' => 1,
                'verify_host' => TRUE,
                'cafile' => $cert,
            ]
        )->toArray();

        if ($response["status"] != "VALID") {
            throw new \Exception($response["data"]);
        }

        return $response;
    }

    public function requestCertificate(User $user)
    {
        $data = [
            "name" => $user->getUsername(),
            "email" => $user->getEmail()
        ];

        return $this->request($data, self::GET_CERTIFICATE_ENDPOINT);
    }

    public function revokeCertificate(int $sn)
    {
        $data = [
            "serialNumber" => $sn
        ];

        return $this->request($data, self::REVOKE_CERTIFICATE_ENDPOINT);
    }

    public function getAdminInfo()
    {
        return $this->request([], self::GET_ADMIN_INFO);
    }
}
