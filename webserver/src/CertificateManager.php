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
use Symfony\Component\HttpFoundation\Request;

class CertificateManager
{
    private const CA_CORE_URL = "https://localhost:8080";
    private const GET_CERTIFICATE_ENDPOINT = "/getCert";
    private const GET_REVOKED_LIST_ENDPOINT = "/revokeList";
    private const REVOKE_CERTIFICATE_ENDPOINT = "/revokeCert";

    public static function requestCertificate(User $user)
    {
        // Request's data
        $data = [
            "name" => $user->getUsername(),
            "email" => $user->getEmail()
        ];

        $url = self::CA_CORE_URL . self::GET_CERTIFICATE_ENDPOINT;
        $cert = dirname(__DIR__) . "/cacore.pem";

        $ch = curl_init();

        $payload = json_encode($data);

        // set url
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt ($ch, CURLOPT_CAINFO, $cert);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($payload))
        );

        // $output contains the output string
        $output = curl_exec($ch);
        if ( ! $output) {
            throw new \Exception(curl_errno($ch) .': '. curl_error($ch));
        }

        // close curl resource to free up system resources
        curl_close($ch);

        return $output;
    }

    public static function getRevokationList() {
        $url = self::CA_CORE_URL . self::GET_REVOKED_LIST_ENDPOINT;
        $cert = dirname(__DIR__) . "/cacore.pem";
        $ch = curl_init();

        // set url
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt ($ch, CURLOPT_CAINFO, $cert);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);

        // $output contains the output string
        $output = curl_exec($ch);
        if ( ! $output) {
            throw new \Exception(curl_errno($ch) .': '. curl_error($ch));
        }

        // close curl resource to free up system resources
        curl_close($ch);

        return $output;
    }

    public static function revokeCertificate(User $user) {
        $data = [
            "email" => $user->getEmail()
        ];

        $url = self::CA_CORE_URL . self::REVOKE_CERTIFICATE_ENDPOINT;
        $cert = dirname(__DIR__) . "/cacore.pem";

        $ch = curl_init();

        $payload = json_encode($data);

        // set url
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt ($ch, CURLOPT_CAINFO, $cert);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($payload))
        );

        // $output contains the output string
        $output = curl_exec($ch);
        if ( ! $output) {
            throw new \Exception(curl_errno($ch) .': '. curl_error($ch));
        }

        // close curl resource to free up system resources
        curl_close($ch);

        var_dump($output);
    }
}