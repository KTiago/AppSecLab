<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class HomeController extends AbstractController
{
    /**
     * @Route("/", name="home")
     */
    public function index()
    {
        return $this->render('home.html.twig');
    }

    /**
     * @Route("/revokedList", name="revoked_list")
     */
    public function getRevokedList() {
        $path = dirname(__DIR__) . "/../rev/";
        $filename = "revocation.crl";
        $pathfile = $path . $filename;

        // Make it downloadable for the user
        $response = new BinaryFileResponse($pathfile);
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $filename);

        return $response;
    }

    /**
     * @Route("/login_certificate", name="login_certificate")
     */
    public function showLoginCertificate() {
        return $this->redirectToRoute('user_home');
    }
}