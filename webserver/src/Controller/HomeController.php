<?php

namespace App\Controller;

use App\CertificateManager;
use http\Env\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
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
        $list = CertificateManager::getRevokationList();

        return new JsonResponse($list);
    }
}