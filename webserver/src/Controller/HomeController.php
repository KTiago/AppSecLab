<?php

namespace App\Controller;

use App\Security\Encoder\ShaPasswordEncoder;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class HomeController extends AbstractController
{
    /**
     * @Route("/", name="home")
     */
    public function index()
    {
        $pe = new ShaPasswordEncoder();

        return $this->render('home.html.twig');
    }
}