<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class UserController extends AbstractController
{
    /**
     * @Route("/user/", name="user_home")
     */
    public function index()
    {
        $user = $this->getUser();

        return new Response("Yo " . $user->getUsername());
    }

}