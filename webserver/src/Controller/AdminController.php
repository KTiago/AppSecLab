<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 29/10/19
 * Time: 13:52
 */

namespace App\Controller;


use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;

class AdminController extends AbstractController
{
    /**
     * @Route("/admin/", name="admin_home")
     */
    public function index() {

    }
}