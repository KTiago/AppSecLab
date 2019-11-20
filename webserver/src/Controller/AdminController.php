<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 29/10/19
 * Time: 13:52
 */

namespace App\Controller;


use App\CertificateManager;
use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AdminController extends AbstractController implements CertificateAuthenticationController
{
    private $certificateManager;

    public function __construct()
    {
        $this->certificateManager = new CertificateManager();
    }

    /**
     * @Route("/admin/", name="admin_home")
     */
    public function index() {
        $this->denyAccessUnlessGranted('ROLE_ADMIN', null, 'You must be an admin to access this page!');

        $adminInfo = $this->certificateManager->getAdminInfo();

        return $this->render('admin/admin.html.twig', $adminInfo);
    }
}
