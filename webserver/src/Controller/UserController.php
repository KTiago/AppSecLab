<?php

namespace App\Controller;

use App\CertificateManager;
use App\Entity\User;
use App\FileWriter;
use App\Form\Type\UserType;
use App\Security\Encoder\ShaPasswordEncoder;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    /**
     * @Route("/user/", name="user_home")
     */
    public function index()
    {
        return $this->render('user/user_home.html.twig');
    }

    /**
     * @param Request $request
     * @Route("/user/update/", name="update_user_information")
     * @return Response
     */
    public function update(Request $request)
    {
        $user = $this->getUser();
        $form = $this->createForm(
            UserType::class,
            $user
        );

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            /** @var User $user */
            $user = $form->getData();

            // Encode the password
            $encoder = new ShaPasswordEncoder();
            $encoded = $encoder->encodePassword($user->getPassword(), null);
            $user->setPwd($encoded);

            // Fetch certificate
            $data = CertificateManager::requestCertificate($user);
            $certificate = $data["data"];
            $sn = $data["sn"];

            // Add the new sn to the user
            $user->addSn($sn);

            // Save the user in the DB
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            $this->addFlash('success', 'Your personal data have been updated.');

            // Decode the certificate
            $certificate = base64_decode($certificate);

            return $this->downloadCert($certificate, $user->getUsername());
        }

        return $this->render('user/update_user_information.html.twig', [
            'form' => $form->createView()
        ]);
    }

    public function downloadCert(string $certificate, string $username)
    {
        // Write the cert
        $path = dirname(__DIR__) . "/.." . FileWriter::TMP_DIRECTORY . "/";
        $filename = $username . "_certificate.p12";
        $pathfile = $path . $filename;
        $fw = new FileWriter();
        $fw->write($pathfile, $certificate);

        // Make it downloadable for the user
        $response = new BinaryFileResponse($pathfile);
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $filename);

        return $response;
    }

    /**
     * @Route("/user/revocation/", name="revoke_user_certificate")
     * @return Response
     */
    public function revokeCert()
    {
        /** @var User $user */
        $user = $this->getUser();

        return $this->render('user/revoke_cert.html.twig', [
           "sns" => $user->getSn()
        ]);
    }

    /**
     * @Route("/user/revoke/{sn}", name="revoke_cert_sn", requirements={"page"="\d+"})
     * @param int $sn, the serial number to be revoked
     * @return Response
     */
    public function revokeCertWithSn(int $sn) {
        /** @var User $user */
        $user = $this->getUser();

        // Checking is SN belongs to user's array
        try {
            $user->removeSn($sn);

            // Revoke the cert
            CertificateManager::revokeCertificate($sn);

            // Save the user in the DB
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            $this->addFlash('success', 'Your certificate has been revoked.');
        } catch (\Exception $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('revoke_user_certificate');
    }
}