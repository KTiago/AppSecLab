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

class UserController extends AbstractController implements CertificateAuthenticationController
{
    private $certificateManager;

    public function __construct()
    {
        $this->certificateManager = new CertificateManager();
    }

    /**
     * @Route("/user/", name="user_home")
     */
    public function index()
    {
        $this->denyAccessUnlessGranted('ROLE_USER', null, 'You must be logged in to access this page!');

        return $this->render('user/user_home.html.twig');
    }

    /**
     * @param Request $request
     * @Route("/user/update/", name="update_user_information")
     * @return Response
     */
    public function update(Request $request)
    {
        $this->denyAccessUnlessGranted('ROLE_USER', null, 'You must be logged in to access this page!');

        /** @var User $user */
        $user = $this->getUser();
        $form = $this->createForm(
            UserType::class,
            $user
        );
        $oldMail = $user->getEmail();
        $id = $user->getUid();

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            /** @var User $user */
            $user = $form->getData();

            // Enforce that the ID can't be change
            $user->setUid($id);

            // Encode the password
            $encoder = new ShaPasswordEncoder();
            $encoded = $encoder->encodePassword($user->getPassword(), null);
            $user->setPwd($encoded);

            $canDownloadCertificate = ($user->getEmail() != $oldMail) || (empty($user->getSn()));

            // If the mail has changed then we request a new certificate
            if ($canDownloadCertificate) {
                // Fetch certificate
                $data = $this->certificateManager->requestCertificate($user);
                $certificate = $data["data"];
                $sn = $data["sn"];

                // Add the new sn to the user
                $user->addSn($sn);

                // Decode the certificate
                $certificate = base64_decode($certificate);
            }

            // Save the user in the DB
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            $this->addFlash('success', 'Your personal data have been updated.');

            if ($canDownloadCertificate) {
                return $this->downloadCert($certificate, $user->getUsername());
            } else {
                return $this->redirectToRoute('user_home');
            }
        }

        return $this->render('user/update_user_information.html.twig', [
            'form' => $form->createView()
        ]);
    }

    private function downloadCert(string $certificate, string $username)
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
        $this->denyAccessUnlessGranted('ROLE_USER', null, 'You must be logged in to access this page!');

        /** @var User $user */
        $user = $this->getUser();

        return $this->render('user/revoke_cert.html.twig', [
            "sns" => $user->getSn()
        ]);
    }

    /**
     * @Route("/user/revoke/{sn}", name="revoke_cert_sn", requirements={"page"="\d+"})
     * @param int $sn , the serial number to be revoked
     * @return Response
     */
    public function revokeCertWithSn(int $sn)
    {
        $this->denyAccessUnlessGranted('ROLE_USER', null, 'You must be logged int o access this page!');

        /** @var User $user */
        $user = $this->getUser();

        // Checking is SN belongs to user's array
        try {
            $user->removeSn($sn);

            // Revoke the cert
            $response = $this->certificateManager->revokeCertificate($sn);

            $crl = $response['crl'];
            $fw = new FileWriter();
            $dir = dirname(__DIR__) . "/../rev";
            $path = $dir . "/revocation.crl";
            $fw->write($path, $crl);

            // Create the symlink for Apache2
            shell_exec("rm " . $dir . "/*.r0");
            shell_exec("cd " . $dir . " && ln -s " . $path . " `openssl crl -hash -noout -in " . $path . "`.r0");
	    shell_exec("cd /../bin/ && ./console cache:clear");

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
