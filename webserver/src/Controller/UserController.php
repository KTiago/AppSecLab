<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\Type\UserType;
use App\Security\Encoder\ShaPasswordEncoder;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
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
    public function update(Request $request) {
        $user = $this->getUser();
        $form = $this->createForm(UserType::class, $user);

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            /** @var User $user */
            $user = $form->getData();

            // Encode the password
            $encoder = new ShaPasswordEncoder();
            $encoded = $encoder->encodePassword($user->getPassword(), null);
            $user->setPwd($encoded);

            // Save the user in the DB
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            $this->addFlash('success', 'Your personal data have been updated.');
        }

        return $this->render('user/update_user_information.html.twig', [
            'form' => $form->createView()
        ]);
    }
}