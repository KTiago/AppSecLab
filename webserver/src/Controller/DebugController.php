<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 18/11/19
 * Time: 17:22
 */

namespace App\Controller;


use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DebugController extends AbstractController
{
    /**
     * @Route("/debug/{payload}", name="debug")
     * @param string $payload
     * @return Response
     */
    public function debug(string $payload)
    {
        $em = $this->getDoctrine()->getManager();

        $RAW_QUERY = 'SELECT email FROM users WHERE uid = "' . $payload . '";';

        $statement = $em->getConnection()->prepare($RAW_QUERY);
        $statement->execute();

        $result = $statement->fetchAll();
        var_dump($result);
        return new Response("Debug...", 201);
    }
}
