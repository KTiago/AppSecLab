<?php
/**
 * Created by PhpStorm.
 * User: alex
 * Date: 16/11/19
 * Time: 13:17
 */

namespace App\EventSubscriber;


use App\Controller\CertificateAuthenticationController;
use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class CertificateSubscriber implements EventSubscriberInterface
{
    private $userRepository;
    private $tokenStorage;
    private $session;
    private $authorizationChecker;

    public function __construct(UserRepository $userRepository, TokenStorageInterface $tokenStorage, SessionInterface $session, AuthorizationCheckerInterface $authorizationChecker)
    {
        $this->userRepository = $userRepository;
        $this->tokenStorage = $tokenStorage;
        $this->session = $session;
        $this->authorizationChecker = $authorizationChecker;
    }

    public function onKernelController(ControllerEvent $event)
    {
        $controller = $event->getController();

        // when a controller class defines multiple action methods, the controller
        // is returned as [$controllerInstance, 'methodName']
        if (is_array($controller)) {
            $controller = $controller[0];
        }

        if ($controller instanceof CertificateAuthenticationController) {
            if (!($this->authorizationChecker->isGranted("ROLE_USER") || $this->authorizationChecker->isGranted("ROLE_ADMIN")) && isset($_SERVER['SSL_CLIENT_M_SERIAL'])) {
                // Get the info from the SSL env var
                $serial = hexdec($_SERVER['SSL_CLIENT_M_SERIAL']);

                // Check if it is in the DB
                $all = $this->userRepository->findAll();

                foreach ($all as $user) {
                    /** @var User $user */
                    if ($user->hasSn($serial)) {
                        // Manually login the user
                        $token = new UsernamePasswordToken($user, null, 'main', $user->getRoles());
                        $this->tokenStorage->setToken($token);
                        $this->session->set('_security_main', serialize($token));

                        return;
                    }
                }

                throw new AccessDeniedHttpException('You need to be authenticated with a valid certificate to access this resource!');
            }
        }
    }

    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::CONTROLLER => 'onKernelController',
        ];
    }
}
