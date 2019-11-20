<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Table(name="users")
 * @ORM\Entity(repositoryClass="App\Repository\UserRepository")
 * @UniqueEntity("email")
 */
class User implements UserInterface
{
    /**
     * @ORM\Id()
     * @ORM\GeneratedValue()
     * @ORM\Column(type="string", length=64, unique=true)
     */
    private $uid;

    /**
     * @ORM\Column(type="json")
     */
    private $roles = [];

    /**
     * @ORM\Column(type="json")
     */
    private $sn = [];

    /**
     * @var string The hashed password
     * @ORM\Column(type="string", length=64)
     */
    private $pwd;

    /**
     * @var string The lastname
     * @ORM\Column(type="string", length=64)
     */
    private $lastname;

    /**
     * @var string the first name
     * @ORM\Column(type="string", length=64)
     */
    private $firstname;

    /**
     * @var string the email
     * @ORM\Column(type="string", length=64, unique=true)
     */
    private $email;

    public function getUid(): ?string
    {
        return $this->uid;
    }

    public function setUid(string $uid): self
    {
        $this->uid = $uid;

        return $this;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;

        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    public function getSn(): array
    {
        return (array)$this->sn;
    }

    public function setSn(array $sn): self
    {
        $this->sn = $sn;

        return $this;
    }

    public function addSn(int $sn): self
    {
        $current = $this->getSn();
        array_push($current, $sn);

        return $this->setSn($current);
    }

    public function removeSn(int $sn): self
    {
        if (!$this->hasSn($sn)) {
            throw new \InvalidArgumentException("Invalid SN value");
        }

        $key = $this->getSnKey($sn);
        $current = $this->getSn();
        unset($current[$key]);

        return $this->setSn($current);
    }

    private function getSnKey(int $sn) {
        return array_search($sn, $this->getSn());
    }

    public function hasSn(int $sn)
    {
        return in_array($sn, $this->getSn());
    }

    /**
     * @see UserInterface
     */
    public function getPwd(): string
    {
        return (string)$this->pwd;
    }

    public function setPwd(string $pwd): self
    {
        $this->pwd = $pwd;

        return $this;
    }


    /**
     * @see UserInterface
     */
    public function getSalt()
    {
        // not needed when using the "bcrypt" algorithm in security.yaml
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials()
    {
        // If you store any temporary, sensitive data on the user, clear it here
        // $this->plainPassword = null;
    }

    /**
     * Returns the password used to authenticate the user.
     *
     * This should be the encoded password. On authentication, a plain-text
     * password will be salted, encoded, and then compared to this value.
     *
     * @return string|null The encoded password if any
     */
    public function getPassword()
    {
        return $this->pwd;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->uid;
    }

    public function setUsername(string $username)
    {
        return $this->setUid($username);
    }

    public function setPassword(string $password)
    {
        return $this->setPwd($password);
    }

    /**
     * @return string
     */
    public function getLastname(): string
    {
        return $this->lastname;
    }

    /**
     * @param string $lastname
     * @return User
     */
    public function setLastname(string $lastname): User
    {
        $this->lastname = $lastname;
        return $this;
    }

    /**
     * @return string
     */
    public function getFirstname(): string
    {
        return $this->firstname;
    }

    /**
     * @param string $firstname
     * @return User
     */
    public function setFirstname(string $firstname): User
    {
        $this->firstname = $firstname;
        return $this;
    }

    /**
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * @param string $email
     * @return User
     */
    public function setEmail(string $email): User
    {
        $this->email = $email;
        return $this;
    }


}

