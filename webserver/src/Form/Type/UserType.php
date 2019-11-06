<?php

namespace App\Form\Type;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('uid', TextType::class, array(
                'attr' => array(
                    'readonly' => true,
                ),
                'label' => "Identifier"
            ))
            ->add('firstname', TextType::class, ['label' => 'First name'])
            ->add('lastname', TextType::class, ['label' => 'Last name'])
            ->add('email', TextType::class, ['label' => 'E-Mail address'])
            ->add('pwd', PasswordType::class, ['label' => 'Password'])
            ->add('save', SubmitType::class, ['label' => 'Save']);
    }

    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}