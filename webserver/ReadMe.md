# iMovie's webserver

The web server uses the Symfony (4.8.2) framework, running on PHP 7.2.24.

## Installation

To deploy the webserver, type the following command : `composer install`. If composer is not installed then grab it [here](https://getcomposer.org/).

Start the server with `symfony server:start`.

Start the asset files compilation with `yarn encore dev --watch`. If yarn is not installed, grab it [here](https://yarnpkg.com/).

(there is more stuff to do to install it I'll complete later)

## Architecture

Here are listed the relevant folders and files.
- assets/ : CSS & JS code for front-end
- config/ : .yaml files for configuration (ex config/packages/security.yaml configures the firewall and authentication provider)
- public/ 
    - index.php : entry point of the website
    - build/ : compiled assets files
- src/
    - Controller/ : controllers for user's action 
    - Entity/ : plain PHP objects (like User object that will be loaded from the DB)
    - Form/Type/ : forms for users (ex: update information form)
    - Repository/ : classes to fetch and modify data in the DB
    - Security/
        - Encoder/ : password encoder (encoding password in SHA1 in our case)
- templates/ : .twig files template to render the page 