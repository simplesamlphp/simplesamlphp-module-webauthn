<?php

namespace SimpleSAML\Module\webauthn;

use SimpleSAML\Configuration;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;

$config = Configuration::getInstance();
$session = Session::getSessionFromRequest();
$request = Request::createFromGlobals();

$controller = new Controller\WebAuthn($config, $session);
$t = $controller->main($request);
$t->show();
