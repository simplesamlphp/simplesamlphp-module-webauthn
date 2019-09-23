<?php

$projectRoot = dirname(__DIR__);
require_once($projectRoot . '/vendor/autoload.php');

// Symlink module into ssp vendor lib so that templates and urls can resolve correctly
$linkPath = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/modules/webauthn';
if (file_exists($linkPath) === false) {
    print "Linking '$linkPath' to '$projectRoot'\n";
    symlink($projectRoot, $linkPath);
}
