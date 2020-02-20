<?php

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error as SspError;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Utils;
use SimpleSAML\Module;

if (session_status() != PHP_SESSION_ACTIVE) {
    session_cache_limiter('nocache');
}

Logger::info('FIDO2 - Accessing WebAuthn token management');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SspError\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];
/** @var array $state */
$state = Auth\State::loadState($id, 'webauthn:request');

if ($state['FIDO2AuthSuccessful'] === false) {
    throw new Exception("Attempt to access the token management page unauthenticated.");
}
switch ($_POST['submit']) {
    case "NEVERMIND":
        Auth\ProcessingChain::resumeProcessing($state);
        break;
    case "DELETE":
        if ($state['FIDO2AuthSuccessful'] == $_POST['credId']) {
            throw new Exception("Attempt to delete the currently used credential despite UI preventing this.");
        }
        $store = $state['webauthn:store'];
        $store->deleteTokenData($_POST['credId']);
        if (array_key_exists('Registration', $state)) {
            
            foreach ($state['FIDO2Tokens'] as $key => $value) {
                if ($state['FIDO2Tokens'][$key][0] == $_POST['credId']) {
                    unset($state['FIDO2Tokens'][$key]);
                    break;
                }            
            }

            StaticProcessHelper::saveStateAndRedirect($state);
        } else {
            Auth\ProcessingChain::resumeProcessing($state);
        }
        break;
    default:
        throw new Exception("Unknown submit button state.");
}
