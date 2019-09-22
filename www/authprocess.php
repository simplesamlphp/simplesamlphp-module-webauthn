<?php

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnAbstractEvent;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnAuthenticationEvent;

if (session_status() != PHP_SESSION_ACTIVE) {
    session_cache_limiter('nocache');
}
$globalConfig = Configuration::getInstance();

Logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new Error\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$debugEnabled = false;

$id = $_REQUEST['StateId'];
$state = Auth\State::loadState($id, 'webauthn:request');

$incomingID = bin2hex(WebAuthnAbstractEvent::base64url_decode($_POST['response_id']));

/**
 * §7.2 STEP 2 - 4 : check that the credential is one of those the particular user owns
 */
$publicKey = false;
$previousCounter = -1;
foreach ($state['FIDO2Tokens'] as $oneToken) {
    if ($oneToken[0] == $incomingID) {
        // Credential ID is eligible for user $state['FIDO2Username']; using publicKey $oneToken[1] with current counter value $oneToken[2]
        $publicKey = $oneToken[1];
        $previousCounter = $oneToken[2];
        break;
    }
}
if ($publicKey === false) {
    throw new Exception("User attempted to authenticate with an unknown credential ID. This should already have been prevented by the browser!");
}

$authObject = new WebAuthnAuthenticationEvent(
    $_POST['type'],
    $state['FIDO2Scope'], 
    $state['FIDO2SignupChallenge'], 
    $state['IdPMetadata']['entityid'], 
    base64_decode($_POST['authenticator_data']), 
    base64_decode($_POST['client_data_raw']), 
    $oneToken[0],
    $oneToken[1], 
    base64_decode($_POST['signature']), 
    $debugEnabled
);

/**
 * §7.2 STEP 18 : detect physical object cloning on the token
 */
if (($previousCounter != 0 || $authObject->counter != 0) && $authObject->counter > $previousCounter) {
    // Signature counter was incremented compared to last time, good
    $store = $state['webauthn:store'];
    $store->updateSignCount($oneToken[0], $authObject->counter);
} else {
    throw new Exception("Signature counter less or equal to a previous authentication! Token cloning likely (old: $previousCounter, new: $authObject->counter.");
}
// THAT'S IT. The user authenticated successfully. Remember the credential ID that was used.
$state['FIDO2AuthSuccessful'] = $oneToken[0];
// See if he wants to hang around for token management operations
if (isset($_POST['credentialChange']) && $_POST['credentialChange'] == "on") {
    $state['FIDO2WantsRegister'] = true;
} else {
    $state['FIDO2WantsRegister'] = false;
}
Auth\State::saveState($state, 'webauthn:request');

if ($debugEnabled) {
    echo $authObject->debugBuffer;
    echo $authObject->validateBuffer;
    echo "Debug mode, not continuing to ". ($state['FIDO2WantsRegister'] ? "credential registration page." : "destination.");
} else {
    if ($state['FIDO2WantsRegister']) {
        header("Location: ".Module::getModuleURL('webauthn/webauthn.php?StateId='.urlencode($id)));
    } else {
        Auth\ProcessingChain::resumeProcessing($state);
    }
}

