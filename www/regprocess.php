<?php

use SimpleSAML\Configuration;
use SimpleSAML\Error as SspError;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Auth;
use SimpleSAML\Module\webauthn\WebAuthn\AAGUID;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnRegistrationEvent;

if (session_status() != PHP_SESSION_ACTIVE) {
    session_cache_limiter('nocache');
}
$globalConfig = Configuration::getInstance();

Logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SspError\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$debugEnabled = false;

$id = $_REQUEST['StateId'];
$state = Auth\State::loadState($id, 'webauthn:request');

// registering a credential is only allowed for new users or after being authenticated
if (count($state['FIDO2Tokens']) > 0 && $state['FIDO2AuthSuccessful'] === false) {
    throw new Exception("Attempt to register new token in unacceptable context.");
}

$regObject = new WebAuthnRegistrationEvent(
    $_POST['type'],
    $state['FIDO2Scope'],
    $state['FIDO2SignupChallenge'],
    $state['IdPMetadata']['entityid'],
    base64_decode($_POST['attestation_object']),
    $_POST['response_id'],
    $_POST['attestation_client_data_json'],
    $debugEnabled
);

// at this point, we need to talk to the DB
/**
 * STEP 19 of the validation procedure in § 7.1 of the spec: see if this credential is already registered
 */
$store = $state['webauthn:store'];
if ($store->doesCredentialExist(bin2hex($regObject->credentialId)) === false) {
    // credential does not exist yet in database, good.
} else {
    throw new Exception("The credential with ID " . $regObject->credentialId . "already exists.");
}
// THAT'S IT. This is a valid credential and can be enrolled to the user.
$friendlyName = $_POST['tokenname'];
// if we have requested the token model, add it to the name
if ($state['requestTokenModel']) {
    $model = \SimpleSAML\Locale\Translate::noop('unknown model');
    $vendor = \SimpleSAML\Locale\Translate::noop('unknown vendor');
    $aaguiddict = AAGUID::getInstance();
    if ($aaguiddict->hasToken($regObject->AAGUID)) {
        $token = $aaguiddict->get($regObject->AAGUID);
        $model = $token['model'];
        $vendor = $token['O'];
    }
    $friendlyName .= " ($model [$vendor])";
}
/**
 * STEP 20 of the validation procedure in § 7.1 of the spec: store credentialId, credential, signCount and associate with user
 */
$store->storeTokenData($state['FIDO2Username'], $regObject->credentialId, $regObject->credential, $regObject->counter, $friendlyName);
// make sure $state gets the news, the token is to be displayed to the user on the next page
$state['FIDO2Tokens'][] = [0 => $regObject->credentialId, 1 => $regObject->credential, 2 => $regObject->counter, 3 => $friendlyName];
Auth\State::saveState($state, 'webauthn:request');
if ($debugEnabled === true) {
    echo $regObject->debugBuffer;
    echo $regObject->validateBuffer;
    echo "<form id='regform' method='POST' action='" . Module::getModuleURL('webauthn/webauthn.php?StateId=' . urlencode($id)) . "'>";
    echo "<button type='submit'>Return to previous page.</button>";
} else {
    Auth\ProcessingChain::resumeProcessing($state);
}
