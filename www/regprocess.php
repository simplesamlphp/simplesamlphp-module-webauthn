<?php

include 'common.php';

session_cache_limiter('nocache');
$globalConfig = \SimpleSAML\Configuration::getInstance();

\SimpleSAML\Logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new \SimpleSAML\Error\BadRequest(
            'Missing required StateId query parameter.'
    );
}

$debugEnabled = FALSE;

$id = $_REQUEST['StateId'];
$state = \SimpleSAML\Auth\State::loadState($id, 'fido2SecondFactor:request');

// registering a credential is only allowed for new users or after being authenticated
if (count($state['FIDO2Tokens']) > 0 && $state['FIDO2AuthSuccessful'] !== TRUE) {
    throw new Exception("Attempt to register new token in unacceptable context.");
}

$regObject = new SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2RegistrationEvent(
        $_POST['type'],
        $state['FIDO2Scope'],
        $state['FIDO2SignupChallenge'],
        $state['IdPMetadata']['entityid'],
        base64_decode($_POST['attestation_object']),
        $_POST['response_id'],
        $_POST['attestation_client_data_json'],
        $debugEnabled);

// at this point, we need to talk to the DB
/**
 * STEP 19 of the validation procedure in § 7.1 of the spec: see if this credential is already registered
 */
$store = $state['fido2SecondFactor:store'];
if ($store->doesCredentialExist(bin2hex($regObject->credentialId)) === false) {
    // credential does not exist yet in database, good.
} else {
    throw new Exception("The credential with ID " . $regObject->credentialId . "already exists.");
}
// THAT'S IT. This is a valid credential and can be enrolled to the user.
$friendlyName = $_POST['tokenname'];
// if we have requested the token model, add it to the name
if ($state['requestTokenModel']) {
    $model = SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2RegistrationEvent::AAGUID_DICTIONARY[$regObject->AAGUID]["model"] ?? "unknown model";
    $vendor = SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2RegistrationEvent::AAGUID_DICTIONARY[$regObject->AAGUID]["O"] ?? "unknown vendor";
    $friendlyName .= " ($model [$vendor])";
}
$store->storeTokenData($state['FIDO2Username'], $regObject->credentialId, $regObject->credential, $regObject->counter, $friendlyName);
// make sure $state gets the news, the token is to be displayed to the user on the next page
$state['FIDO2Tokens'][] = [0 => $regObject->credentialId, 1 => $regObject->credential, 2 => $regObject->counter, 3 => $friendlyName];
\SimpleSAML\Auth\State::saveState($state, 'fido2SecondFactor:request');
if ($debugEnabled) {
    echo $regObject->debugBuffer;
    echo $regObject->validateBuffer;
    echo "<form id='regform' method='POST' action='" . \SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId=' . urlencode($id)) . "'>";
    echo "<button type='submit'>Return to previous page.</button>";
} else {
    \SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
}