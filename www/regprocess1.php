<?php

include 'common1.php';

session_cache_limiter('nocache');
$globalConfig = \SimpleSAML\Configuration::getInstance();

\SimpleSAML\Logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new \SimpleSAML\Error\BadRequest(
            'Missing required StateId query parameter.'
    );
}

$debugEnabled = TRUE;
global $debugbuffer;
global $validatebuffer;
$debugbuffer = "";
$validatebuffer = "";
$id = $_REQUEST['StateId'];
$state = \SimpleSAML\Auth\State::loadState($id, 'fido2SecondFactor:request');

$debugbuffer .= "Incoming parameters:<hr/>
Requested operation: " . $_POST['operation'] . "
<hr/>
Responde ID (B64): " . $_POST['response_id'] . "<br/>Response ID (bin2hex): " . bin2hex(\SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2AbstractEvent::base64url_decode($_POST['response_id'])) . "
<hr/>
Type: " . $_POST['type'] . "
<hr/>
Desired Token Name: ";

$friendlyName = $_POST['tokenname'];
$debugbuffer .= $friendlyName . "
<hr/>
Client Attestation Data (JSON-decoded): <pre>" . print_r(json_decode($_POST['attestation_client_data_json'], true), true) . "</pre>
<hr/>
Attestation Object (CBOR decoded, normalized): ";

/**
 * This is not a required validation as per spec. Still odd that Firefox returns
 * "undefined" even though its own API spec says it will send "public-key".
 */
switch ($_POST['type']) {
    case "public-key": pass("Key Type");
        break;
    case "undefined": warn("Key Type 'undefined' - Firefox or Yubikey issue?");
        break;
    default: fail("Unknown Key Type: " . $_POST['type']);
}

$regObject = new SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2RegistrationEvent($state['FIDO2Scope'], $state['FIDO2SignupChallenge'], $state['IdPMetadata']['entityid'], base64_decode($_POST['attestation_object']), $_POST['response_id'], $_POST['attestation_client_data_json'], $debugEnabled);

// at this point, we need to talk to the DB
/**
 * STEP 19 of the validation procedure in § 7.1 of the spec: see if this credential is already registered
 */
$store = $state['fido2SecondFactor:store'];
if ($store->doesCredentialExist(bin2hex($regObject->credentialId)) === false) {
    pass("Credential does not exist yet in database.");
} else {
    fail("This credential already exists.");
}
// THAT'S IT. This is a valid credential and can be enrolled to the user.
$store->storeTokenData($state['FIDO2Username'], $regObject->credentialId, $regObject->credential, $regObject->counter, $friendlyName);
pass("Credential registered.");
// make sure $state gets the news, the token is to be displayed to the user on the next page
$state['FIDO2Tokens'][] = [0 => $regObject->credentialId, 1 => $regObject->credential, 2 => $regObject->counter, 3 => $friendlyName];
$state['FIDO2EnrollmentAllowed'] = false;
\SimpleSAML\Auth\State::saveState($state, 'fido2SecondFactor:request');
if ($debugEnabled) {
    echo $debugbuffer;
    echo $regObject->debugBuffer;
    echo $regObject->validateBuffer;
    echo $validatebuffer;
    echo "<form id='regform' method='POST' action='" . \SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId=' . urlencode($id)) . "'>";
    echo "<button type='submit'>Return to previous page.</button>";
} else {
    header("Location: " . \SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId=' . urlencode($id)));
}

