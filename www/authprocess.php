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

global $debugbuffer;
global $validatebuffer;
global $debugEnabled;
$debugEnabled = FALSE;

$validatebuffer = "";
$debugbuffer = "";
$id = $_REQUEST['StateId'];
$state = \SimpleSAML\Auth\State::loadState($id, 'fido2SecondFactor:request');

$incomingID = bin2hex(\SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2AbstractEvent::base64url_decode($_POST['response_id']));

$debugbuffer .= "Incoming parameters:<hr/>
Requested operation: " . $_POST['operation'] . "
<hr/>
Responde ID (B64): " . $_POST['response_id'] . "<br/>Response ID (bin2hex): " . $incomingID . "
<hr/>
Type: " . $_POST['type'] . "
<hr/>
authData Object (binary byte sequence): ";

$authData = base64_decode($_POST['authenticator_data']);
$debugbuffer .= "<pre>";
$debugbuffer .= print_r($authData, true);
$debugbuffer .= "</pre>";
switch ($_POST['type']) {
    case "public-key": pass("Key Type");
        break;
    case "undefined": warn("Key Type 'undefined' - Firefox or Yubikey issue?");
        break;
    default: fail("Unknown Key Type: " . $_POST['type']);
}

/**
 * §7.2 STEP 2 - 4 : check that the credential is one of those the particular user owns
 */
$publicKey = FALSE;
$previousCounter = -1;
foreach ($state['FIDO2Tokens'] as $oneToken) {
    if ($oneToken[0] == $incomingID) {
        pass("Credential ID is eligible for user " . $state['FIDO2Username'] . ". Using publicKey " . $oneToken[1] . " with current counter value " . $oneToken[2]);
        $publicKey = $oneToken[1];
        $previousCounter = $oneToken[2];
        break;
    }
}
if ($publicKey === FALSE) {
    fail("User attempted to authenticate with an unknown credential ID. This should already have been prevented by the browser!");
}
$authObject = new SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2AuthenticationEvent($state['FIDO2Scope'], $state['FIDO2SignupChallenge'], $state['IdPMetadata']['entityid'], base64_decode($_POST['authenticator_data']), base64_decode($_POST['client_data_raw']), $oneToken[1], base64_decode($_POST['signature']), $debugEnabled);
/**
 * §7.2 STEP 18 : detect physical object cloning on the token
 */
if (($previousCounter != 0 || $counter != 0) && $authObject->counter > $previousCounter) {
    pass("Signature counter was incremented compared to last time (now: $authObject->counter, previous: $previousCounter).");
    $store = $state['fido2SecondFactor:store'];
    $store->updateSignCount($incomingID, $authObject->counter);
} else {
    fail("Signature counter less or equal to a previous authentication! Token cloning likely.");
}
// THAT'S IT. The user authenticated successfully.
$state['FIDO2AuthSuccessful'] = TRUE;
// See if he wants to hang around for token management operations
if (isset($_POST['credentialChange']) && $_POST['credentialChange'] == "on") {
    $state['FIDO2WantsRegister'] = TRUE;
} else {
    $state['FIDO2WantsRegister'] = FALSE;
}
\SimpleSAML\Auth\State::saveState($state, 'fido2SecondFactor:request');

if ($debugEnabled) {
    echo $debugbuffer;
    echo $authObject->debugBuffer;
    echo $validatebuffer;
    echo $authObject->validateBuffer;
    echo "Debug mode, not continuing to ". ($state['FIDO2WantsRegister'] ? "credential registration page." : "destination.");
} else {
    if ($state['FIDO2WantsRegister']) {
        header("Location: ".\SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId=' . urlencode($id)));
    } else {
        \SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
    }
}

