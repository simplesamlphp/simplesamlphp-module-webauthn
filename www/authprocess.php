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

$incomingID = bin2hex(\SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2AbstractEvent::base64url_decode($_POST['response_id']));

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
    throw new Exception("User attempted to authenticate with an unknown credential ID. This should already have been prevented by the browser!");
}

$authObject = new SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\FIDO2AuthenticationEvent(
        $_POST['type'],
        $state['FIDO2Scope'], 
        $state['FIDO2SignupChallenge'], 
        $state['IdPMetadata']['entityid'], 
        base64_decode($_POST['authenticator_data']), 
        base64_decode($_POST['client_data_raw']), 
        $oneToken[0],
        $oneToken[1], 
        base64_decode($_POST['signature']), 
        $debugEnabled);
/**
 * §7.2 STEP 18 : detect physical object cloning on the token
 */
if (($previousCounter != 0 || $authObject->counter != 0) && $authObject->counter > $previousCounter) {
    // Signature counter was incremented compared to last time, good
    $store = $state['fido2SecondFactor:store'];
    $store->updateSignCount($incomingID, $authObject->counter);
} else {
    throw new Exception("Signature counter less or equal to a previous authentication! Token cloning likely (old: $previousCounter, new: $authObject->counter.");
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
    echo $authObject->debugBuffer;
    echo $authObject->validateBuffer;
    echo "Debug mode, not continuing to ". ($state['FIDO2WantsRegister'] ? "credential registration page." : "destination.");
} else {
    if ($state['FIDO2WantsRegister']) {
        header("Location: ".\SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId=' . urlencode($id)));
    } else {
        \SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
    }
}

