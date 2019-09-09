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

$incomingID = bin2hex(base64url_decode($_POST['response_id']));

ob_clean();
ob_start();
$debugbuffer .= "Incoming parameters:<hr/>
Requested operation: ". $_POST['operation']."
<hr/>
Responde ID (B64): ". $_POST['response_id']."<br/>Response ID (bin2hex): ".$incomingID."
<hr/>
Type: ".$_POST['type']."
<hr/>
authData Object (binary byte sequence): "; 
/**
 * 
 */
$authData = base64_decode($_POST['authenticator_data']);
$debugbuffer .= "<pre>";
$debugbuffer .= print_r($authData, true);
$debugbuffer .= "</pre>";
switch ($_POST['type']) {
        case "public-key": pass("Key Type"); break;
        case "undefined": warn("Key Type 'undefined' - Firefox or Yubikey issue?"); break;
        default: fail("Unknown Key Type: ".$_POST['type']);
}
$operation = $_POST['operation'];

// if the following function returns, all was good. Otherwise, we are dead.
/** STEP and  done here */
$clientDataHash = verifyClientDataJSON($state, $_POST['attestation_client_data_json'], $operation);

$counter = validateAuthData($state, $authData, $operation);

$debugbuffer .= "Signature Counter (decimal): ".$counter."<br/>";
if ($operation == "AUTH") {
	/**
	 * §7.2 STEP 2 - 4 : check that the credential is one of those the particular user owns
	 */
	$publicKey = FALSE;
	$previousCounter = -1;
	foreach ($state['FIDO2Tokens'] as $oneToken) {
		if ($oneToken[0] == $incomingID) {
			pass("Credential ID is eligible for user ".$state['FIDO2Username'].". Using publicKey ".$oneToken[1]." with current counter value ".$oneToken[2]);
			$publicKey = $oneToken[1];
			$previousCounter = $oneToken[2];
			break;
		}
	}
	if ($publicKey === FALSE) {
		fail("User attempted to authenticate with an unknown credential ID. This should already have been prevented by the browser!");
	}

	/**
         * §7.2 STEP 16 :calculate SHA-256 hash of clientData
         */
	$cDataHash = hash("sha256", $_POST['attestation_client_data_json']);

        /**
         * §7.2 STEP 17 : NOT IMPLEMENTED - actually check the signature
         */
	$totalContent = $authData . $cDataHash;
	ignore("openssl_verify() with parameters \$totalContent, base64_decode(\$_POST['sig']) and the key I can't currently encode yet. Probably need OPENSSL_ALGO_SHA256.");

	/**
	 * §7.2 STEP 18 : detect physical object cloning on the token
	 */
	if (($previousCounter != 0 || $counter != 0) && $counter > $previousCounter ) {
		pass("Signature counter was incremented compared to last time (now: $counter, previous: $previousCounter).");
		$store = $state['fido2SecondFactor:store'];
	        $store->updateSignCount($incomingID, $counter); 
	} else {
		fail("Signature counter less or equal to a previous authentication! Token cloning likely.");
	}
	// THAT'S IT. The user authenticated successfully.
	if ($debugEnabled) {
		echo $debugbuffer;
		echo $validatebuffer;
		echo "Debug mode, not continuing to destination.";
		ob_flush();
		flush();
	} else {
		\SimpleSAML\Auth\ProcessingChain::resumeProcessing($state);
	}
}
