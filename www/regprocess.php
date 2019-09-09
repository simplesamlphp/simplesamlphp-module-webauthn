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

$debugbuffer .= "Incoming parameters:<hr/>
Requested operation: " . $_POST['operation'] . "
<hr/>
Responde ID (B64): " . $_POST['response_id'] . "<br/>Response ID (bin2hex): " . bin2hex(base64url_decode($_POST['response_id'])) . "
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
 * STEP 9 of the validation procedure in § 7.1 of the spec: CBOR-decode the attestationObject
 */
$attestationArray = cborDecode(base64_decode($_POST['attestation_object']));
$debugbuffer .= "<pre>";
$debugbuffer .= print_r($attestationArray, true);
$debugbuffer .= "</pre>";
switch ($_POST['type']) {
    case "public-key": pass("Key Type");
        break;
    case "undefined": warn("Key Type 'undefined' - Firefox or Yubikey issue?");
        break;
    default: fail("Unknown Key Type: " . $_POST['type']);
}
$operation = $_POST['operation'];

// if the following function returns, all was good. Otherwise, we are dead.
/** STEP 2-8 and parts of 14 done here */
$clientDataHash = verifyClientDataJSON($state, $_POST['attestation_client_data_json'], $operation);

/**
 * STEP 15 of the validation procedure in § 7.1 of the spec: verify attStmt values
 */
switch ($attestationArray['fmt']) {
    case "none": // § 8.7 of the spec
        /**
         * STEP 16 of the validation procedure in § 7.1 of the spec: stmt must be an empty array
         */
        if (count($attestationArray['attStmt']) == 0) {
            pass("Attestation format and statement as expected.");
        }
        break;
    case "packed":
    case "tpm":
    case "android-key":
    case "android-safetynet":
    case "fido-u2f":
        fail("Attestation format " . $attestationArray['fmt'] . " validation not supported right now.");
        break;
    default:
        fail("Unknown attestation format.");
}
$authData = $attestationArray['authData'];

$counter = validateAuthData($state, $attestationArray['authData'], $operation);

$debugbuffer .= "Signature Counter: 0x" . bin2hex($counterBin) . " / " . $counter . "<br/>";
if ($operation == "REG") {
    // we checked earlier that AT is set, so can extract attestationData from the byte sequence that follows
    $aaguid = substr($authData, 37, 16);
    $credIdLenBytes = substr($authData, 53, 2);
    $credIdLen = intval(bin2hex($credIdLenBytes), 16);
    $credId = substr($authData, 55, $credIdLen);
    $debugbuffer .= "AAGUID (hex) = " . bin2hex($aaguid) . "</br/>";
    $debugbuffer .= "Length Raw = " . bin2hex($credIdLenBytes) . "<br/>";
    $debugbuffer .= "Credential ID Length (decimal) = " . $credIdLen . "<br/>";
    $debugbuffer .= "Credential ID (hex) = " . bin2hex($credId) . "<br/>";
    if (bin2hex(base64url_decode($_POST['response_id'])) == bin2hex($credId)) {
        pass("Credential IDs in authenticator response and in attestation data match.");
    } else {
        fail("Mismatch of credentialId vs. response ID.");
    }
    // so far so good. Now extract the actual public key from its COSE encoding.
    // finding out the number of bytes to CBOR decode appears non-trivial. The simple case is if no ED is present as the CBOR data then goes to the end of the byte sequence
    // since we made sure above that no ED is in the sequence, take the rest of the sequence in its entirety.
    $pubKeyCBOR = substr($authData, 55 + $credIdLen);
    echo $debugbuffer;
    $arrayPK = cborDecode($pubKeyCBOR);
    $debugbuffer .= "pubKey in canonical form: <pre>" . print_r($arrayPK, true) . "</pre>";
    /**
     * STEP 13 of the validation procedure in § 7.1 of the spec: is the algorithm the expected one?
     */
    if ($arrayPK['3'] == -7) { // we requested -7, so want to see it here
        pass("Public Key Algorithm is the expected one (-7, ECDSA).");
    } else {
        fail("Public Key Algorithm mismatch!");
    }
    /**
     * STEP 17 + 18 of the validation procedure in § 7.1 of the spec are a NOOP if the format was "none" (which is acceptable as per this RPs policy)
     */
    if ($attestationArray['fmt'] == 'none') {
        pass("No attestation authorities to retrieve.");
    } else {
        fail("Not implemented, can't go on.");
    }
    // at this point, we need to talk to the DB
    /**
     * STEP 19 of the validation procedure in § 7.1 of the spec: see if this credential is already registered
     */
    $store = $state['fido2SecondFactor:store'];
    if ($store->doesCredentialExist(bin2hex($credId)) === false) {
        pass("Credential does not exist yet in database.");
    } else {
        fail("This credential already exists.");
    }
    // THAT'S IT. This is a valid credential and can be enrolled to the user.
    $store->storeTokenData($state['FIDO2Username'], bin2hex($credId), bin2hex($pubKeyCBOR), $counter, $friendlyName);
    pass("Credential registered.");
    // make sure $state gets the news, the token is to be displayed to the user on the next page
    $state['FIDO2Tokens'][] = [0 => bin2hex($credId), 1 => bin2hex($pubKeyCBOR), 2 => $counter, 3 => $friendlyName];
    $state['FIDO2EnrollmentAllowed'] = false;
    \SimpleSAML\Auth\State::saveState($state, 'fido2SecondFactor:request');
    if ($debugEnabled) {
        echo $debugbuffer;
        echo $validatebuffer;
        echo "<form id='regform' method='POST' action='" . \SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId=' . urlencode($id)) . "'>";
        echo "<button type='submit'>Return to previous page.</button>";
    } else {
        header("Location: ".\SimpleSAML\Module::getModuleURL('fido2SecondFactor/fido2.php?StateId='.urlencode($id)));
    }
}
