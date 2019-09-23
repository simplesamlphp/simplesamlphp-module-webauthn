<?php

/**
 * construct relevant page variables for FIDO registration, authentication and
 * token management
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error as SspError;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;;

$globalConfig = Configuration::getInstance();

Logger::info('FIDO2 - Accessing WebAuthn interface');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SspError\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];
$state = Auth\State::loadState($id, 'webauthn:request');

// Make, populate and layout consent form
$t = new Template($globalConfig, 'webauthn:webauthn.php');
$translator = $t->getTranslator();
$t->data['UserID'] = $state['FIDO2Username'];
$t->data['FIDO2Tokens'] = $state['FIDO2Tokens'];

$t->data['JSCode'] = "
// the following two functions are taken from https://stackoverflow.com/questions/16363419/how-to-get-binary-string-from-arraybuffer

function BinaryToString(binary)
{
    var error;

    try {
        return decodeURIComponent(escape(binary));
    } catch (_error) {
        error = _error;
        if (error instanceof URIError) {
            return binary;
        } else {
            throw error;
        }
    }
}

function ArrayBufferToString(buffer)
{
    return BinaryToString(String.fromCharCode.apply(null, Array.prototype.slice.apply(new Uint8Array(buffer))));
}
";

$challenge = str_split($state['FIDO2SignupChallenge'], 2);
$username = str_split(hash('sha512', $state['FIDO2Username'] . '|' . Utils\Config::getSecretSalt() . '|' . $state['Source']['entityid']), 2);

$challengeEncoded = "";
foreach ($challenge as $oneChar) {
    $challengeEncoded .= "0x$oneChar, ";
}

foreach ($state['FIDO2Tokens'] as $number => $token) {
    $idSplit = str_split($token[0], 2);
    $credentialIdEncoded[$number] = "";
    foreach ($idSplit as $credIdBlock) {
        $credentialIdEncoded[$number] .= "0x$credIdBlock, ";
    }
}

$usernameEncoded = "";
foreach ($username as $oneChar) {
    $usernameEncoded .= "0x$oneChar, ";
}

$t->data['FIDO2AuthSuccessful'] = $state['FIDO2AuthSuccessful'];
$t->data['regForm'] = "";
if (count($state['FIDO2Tokens']) == 0 || ($state['FIDO2WantsRegister'] === true && $state['FIDO2AuthSuccessful'] !== false)) {
    $t->data['regURL'] = Module::getModuleURL('webauthn/regprocess.php?StateId=' . urlencode($id));
    $t->data['delURL'] = Module::getModuleURL('webauthn/managetoken.php?StateId=' . urlencode($id));
    $t->data['regForm'] = "navigator.credentials.create(publicKeyCredentialCreationOptions)
    .then((cred) => {
        console.log('NEW CREDENTIAL', cred);
        document.getElementById('resp').value = cred.id;
        var enc = new TextDecoder('utf-8');
        document.getElementById('data').value = enc.decode(cred.response.clientDataJSON);
        document.getElementById('attobj').value = btoa(ArrayBufferToString(cred.response.attestationObject));
        document.getElementById('type').value = cred.response.type;
        document.forms['regform'].submit();
    })
    .then((assertion) => {
        console.log('ASSERTION', assertion);
    })
    .catch((err) => {
        console.log('ERROR', err);
    });";
    $t->data['JSCode'] .= "
var publicKeyCredentialCreationOptions = {
    publicKey: {
      challenge: new Uint8Array([ " . $challengeEncoded . " ]).buffer, 
      rp: {
          name: '" . $state['Source']['entityid'] . "',
          ".is_null($state['FIDO2Scope']) ? '' : ("id: '".$state['FIDO2Scope']."'"). ",
      },
      user: {
	  id: new Uint8Array([ " . $usernameEncoded . " ]).buffer,
          name: '" . $state['FIDO2Username'] . "',
          displayName: '" . $state['FIDO2Displayname'] . "',
      },
      pubKeyCredParams: [{alg: -7, type: 'public-key'}],
      timeout: 60000,
      attestation: '".($state['requestTokenModel'] ? "indirect" : "none") . "',
  }
};";
}

$t->data['authForm'] = "";
if (count($state['FIDO2Tokens']) > 0 && ($state['FIDO2WantsRegister'] !== true || $state['FIDO2AuthSuccessful'] === false)) {
    $t->data['authURL'] = Module::getModuleURL('webauthn/authprocess.php?StateId=' . urlencode($id));
    $t->data['authForm'] = "navigator.credentials.get(publicKeyCredentialRequestOptions)
    .then((cred) => {
        console.log('NEW CREDENTIAL', cred);
        document.getElementById('resp').value = cred.id;
        var enc = new TextDecoder('utf-8');
        document.getElementById('data_raw_b64').value = btoa(ArrayBufferToString(cred.response.clientDataJSON));
        document.getElementById('data').value = enc.decode(cred.response.clientDataJSON);
        document.getElementById('authdata').value = btoa(ArrayBufferToString(cred.response.authenticatorData));
	document.getElementById('sigdata').value = btoa(ArrayBufferToString(cred.response.signature));
        document.getElementById('type').value = cred.response.type;
        document.forms['authform'].submit();
    })
    .then((assertion) => {
        console.log('ASSERTION', assertion);
    })
    .catch((err) => {
        console.log('ERROR', err);
    });";
    $t->data['JSCode'] .= "const publicKeyCredentialRequestOptions = {
    publicKey: {
        challenge: new Uint8Array([ " . $challengeEncoded . " ]).buffer,
	rpId: '" . $state['FIDO2Scope'] . "',
        allowCredentials: [\n";
    foreach ($credentialIdEncoded as $oneId) {
        $t->data['JSCode'] .= "{id: new Uint8Array([ " . $oneId . "  ]).buffer , type: 'public-key' },\n";
    }
    $t->data['JSCode'] .= "
        ],
        timeout: 60000,
    }
}
";
}

// dynamically generate the JS code needed for token registration

$t->show();

