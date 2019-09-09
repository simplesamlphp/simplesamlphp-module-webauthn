<?php
/**
 * Consent script
 *
 * This script displays a page to the user, which requests that the user
 * authorizes the release of attributes.
 *
 * @package SimpleSAMLphp
 *
 * Explicit instruct consent page to send no-cache header to browsers to make
 * sure the users attribute information are not store on client disk.
 *
 * In an vanilla apache-php installation is the php variables set to:
 *
 * session.cache_limiter = nocache
 *
 * so this is just to make sure.
 */
session_cache_limiter('nocache');

$globalConfig = \SimpleSAML\Configuration::getInstance();

\SimpleSAML\Logger::info('FIDO2 - Accessing WebAuthn interface');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new \SimpleSAML\Error\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];
$state = \SimpleSAML\Auth\State::loadState($id, 'fido2SecondFactor:request');

if (array_key_exists('core:SP', $state)) {
    $spentityid = $state['core:SP'];
} elseif (array_key_exists('saml:sp:State', $state)) {
    $spentityid = $state['saml:sp:State']['core:SP'];
} else {
    $spentityid = 'UNKNOWN';
}

// Parse parameters
if (array_key_exists('name', $state['Source'])) {
    $srcName = $state['Source']['name'];
} elseif (array_key_exists('OrganizationDisplayName', $state['Source'])) {
    $srcName = $state['Source']['OrganizationDisplayName'];
} else {
    $srcName = $state['Source']['entityid'];
}

if (array_key_exists('name', $state['Destination'])) {
    $dstName = $state['Destination']['name'];
} elseif (array_key_exists('OrganizationDisplayName', $state['Destination'])) {
    $dstName = $state['Destination']['OrganizationDisplayName'];
} else {
    $dstName = $state['Destination']['entityid'];
}

// Make, populate and layout consent form
$t = new \SimpleSAML\XHTML\Template($globalConfig, 'fido2SecondFactor:fido2.php');
$translator = $t->getTranslator();
$t->data['srcMetadata'] = $state['Source'];
$t->data['dstMetadata'] = $state['Destination'];
$t->data['yesData'] = ['StateId' => $id];
$t->data['noData'] = ['StateId' => $id];
$t->data['stateId'] = $id;
$t->data['State'] = "<pre>".print_r($state, true)."</pre>";
$t->data['UserID'] = $state['FIDO2Username'];
$t->data['FIDO2Tokens'] = "<table>";
foreach ($state['FIDO2Tokens'] as $oneToken) {
	$t->data['FIDO2Tokens'] .= "<tr><td>".$oneToken[3]."</td><td>$oneToken[0]</td></tr>";
//print_r($oneToken);
}
$t->data['FIDO2Tokens'] .= "</table>";
$t->data['regForm'] = "";
if ($state['FIDO2EnrollmentAllowed'] === true) {
$t->data['regForm'] = "<form id='regform' method='POST' action='".\SimpleSAML\Module::getModuleURL('fido2SecondFactor/regprocess.php?StateId='.urlencode($id))."'>
<input type='hidden' id='resp' name='response_id' value='0'/>
<input type='hidden' id='data' name='attestation_client_data_json' value='nix'/>
<input type='hidden' id='attobj' name='attestation_object' value='mehrnix'/>
<input type='hidden' id='type' name='type' value='something'/>
<input type='hidden' id='operation' name='operation' value='REG'/>
Name for the new token: <input type='text' id='tokenname' name='tokenname' size='40' value='Token registered at ".(new DateTime())->format('Y-m-d')."'/>
<button type='button' onClick=\"navigator.credentials.create(publicKeyCredentialCreationOptions)
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
    });\" onsubmit='false' >Enroll new Token</button>
</form>";
}

$t->data['authForm'] = "";
if (count($state['FIDO2Tokens']) > 0) {
$t->data['authForm'] = "
<form id='authform' method='POST' action='".\SimpleSAML\Module::getModuleURL('fido2SecondFactor/authprocess.php?StateId='.urlencode($id))."'>
<input type='hidden' id='resp' name='response_id' value='0'/>
<input type='hidden' id='data' name='attestation_client_data_json' value='nix'/>
<input type='hidden' id='authdata' name='authenticator_data' value='mehrnix'/>
<input type='hidden' id='sigdata' name='signature' value='evenmorenix'/>
<!-- ignoring <input type='hidden' id='userhandle' name='userhandle' value='someuser'/> -->
<input type='hidden' id='type' name='type' value='something'/>
<input type='hidden' id='operation' name='operation' value='AUTH'/>
<button type='button' onClick=\"navigator.credentials.get(publicKeyCredentialRequestOptions)
    .then((cred) => {
        console.log('NEW CREDENTIAL', cred);
        document.getElementById('resp').value = cred.id;
        var enc = new TextDecoder('utf-8');
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
    });\" onsubmit='false' >Authenticate with existing Token</button>
</form>
";
}

// dynamically generate the JS code needed for token registration

$challenge = str_split($state['FIDO2SignupChallenge'],2);
$username = str_split(hash('sha512', $state['FIDO2Username'].'|'.\SimpleSAML\Utils\Config::getSecretSalt().'|'.$state['Source']['entityid']), 2);

$challengeEncoded = "";
foreach ($challenge as $oneChar) {
   $challengeEncoded .= "0x$oneChar, ";
}

foreach ($state['FIDO2Tokens'] as $number => $token) {
	$idSplit = str_split($token[0],2);
	$credentialIdEncoded[$number] = "";
	foreach ($idSplit as $credIdBlock) {
		$credentialIdEncoded[$number] .= "0x$credIdBlock, ";
	}
}

$usernameEncoded = "";
foreach ($username as $oneChar) {
   $usernameEncoded .= "0x$oneChar, ";
}
$t->data['JSCode'] = "
// the following two functions are taken from https://stackoverflow.com/questions/16363419/how-to-get-binary-string-from-arraybuffer

function BinaryToString(binary) {
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

function ArrayBufferToString(buffer) {
    return BinaryToString(String.fromCharCode.apply(null, Array.prototype.slice.apply(new Uint8Array(buffer))));
}
";

if ($state['FIDO2EnrollmentAllowed'] === true) {
$t->data['JSCode'] .= "
var publicKeyCredentialCreationOptions = {
    publicKey: {
      challenge: new Uint8Array([ ". $challengeEncoded ." ]).buffer, 
      rp: {
          name: '".$state['Source']['entityid']."',
          id: '".$state['FIDO2Scope']."',
      },
      user: {
	  id: new Uint8Array([ ".$usernameEncoded." ]).buffer,
          name: '".$state['FIDO2Username']."',
          displayName: '".$state['FIDO2Displayname']."',
      },
      pubKeyCredParams: [{alg: -7, type: 'public-key'}],
      timeout: 60000,
      attestation: 'none',
  }
};";
}

if (count($state['FIDO2Tokens']) > 0 ) {
$t->data['JSCode'] .= "const publicKeyCredentialRequestOptions = {
    publicKey: {
        challenge: new Uint8Array([ ". $challengeEncoded ." ]).buffer,
	rpId: '".$state['FIDO2Scope']."',
        allowCredentials: [\n";
		foreach( $credentialIdEncoded as $oneId ) {
			 $t->data['JSCode'] .= "{id: new Uint8Array([ ".$oneId."  ]).buffer , type: 'public-key' },\n";
		}
$t->data['JSCode'] .="
        ],
        timeout: 60000,
    }
}
";
}

$srcName = htmlspecialchars(is_array($srcName) ? $translator->t($srcName) : $srcName);
$dstName = htmlspecialchars(is_array($dstName) ? $translator->t($dstName) : $dstName);

$t->data['srcName'] = $srcName;
$t->data['dstName'] = $dstName;

$t->show();

