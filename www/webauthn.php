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
use SimpleSAML\XHTML\Template;
use Webmozart\Assert\Assert;

$globalConfig = Configuration::getInstance();

Logger::info('FIDO2 - Accessing WebAuthn interface');

if (!array_key_exists('StateId', $_REQUEST)) {
    throw new SspError\BadRequest(
        'Missing required StateId query parameter.'
    );
}

$id = $_REQUEST['StateId'];
/** @var array $state */
$state = Auth\State::loadState($id, 'webauthn:request');

$templateFile = $state['UseInflowRegistration'] ? 'webauthn:webauthn.php' : 'webauthn:authentication.twig';

// Make, populate and layout consent form
$t = new Template($globalConfig, $templateFile);
$translator = $t->getTranslator();
$t->data['UserID'] = $state['FIDO2Username'];
$t->data['FIDO2Tokens'] = $state['FIDO2Tokens'];

$challenge = str_split($state['FIDO2SignupChallenge'], 2);
$username = str_split(
    hash('sha512', $state['FIDO2Username'] . '|' . Utils\Config::getSecretSalt() . '|' . $state['Source']['entityid']),
    2
);

$credentialIdEncoded = [];
$challengeEncoded = [];
foreach ($challenge as $oneChar) {
    $challengeEncoded[] = hexdec($oneChar);
}

$credentialIdEncoded = [];
foreach ($state['FIDO2Tokens'] as $number => $token) {
    $idSplit = str_split($token[0], 2);
    $credentialIdEncoded[$number] = [];
    foreach ($idSplit as $credIdBlock) {
        $credentialIdEncoded[$number][] = hexdec($credIdBlock);
    }
}

$usernameEncoded = [];
foreach ($username as $oneChar) {
    $usernameEncoded[] = hexdec($oneChar);
}

$frontendData = [];
$frontendData['challengeEncoded'] = $challengeEncoded;
$frontendData['state'] = [];
foreach (['Source', 'FIDO2Scope','FIDO2Username','FIDO2Displayname','requestTokenModel'] as $stateItem) {
    $frontendData['state'][$stateItem] = $state[$stateItem];
}

$t->data['showExitButton'] = !array_key_exists('Registration', $state);
$frontendData['usernameEncoded'] = $usernameEncoded;
$frontendData['attestation'] = $state['requestTokenModel'] ? "indirect" : "none";
$frontendData['credentialIdEncoded'] = $credentialIdEncoded;
$t->data['frontendData'] = json_encode($frontendData);

$t->data['FIDO2AuthSuccessful'] = $state['FIDO2AuthSuccessful'];
if (
    count($state['FIDO2Tokens']) == 0 ||
    ($state['FIDO2WantsRegister'] === true && $state['FIDO2AuthSuccessful'] !== false)
) {
    $t->data['regURL'] = Module::getModuleURL('webauthn/regprocess.php?StateId=' . urlencode($id));
    $t->data['delURL'] = Module::getModuleURL('webauthn/managetoken.php?StateId=' . urlencode($id));
}

$t->data['authForm'] = "";
if (
    count($state['FIDO2Tokens']) > 0 &&
    ($state['FIDO2WantsRegister'] !== true || $state['FIDO2AuthSuccessful'] === false)
) {
    $t->data['authURL'] = Module::getModuleURL('webauthn/authprocess.php?StateId=' . urlencode($id));
}

// dynamically generate the JS code needed for token registration

$t->show();
