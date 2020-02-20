<?php

/**
 * construct relevant page variables for FIDO registration, authentication and
 * token management
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

$config = Configuration::getOptionalConfig('module_webauthn.php');
$registrationAuthSource = $config->getString('registration_auth_source', 'default-sp');

$as = new Simple($registrationAuthSource);
$stateData = new StateData();
$as->requireAuth();
$attrs = $as->getAttributes();

$state['Attributes'] = $attrs;

$stateData->requestTokenModel = $config->getBoolean('request_tokenmodel', false);
try {
    $stateData->store = Store::parseStoreConfig($config->getArray('store'));
} catch (\Exception $e) {
    Logger::error(
        'webauthn: Could not create storage: ' .
        $e->getMessage()
    );
}
$stateData->scope = $config->getString('scope', null);
$baseurl = Utils\HTTP::getSelfHost();
$hostname = parse_url($baseurl, PHP_URL_HOST);
if ($hostname !== null) {
    $stateData->derivedScope = $hostname;
}
$stateData->usernameAttrib = $config->getString('attrib_username');
$stateData->displaynameAttrib = $config->getString('attrib_displayname');
$stateData->useInflowRegistration = true;

StaticProcessHelper::prepareState($stateData, $state);

$metadataHandler = MetaDataStorageHandler::getMetadataHandler();
$metadata = $metadataHandler->getMetaDataCurrent('saml20-idp-hosted');
$state['Source'] = $metadata;
$state['IdPMetadata'] = $metadata;
$state['Registration'] = true;
$state['FIDO2AuthSuccessful'] = $state['FIDO2Tokens'][0][0];
$state['FIDO2WantsRegister'] = true;

StaticProcessHelper::saveStateAndRedirect($state);
