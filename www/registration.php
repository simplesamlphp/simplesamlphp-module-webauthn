<?php

/**
 * construct relevant page variables for FIDO registration, authentication and
 * token management
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

$config = Configuration::getOptionalConfig('module_webauthn.php')->toArray();
assert(is_array($config));
$as = new Simple('default-sp');
$stateData = new StateData();
$as->requireAuth();
$attrs = $as->getAttributes();

$state['Attributes'] = $attrs;

$stateData->requestTokenModel = $config['request_tokenmodel'];
$stateData->store = Store::parseStoreConfig($config['store']); // exception
$stateData->scope = $config['scope'];
$baseurl = Utils\HTTP::getSelfHost();
$hostname = parse_url($baseurl, PHP_URL_HOST);
if ($hostname !== null) {
    $stateData->derivedScope = $hostname;
}
$stateData->usernameAttrib = $config['attrib_username'];
$stateData->displaynameAttrib = $config['attrib_displayname'];
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
