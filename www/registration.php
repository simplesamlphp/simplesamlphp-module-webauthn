<?php

/**
 * construct relevant page variables for FIDO registration, authentication and
 * token management
 *
 * @package SimpleSAMLphp
 */

use SimpleSAML\Auth;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Error as SspError;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Webmozart\Assert\Assert;



$globalConfig = Configuration::getInstance();

$config = Configuration::getOptionalConfig("module_webauthn.php")->toArray();
assert(is_array($config));
$uidAttribute = $config["attrib_username"]; // druhý argument je default
$as = new Simple("default-sp");

$as->requireAuth();
$attrs = $as->getAttributes();
$attrs['uid'] = $attrs['urn:oid:0.9.2342.19200300.100.1.1'];
$attrs['displayName'] = $attrs['urn:oid:2.16.840.1.113730.3.1.241'];
$attrs['eduPersonAffiliation'] = $attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.1'];
$attrs['toggle'] = $attrs['urn:oid:0.9.2342.19200300.100.1.1'];

$state["Attributes"] = $attrs;
$uId = $attrs[$uidAttribute];

$metadataHandler = MetaDataStorageHandler::getMetadataHandler();
$metadata = $metadataHandler->getMetaDataCurrent("saml20-idp-hosted");

$state['Source'] = $metadata;
$state['IdPMetadata'] = $metadata;

$store = Store::parseStoreConfig($config['store']); // exception

$state['requestTokenModel'] = $config['request_tokenmodel'];
$state['webauthn:store'] = $store;
$state['FIDO2Tokens'] = $store->getTokenData($attrs[$config["attrib_username"]][0]);


$state['FIDO2Scope'] = $config['scope'];

// Set the derived scope so we can compare it to the sent host at a later point
$baseurl = Utils\HTTP::getSelfHost();
$hostname = parse_url($baseurl, PHP_URL_HOST);
$derivedScope = null;
if ($hostname !== null) {
    $derivedScope = $hostname;
}

$state['FIDO2DerivedScope'] = $derivedScope;

$usernameAttrib = $config['attrib_username'];


$state['FIDO2Username'] = $attrs[$usernameAttrib][0];

$displaynameAttrib = $config['attrib_displayname'];
$state['FIDO2Displayname'] = $attrs[$displaynameAttrib][0];

$state['FIDO2SignupChallenge'] = hash('sha512', random_bytes(64));
$state['FIDO2WantsRegister'] = true;
$state['FIDO2AuthSuccessful'] = $state['FIDO2Tokens'][0][0];
$state['UseInflowRegistration'] = true;
$state['Registration'] = true;

//$state['returnUrl'] = Module::getModuleURL('webauthn/webauthn.php?StateId='.$id);
// Save state and redirect
$id = Auth\State::saveState($state, 'webauthn:request');
$url = Module::getModuleURL('webauthn/webauthn.php');
Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);

