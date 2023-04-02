<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\WebAuthn;

use SimpleSAML\Auth;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Utils;

class StaticProcessHelper
{
    public static function saveStateAndRedirect(array &$state): void
    {
        $id = Auth\State::saveState($state, 'webauthn:request');
        $url = Module::getModuleURL('webauthn/webauthn');
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, ['StateId' => $id]);
    }

    public static function prepareState(StateData $stateData, array &$state): void
    {
        $state['requestTokenModel'] = $stateData->requestTokenModel;
        $state['webauthn:store'] = $stateData->store;
        $state['FIDO2Tokens'] = $stateData->store->getTokenData($state['Attributes'][$stateData->usernameAttrib][0]);
        $state['FIDO2Scope'] = $stateData->scope;
        $state['FIDO2DerivedScope'] = $stateData->derivedScope;
        $state['FIDO2AttributeStoringUsername'] = $stateData->usernameAttrib;
        $state['FIDO2Username'] = $state['Attributes'][$stateData->usernameAttrib][0];
        $state['FIDO2Displayname'] = $state['Attributes'][$stateData->displaynameAttrib][0];
        $state['FIDO2SignupChallenge'] = hash('sha512', random_bytes(64));
        $state['FIDO2WantsRegister'] = false;
        $state['FIDO2AuthSuccessful'] = false;
        $state['FIDO2PasswordlessAuthMode'] = false;
    }

    public static function prepareStatePasswordlessAuth(StateData $stateData, array &$state): void
    {
        $state['requestTokenModel'] = $stateData->requestTokenModel;
        $state['webauthn:store'] = $stateData->store;
        $state['FIDO2Scope'] = $stateData->scope;
        $state['FIDO2DerivedScope'] = $stateData->derivedScope;
        $state['FIDO2AttributeStoringUsername'] = $stateData->usernameAttrib;
        $state['FIDO2SignupChallenge'] = hash('sha512', random_bytes(64));
        $state['FIDO2PasswordlessAuthMode'] = true;
        $state['FIDO2AuthSuccessful'] = false;
        $state['FIDO2Tokens'] = []; // we don't know which token comes in.
        $state['FIDO2Username'] = 'notauthenticated';
        $state['FIDO2Displayname'] = 'User Not Authenticated Yet';
        $state['FIDO2WantsRegister'] = false;
    }
}
