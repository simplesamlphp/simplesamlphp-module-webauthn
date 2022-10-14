<?php

/**
 * FIDO2 Passwordless authentication source.
 *
 * @package simplesamlphp/simplesamlphp-module-webauthn
 */
declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Auth\Source;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\Source;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Module\webauthn\Controller\WebAuthn;

class Passwordless extends Source {

    /**
     * An object with all the parameters that will be needed in the process
     *
     * @var Module\webauthn\WebAuthn\StateData
     */
    private StateData $stateData;

    public function __construct(array $info, array $config) {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->ldapConfig = Configuration::loadFromArray(
                        $config,
                        'authsources[' . var_export($this->authId, true) . ']'
        );
        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();

        $initialStateData = new StateData();
        WebAuthn::loadModuleConfig($moduleConfig, $initialStateData);
        $this->stateData = $initialStateData;
    }

    public function authenticate(array &$state): void {
    //    Assert::keyExists($state['Source'], 'metadata-set');

        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef ??
                'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO';

        StaticProcessHelper::prepareStatePasswordlessAuth($this->stateData, $state);
        StaticProcessHelper::saveStateAndRedirect($state);
    }

}
