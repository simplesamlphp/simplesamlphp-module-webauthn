<?php

/**
 * FIDO2 Passwordless authentication source.
 *
 * @package simplesamlphp/simplesamlphp-module-webauthn
 */

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Auth\Source;

use SimpleSAML\Auth\Source;
use SimpleSAML\Configuration;
use SimpleSAML\Module\webauthn\Controller\WebAuthn;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;

class Passwordless extends Source
{
    /**
     * An object with all the parameters that will be needed in the process
     *
     * @var \SimpleSAML\Module\webauthn\WebAuthn\StateData
     */
    protected StateData $stateData;

    /**
     * @var string|null AuthnContextClassRef
     */
    protected ?string $authnContextClassRef = null;

    /**
     * @var Configuration $authSourceConfig
     */
    protected Configuration $authSourceConfig;

    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->authSourceConfig = Configuration::loadFromArray(
            $config,
            'authsources[' . var_export($this->authId, true) . ']',
        );
        $this->authnContextClassRef = $this->authSourceConfig->getOptionalString(
            "authncontextclassref",
            'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO',
        );
        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();

        $initialStateData = new StateData();
        WebAuthn::loadModuleConfig($moduleConfig, $initialStateData);
        $this->stateData = $initialStateData;
    }

    public function authenticate(array &$state): void
    {
        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef;

        StaticProcessHelper::prepareStatePasswordlessAuth($this->stateData, $state);
        StaticProcessHelper::saveStateAndRedirect($state);
    }
}
