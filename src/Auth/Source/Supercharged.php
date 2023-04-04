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

class Supercharged extends Passwordless
{

    public function __construct(array $info, array $config)
    {
        parent::__construct($info, $config);
    }
    public function authenticate(array &$state): void
    {
        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef;

        StaticProcessHelper::prepareStatePasswordlessAuth($this->stateData, $state);
        StaticProcessHelper::saveStateAndRedirectSupercharged($state);
    }

}
