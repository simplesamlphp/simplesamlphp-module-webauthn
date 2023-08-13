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

    /**
     * The AuthSource to use when someone enters a username/password
     *
     * @var string
     */
    private $pushbackAuthsource;

    public function __construct(array $info, array $config)
    {
        parent::__construct($info, $config);

        $this->pushbackAuthsource = $this->authSourceConfig->getString("password_authsource");
    }

    public function authenticate(array &$state): void
    {
        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef;
        $state['pushbackAuthsource'] = $this->pushbackAuthsource;

        StaticProcessHelper::prepareStatePasswordlessAuth($this->stateData, $state);
        StaticProcessHelper::saveStateAndRedirectSupercharged($state);
    }
}
