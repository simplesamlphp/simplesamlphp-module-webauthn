<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\WebAuthn;

use SimpleSAML\Module\webauthn\Store;

class StateData
{
    /**
     * backend storage configuration. Required.
     *
     * @var \SimpleSAML\Module\webauthn\Store
     */
    public Store $store;

    /**
     * Scope of the FIDO2 attestation. Can only be in the own domain.
     */
    public ?string $scope = null;

    /**
     * The scope derived from the SimpleSAMLphp configuration;
     * can be null due to misconfiguration, in case we cannot warn the administrator on a mismatching scope
     */
    public ?string $derivedScope = null;

    /**
     * attribute to use as username for the FIDO2 attestation.
     */
    public string $usernameAttrib;

    /**
     * attribute to use as display name for the FIDO2 attestation.
     */
    public string $displaynameAttrib;

    public bool $requestTokenModel;

    public string $minCertLevel2FA;

    public array $aaguidWhitelist2FA;

    public array $attFmtWhitelist2FA;

    public string $minCertLevelPasswordless;

    public array $aaguidWhitelistPasswordless;

    public array $attFmtWhitelistPasswordless;

    /**
     * @var bool an attribute which determines whether you will be able to register and manage tokens
     *           while authenticating or you want to use the standalone registration page for these
     *           purposes. If set to false => standalone registration page, if true => inflow registration.
     *           Defaults to true.
     */
    public bool $useInflowRegistration;
}
