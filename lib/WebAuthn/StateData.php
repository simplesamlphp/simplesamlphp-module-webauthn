<?php

namespace SimpleSAML\Module\webauthn\WebAuthn;

class StateData
{
    /**
     * backend storage configuration. Required.
     *
     * @var \SimpleSAML\Module\webauthn\Store
     */
    public $store;

    /**
     * Scope of the FIDO2 attestation. Can only be in the own domain.
     *
     * @var string|null
     */
    public $scope = null;

    /**
     * The scope derived from the SimpleSAMLphp configuration;
     * can be null due to misconfiguration, in case we cannot warn the administrator on a mismatching scope
     *
     * @var string|null
     */
    public $derivedScope = null;

    /**
     * attribute to use as username for the FIDO2 attestation.
     *
     * @var string
     */
    public $usernameAttrib;

    /**
     * attribute to use as display name for the FIDO2 attestation.
     *
     * @var string
     */
    public $displaynameAttrib;

    /**
     * @var boolean
     */
    public $requestTokenModel;

    /**
     * @var bool an attribute which determines whether you will be able to register and manage tokens
     *           while authenticating or you want to use the standalone registration page for these
     *           purposes. If set to false => standalone registration page, if true => inflow registration.
     *           Defaults to true.
     */
    public $useInflowRegistration;
}
