<?php

namespace SimpleSAML\Module\webauthn\Auth\Process;

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Utils;

class WebAuthn extends Auth\ProcessingFilter
{
    /**
     * backend storage configuration. Required.
     *
     * @var \SimpleSAML\Module\webauthn\Store
     */
    private $store;

    /**
     * Scope of the FIDO2 attestation. Can only be in the own domain.
     *
     * @var string
     */
    private $scope;

    /**
     * attribute to use as username for the FIDO2 attestation.
     *
     * @var string
     */
    private $usernameAttrib;

    /**
     * attribute to use as display name for the FIDO2 attestation.
     *
     * @var string
     */
    private $displaynameAttrib;

    /**
     * @var boolean
     */
    private $requestTokenModel;

    /**
     * @var boolean should new users be considered as enabled by default?
     */
    private $defaultEnabled;

    /**
     * Initialize filter.
     *
     * Validates and parses the configuration.
     *
     * @param array $config Configuration information.
     * @param mixed $reserved For future use.
     *
     * @throws \SimpleSAML\Error\Exception if the configuration is not valid.
     */
    public function __construct($config, $reserved)
    {
        assert(is_array($config));
        parent::__construct($config, $reserved);

        try {
            $this->store = Store::parseStoreConfig($config['store']);
        } catch (\Exception $e) {
            Logger::error(
                'webauthn: Could not create storage: '.
                $e->getMessage()
            );
        }

        if (array_key_exists('scope', $config)) {
            $this->scope = $config['scope'];
        } else {
            $baseurl = Utils\HTTP::getSelfHost();
            $hostname = parse_url($baseurl, PHP_URL_HOST);
            if ($hostname === false) {
                throw new Error\CriticalConfigurationError("Unable to derive scope from 'baseurlpath'.");
            }
            $this->scope = $hostname;
        }

        if (array_key_exists('attrib_username', $config)) {
            $this->usernameAttrib = $config['attrib_username'];
        } else {
            Logger::error('webauthn: it is required to set attrib_username in config.');
        }

        if (array_key_exists('attrib_displayname', $config)) {
            $this->displaynameAttrib = $config['attrib_displayname'];
        } else {
            Logger::error('webauthn: it is required to set attrib_displayname in config.');
        }

        if (array_key_exists('request_tokenmodel', $config)) {
            $this->requestTokenModel = $config['request_tokenmodel'];
        } else {
            $this->requestTokenModel = false;
        }
        if (array_key_exists('default_enable', $config)) {
            $this->defaultEnabled = $config['default_enable'];
        } else {
            $this->defaultEnabled = false;
        }
    }

    /**
     * Process a authentication response
     *
     * This function saves the state, and redirects the user to the page where
     * the user can register or authenticate with his token.
     *
     * @param array &$state The state of the response.
     *
     * @return void
     */
    public function process(&$state)
    {
        assert(is_array($state));
        assert(array_key_exists('UserID', $state));
        assert(array_key_exists('Destination', $state));
        assert(array_key_exists('entityid', $state['Destination']));
        assert(array_key_exists('metadata-set', $state['Destination']));
        assert(array_key_exists('entityid', $state['Source']));
        assert(array_key_exists('metadata-set', $state['Source']));

        if (!array_key_exists($this->usernameAttrib, $state['Attributes'])) {
            Logger::warning('webauthn: cannot determine if user needs second factor, missing attribute "'.
                $this->usernameAttrib.'".');
            return;
        }

        $state['requestTokenModel'] = $this->requestTokenModel;
        $state['webauthn:store'] = $this->store;
        Logger::debug('webauthn: userid: ' . $state['Attributes'][$this->usernameAttrib][0]);

        if ($this->store->is2FAEnabled($state['Attributes'][$this->usernameAttrib][0], $this->defaultEnabled) === false) {
            // nothing to be done here, end authprocfilter processing
            return;
        }

        $state['FIDO2Tokens'] = $this->store->getTokenData($state['Attributes'][$this->usernameAttrib][0]);
        $state['FIDO2Scope'] = $this->scope;
        $state['FIDO2Username'] = $state['Attributes'][$this->usernameAttrib][0];
        $state['FIDO2Displayname'] = $state['Attributes'][$this->displaynameAttrib][0];
        $state['FIDO2SignupChallenge'] = hash('sha512', random_bytes(64));
        $state['FIDO2WantsRegister'] = false;
        $state['FIDO2AuthSuccessful'] = false;

        // Save state and redirect
        $id = Auth\State::saveState($state, 'webauthn:request');
        $url = Module::getModuleURL('webauthn/webauthn.php');
        Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }
}
