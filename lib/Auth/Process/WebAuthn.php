<?php

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */

namespace SimpleSAML\Module\webauthn\Auth\Process;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

class WebAuthn extends Auth\ProcessingFilter
{
    /**
     * @var boolean should new users be considered as enabled by default?
     */
    private $defaultEnabled;

    /**
     * @var boolean switch that determines how 'toggle' will be used, if true then value of 'toggle'
     *              will mean whether to trigger (true) or not (false) the webauthn authentication,
     *              if false then $toggle means whether to switch the value of $defaultEnabled and then use that
     */
    private $force;

    /**
     * @var string an attribute which is associated with 'force' because it determines its meaning,
     *              it either simply means whether to trigger webauthn authentication or switch the default settings,
     *              if null (was not sent as attribute) then the information from database is used
     */
    private $toggleAttrib;

    /**
     * @var bool a bool that determines whether to use local database or not
     */
    private $useDatabase;

    /**
     * @var string|null AuthnContextClassRef
     */
    private $authnContextClassRef = null;

    /**
     * An object with all the parameters that will be needed in the process
     *
     * @var Module\webauthn\WebAuthn\StateData
     */
    private $stateData;

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
        parent::__construct($config, $reserved);

        $this->stateData = new Module\webauthn\WebAuthn\StateData();

        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();
        try {
            $this->stateData->store = Store::parseStoreConfig($moduleConfig['store']);
        } catch (\Exception $e) {
            Logger::error(
                'webauthn: Could not create storage: ' .
                $e->getMessage()
            );
        }

        // Set the optional scope if set by configuration
        if (array_key_exists('scope', $moduleConfig)) {
            $this->stateData->scope = $moduleConfig['scope'];
        }

        // Set the derived scope so we can compare it to the sent host at a later point
        $baseurl = Utils\HTTP::getSelfHost();
        $hostname = parse_url($baseurl, PHP_URL_HOST);
        if ($hostname !== null) {
            $this->stateData->derivedScope = $hostname;
        }

        if (array_key_exists('attrib_username', $moduleConfig)) {
            $this->stateData->usernameAttrib = $moduleConfig['attrib_username'];
        } else {
            throw new Error\CriticalConfigurationError('webauthn: it is required to set attrib_username in config.');
        }

        if (array_key_exists('attrib_displayname', $moduleConfig)) {
            $this->stateData->displaynameAttrib = $moduleConfig['attrib_displayname'];
        } else {
            throw new Error\CriticalConfigurationError('webauthn: it is required to set attrib_displayname in config.');
        }

        if (array_key_exists('request_tokenmodel', $moduleConfig)) {
            $this->stateData->requestTokenModel = $moduleConfig['request_tokenmodel'];
        } else {
            $this->stateData->requestTokenModel = false;
        }
        if (array_key_exists('default_enable', $moduleConfig)) {
            $this->defaultEnabled = $moduleConfig['default_enable'];
        } else {
            $this->defaultEnabled = false;
        }

        if (array_key_exists('force', $moduleConfig)) {
            $this->force = $moduleConfig['force'];
        } else {
            $this->force = true;
        }
        if (array_key_exists('attrib_toggle', $moduleConfig)) {
            $this->toggleAttrib = $moduleConfig['attrib_toggle'];
        } else {
            $this->toggleAttrib = 'toggle';
        }
        if (array_key_exists('use_database', $moduleConfig)) {
            $this->useDatabase = $moduleConfig['use_database'];
        } else {
            $this->useDatabase = true;
        }
        if (array_key_exists('authnContextClassRef', $moduleConfig)) {
            $this->authnContextClassRef = $moduleConfig['authnContextClassRef'];
        }
        if (array_key_exists('use_inflow_registration', $moduleConfig)) {
            $this->stateData->useInflowRegistration = $moduleConfig['use_inflow_registration'];
        } else {
            $this->stateData->useInflowRegistration = true;
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
    public function process(&$state): void
    {
        Assert::keyExists($state, 'UserID');
        Assert::keyExists($state, 'Destination');
        Assert::keyExists($state['Destination'], 'entityid');
        Assert::keyExists($state['Destination'], 'metadata-set');
        Assert::keyExists($state['Source'], 'entityid');
        Assert::keyExists($state['Source'], 'metadata-set');

        if (!array_key_exists($this->stateData->usernameAttrib, $state['Attributes'])) {
            Logger::warning('webauthn: cannot determine if user needs second factor, missing attribute "' .
                $this->stateData->usernameAttrib . '".');
            return;
        }

        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef ?? 'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO';
        Logger::debug('webauthn: userid: ' . $state['Attributes'][$this->stateData->usernameAttrib][0]);

        $localToggle = !empty($state['Attributes'][$this->toggleAttrib])
            && !empty($state['Attributes'][$this->toggleAttrib][0]);

        if (
            $this->stateData->store->is2FAEnabled(
                $state['Attributes'][$this->stateData->usernameAttrib][0],
                $this->defaultEnabled,
                $this->useDatabase,
                $localToggle,
                $this->force
            ) === false
        ) {
            // nothing to be done here, end authprocfilter processing
            return;
        }
        StaticProcessHelper::prepareState($this->stateData, $state);
        StaticProcessHelper::saveStateAndRedirect($state);
    }
}
