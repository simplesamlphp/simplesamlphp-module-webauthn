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

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Auth\Process;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Utils;

class WebAuthn extends Auth\ProcessingFilter
{
    /**
     * @var boolean should new users be considered as enabled by default?
     */
    private bool $defaultEnabled;

    /**
     * @var boolean switch that determines how 'toggle' will be used, if true then value of 'toggle'
     *              will mean whether to trigger (true) or not (false) the webauthn authentication,
     *              if false then $toggle means whether to switch the value of $defaultEnabled and then use that
     */
    private bool $force;

    /**
     * @var string an attribute which is associated with 'force' because it determines its meaning,
     *              it either simply means whether to trigger webauthn authentication or switch the default settings,
     *              if null (was not sent as attribute) then the information from database is used
     */
    private string $toggleAttrib;

    /**
     * @var bool a bool that determines whether to use local database or not
     */
    private bool $useDatabase;

    /**
     * @var string|null AuthnContextClassRef
     */
    private ?string $authnContextClassRef = null;

    /**
     * An object with all the parameters that will be needed in the process
     *
     * @var Module\webauthn\WebAuthn\StateData
     */
    private StateData $stateData;

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
    public function __construct(array $config, $reserved)
    {
        /**
         * Remove annotation + assert as soon as this method can be typehinted (SSP 2.0)
         * @psalm-suppress RedundantConditionGivenDocblockType
         */
        parent::__construct($config, $reserved);

        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();

        $initialStateData = new Module\webauthn\WebAuthn\StateData();
        Module\webauthn\Controller\WebAuthn::loadModuleConfig($moduleConfig, $initialStateData);
        $this->stateData = $initialStateData;

        // switched to authsource config for 2.0
        $this->force = $config['force'] ?? true;
        $this->toggleAttrib = $config['attrib_toggle'] ?? 'toggle';
        $this->useDatabase = $config['use_database'] ?? true;
        $this->defaultEnabled = $config['default_enable'] ?? false;
        $this->authnContextClassRef = $config['authncontextclassref'] ?? null;

        if (array_key_exists('use_inflow_registration', $moduleConfig['registration'])) {
            $this->stateData->useInflowRegistration = $moduleConfig['registration']['use_inflow_registration'];
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
    public function process(array &$state): void
    {
        if (!array_key_exists($this->stateData->usernameAttrib, $state['Attributes'])) {
            Logger::warning('webauthn: cannot determine if user needs second factor, missing attribute "' .
                $this->stateData->usernameAttrib . '".');
            return;
        }

        $state['saml:AuthnContextClassRef'] =
            $this->authnContextClassRef ??
            'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO';
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
