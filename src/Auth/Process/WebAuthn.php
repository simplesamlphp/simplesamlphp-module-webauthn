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

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;

class WebAuthn extends Auth\ProcessingFilter {

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
     * Maximum age of second-factor authentication in authproc
     */
    private int $SecondFactorMaxAge;

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
    public function __construct(array $config, $reserved) {
        parent::__construct($config, $reserved);

        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();

        $initialStateData = new Module\webauthn\WebAuthn\StateData();
        Module\webauthn\Controller\WebAuthn::loadModuleConfig($moduleConfig, $initialStateData);
        $this->stateData = $initialStateData;

        $this->force = $config['force'] ?? true;
        $this->toggleAttrib = $config['attrib_toggle'] ?? 'toggle';
        $this->useDatabase = $config['use_database'] ?? true;
        $this->defaultEnabled = $config['default_enable'] ?? false;
        $this->authnContextClassRef = $config['authncontextclassref'] ?? null;
        $this->SecondFactorMaxAge = $config['secondfactormaxage'] ?? -1;

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
    public function process(array &$state): void {
        if (!array_key_exists($this->stateData->usernameAttrib, $state['Attributes'])) {
            Logger::warning('webauthn: cannot determine if user needs second factor, missing attribute "' .
                    $this->stateData->usernameAttrib . '".');
            return;
        }

        $state['saml:AuthnContextClassRef'] = $this->authnContextClassRef ??
                'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO';
        Logger::debug('webauthn: userid: ' . $state['Attributes'][$this->stateData->usernameAttrib][0]);

        $localToggle = !empty($state['Attributes'][$this->toggleAttrib]) && !empty($state['Attributes'][$this->toggleAttrib][0]);

        if (
                $this->stateData->store->is2FAEnabled(
                        $state['Attributes'][$this->stateData->usernameAttrib][0],
                        $this->defaultEnabled,
                        $this->useDatabase,
                        $localToggle,
                        $this->force,
                ) === false
        ) {
            // nothing to be done here, end authprocfilter processing
            return;
        }

        if // did we do Passwordless mode successfully before?
        (
                isset($state['Attributes']['internal:FIDO2PasswordlessAuthentication']) &&
                $state['Attributes']['internal:FIDO2PasswordlessAuthentication'][0] == $state['Attributes'][$this->stateData->usernameAttrib][0]
        ) {
            // then no need to trigger a second 2-Factor via authproc
            // just delete the internal attribute then
            unset($state['Attributes']['internal:FIDO2PasswordlessAuthentication']);
            return;
        }

        if // do we need to do secondFactor in interval, or even every time?
           // we skip only if an interval is configured AND we did successfully authenticate, AND are within the interval
        (
                $this->SecondFactorMaxAge >= 0 && // 
                (
                isset($state['Attributes']['LastSuccessfulSecondFactor']) &&
                $state['Attributes']['LastSuccessfulSecondFactor'] instanceof \DateTime
                )
        ) {
            $interval = \DateTime::diff($state['Attributes']['LastSuccessfulSecondFactor'], \DateTime());
            if ($interval->invert == 1) {
                throw new \Exception("We are talking to a future self. Amazing.");
            }
            $totalAge = $interval->s + 60 * $interval->i + 3600 * $interval->h + 86400 * $interval->d + 86400 * 30 * $interval->m + 86400 * 365 * $interval->y;
            if ($totalAge < $this->SecondFactorMaxAge) { // we are within the interval indeed, skip calling the AuthProc
                return;
            }
        }
        StaticProcessHelper::prepareState($this->stateData, $state);
        StaticProcessHelper::saveStateAndRedirect($state);
    }
}
