<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the webauthn module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\webauthn
 */
class WebAuthn
{
    public const STATE_AUTH_NOMGMT = 1; // just authenticate user
    public const STATE_AUTH_ALLOWMGMT = 2; // allow to switch to mgmt page
    public const STATE_MGMT = 4; // show token management page

    /** @var \SimpleSAML\Auth\State|string */
    protected $authState = Auth\State::class;

    /** @var \SimpleSAML\Logger|string */
    protected $logger = Logger::class;


    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration              $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session                    $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        protected Configuration $config,
        protected Session $session,
    ) {
    }


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }


    /**
     * Inject the \SimpleSAML\Logger dependency.
     *
     * @param \SimpleSAML\Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }

    public static function workflowStateMachine(array $state)
    {
        // if we don't have any credentials yet, allow user to register
        // regardless if in inflow or standalone (redirect to standalone if need
        // be)
        // OTOH, if we are invoked for passwordless auth, we don't know the
        // username nor whether the user has any credentials. The only thing
        // we can do is authenticate -> final else
        if (
            $state['FIDO2PasswordlessAuthMode'] != true &&
            (!isset($state['FIDO2Tokens']) || count($state['FIDO2Tokens']) == 0)
        ) {
            return self::STATE_MGMT;
        }
        // from here on we do have a credential to work with
        //
        // user indicated he wants to manage tokens. He did so either by
        // visiting the Registration page, or by checking the box during
        // inflow.
        // If coming from inflow, allow management only if user is
        // properly authenticated, otherwise send to auth page
        if ($state['FIDO2WantsRegister']) {
            if ($state['FIDO2AuthSuccessful'] || $state['Registration']) {
                return self::STATE_MGMT;
            }
            return self::STATE_AUTH_ALLOWMGMT;
        } else { // in inflow, allow to check the management box; otherwise,
                 // only auth
            $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();
            return $moduleConfig['registration']['use_inflow_registration'] ?
                self::STATE_AUTH_ALLOWMGMT : self::STATE_AUTH_NOMGMT;
        }
    }

    public static function loadModuleConfig(array $moduleConfig, StateData &$stateData): void
    {
        $stateData->store = Store::parseStoreConfig($moduleConfig['store']);

        // Set the optional scope if set by configuration
        if (array_key_exists('scope', $moduleConfig)) {
            $stateData->scope = $moduleConfig['scope'];
        }

        // Set the derived scope so we can compare it to the sent host at a later point
        $httpUtils = new Utils\HTTP();
        $baseurl = $httpUtils->getSelfHost();
        $hostname = parse_url($baseurl, PHP_URL_HOST);
        if ($hostname !== null) {
            $stateData->derivedScope = $hostname;
        }

        if (array_key_exists('identifyingAttribute', $moduleConfig)) {
            $stateData->usernameAttrib = $moduleConfig['identifyingAttribute'];
        } else {
            throw new Error\CriticalConfigurationError(
                'webauthn: it is required to set identifyingAttribute in config.',
            );
        }

        if (array_key_exists('attrib_displayname', $moduleConfig)) {
            $stateData->displaynameAttrib = $moduleConfig['attrib_displayname'];
        } else {
            throw new Error\CriticalConfigurationError(
                'webauthn: it is required to set attrib_displayname in config.',
            );
        }

        if (array_key_exists('minimum_certification_level', $moduleConfig['registration']['policy_2fa'])) {
            // phpcs:disable Generic.Files.LineLength.TooLong
            $stateData->requestTokenModel = ($moduleConfig['registration']['policy_2fa']['minimum_certification_level'] == Module\webauthn\WebAuthn\WebAuthnRegistrationEvent::CERTIFICATION_NOT_REQUIRED ? false : true);
            $stateData->minCertLevel2FA = $moduleConfig['registration']['policy_2fa']['minimum_certification_level'];
            $stateData->aaguidWhitelist2FA = $moduleConfig['registration']['policy_2fa']['aaguid_whitelist'] ?? [];
            $stateData->attFmtWhitelist2FA = $moduleConfig['registration']['policy_2fa']['attestation_format_whitelist'] ?? [];
            $stateData->minCertLevelPasswordless = $moduleConfig['registration']['policy_passwordless']['minimum_certification_level'];
            $stateData->aaguidWhitelistPasswordless = $moduleConfig['registration']['policy_passwordless']['aaguid_whitelist'] ?? [];
            $stateData->attFmtWhitelistPasswordless = $moduleConfig['registration']['policy_passwordless']['attestation_format_whitelist'] ?? [];
            // phpcs:enable Generic.Files.LineLength.TooLong
        } else {
            $stateData->requestTokenModel = false;
        }
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template  A Symfony Response-object.
     */
    public function main(Request $request): Template
    {
        $this->logger::info('FIDO2 - Accessing WebAuthn interface');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $state = $this->authState::loadState($stateId, 'webauthn:request');

        if ($this->workflowStateMachine($state) != self::STATE_AUTH_NOMGMT) {
            $templateFile = 'webauthn:webauthn.twig';
        } else {
            $templateFile = 'webauthn:authentication.twig';
        }

        // Make, populate and layout consent form
        $t = new Template($this->config, $templateFile);
        $t->data['UserID'] = $state['FIDO2Username'];
        $t->data['FIDO2Tokens'] = $state['FIDO2Tokens'];
        // in case IdPs want to override UI and display SP-specific content
        $t->data['entityid'] = $state['SPMetadata']['entityid'] ?? 'WEBAUTHN-SP-NONE';

        $challenge = str_split($state['FIDO2SignupChallenge'], 2);
        $configUtils = new Utils\Config();
        $username = str_split(
            hash('sha512', $state['FIDO2Username'] . '|' . $configUtils->getSecretSalt()),
            2,
        );

        $challengeEncoded = [];
        foreach ($challenge as $oneChar) {
            $challengeEncoded[] = hexdec($oneChar);
        }

        $credentialIdEncoded = [];
        foreach ($state['FIDO2Tokens'] as $number => $token) {
            $idSplit = str_split($token[0], 2);
            $credentialIdEncoded[$number] = [];
            foreach ($idSplit as $credIdBlock) {
                $credentialIdEncoded[$number][] = hexdec($credIdBlock);
            }
        }

        $usernameEncoded = [];
        foreach ($username as $oneChar) {
            $usernameEncoded[] = hexdec($oneChar);
        }

        $frontendData = [];
        $frontendData['challengeEncoded'] = $challengeEncoded;
        $frontendData['state'] = [];
        foreach (['FIDO2Scope','FIDO2Username','FIDO2Displayname','requestTokenModel'] as $stateItem) {
            $frontendData['state'][$stateItem] = $state[$stateItem];
        }

        $t->data['showExitButton'] = !array_key_exists('Registration', $state);
        $frontendData['usernameEncoded'] = $usernameEncoded;
        $frontendData['attestation'] = $state['requestTokenModel'] ? "indirect" : "none";
        $frontendData['credentialIdEncoded'] = $credentialIdEncoded;
        $frontendData['FIDO2PasswordlessAuthMode'] = $state['FIDO2PasswordlessAuthMode'];
        $t->data['frontendData'] = json_encode($frontendData);

        $t->data['FIDO2AuthSuccessful'] = $state['FIDO2AuthSuccessful'];
        if ($this->workflowStateMachine($state) == self::STATE_MGMT) {
            $t->data['regURL'] = Module::getModuleURL('webauthn/regprocess?StateId=' . urlencode($stateId));
            $t->data['delURL'] = Module::getModuleURL('webauthn/managetoken?StateId=' . urlencode($stateId));
        }

        $t->data['authForm'] = "";
        if (
            $this->workflowStateMachine($state) == self::STATE_AUTH_ALLOWMGMT ||
            $this->workflowStateMachine($state) == self::STATE_AUTH_NOMGMT
        ) {
            $t->data['authURL'] = Module::getModuleURL('webauthn/authprocess?StateId=' . urlencode($stateId));
            $t->data['delURL'] = Module::getModuleURL('webauthn/managetoken?StateId=' . urlencode($stateId));
        }

        // dynamically generate the JS code needed for token registration
        return $t;
    }
}
