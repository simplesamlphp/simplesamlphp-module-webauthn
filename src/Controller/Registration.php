<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Controller;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module\webauthn\Store;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnRegistrationEvent;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the webauthn module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\webauthn
 */
class Registration
{
    /** @var \SimpleSAML\Auth\State|string */
    protected $authState = Auth\State::class;

    /** @var \SimpleSAML\Auth\Simple|string */
    protected $authSimple = Auth\Simple::class;

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
     * Inject the \SimpleSAML\Auth\Simple dependency.
     *
     * @param \SimpleSAML\Auth\Simple $authSimple
     */
    public function setAuthSimple(Auth\Simple $authSimple): void
    {
        $this->authSimple = $authSimple;
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


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\HTTP\RunnableResponse  A Symfony Response-object.
     */
    public function main(/** @scrutinizer ignore-unused */ Request $request): RunnableResponse
    {
        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php');
        $registrationConfig = $moduleConfig->getArray('registration');
        $registrationAuthSource = $registrationConfig['auth_source'] ?? 'default-sp';

        $state = [];
        $state['SPMetadata']['entityid'] = "WEBAUTHN-SP-REGISTRATION";

        $authSimple = $this->authSimple;
        $as = new $authSimple($registrationAuthSource);
        $as->requireAuth();
        $attrs = $as->getAttributes();

        $state['Attributes'] = $attrs;

        $stateData = new StateData();
        // phpcs:disable Generic.Files.LineLength.TooLong
        $stateData->requestTokenModel = ($registrationConfig['policy_2fa']['minimum_certification_level'] == WebAuthnRegistrationEvent::CERTIFICATION_NOT_REQUIRED ? false : true);
        $stateData->minCertLevel2FA = $registrationConfig['policy_2fa']['minimum_certification_level'];
        $stateData->aaguidWhitelist2FA = $registrationConfig['policy_2fa']['aaguid_whitelist'] ?? [];
        $stateData->attFmtWhitelist2FA = $registrationConfig['policy_2fa']['attestation_format_whitelist'] ?? [];
        $stateData->minCertLevelPasswordless = $registrationConfig['policy_passwordless']['minimum_certification_level'];
        $stateData->aaguidWhitelistPasswordless = $registrationConfig['policy_passwordless']['aaguid_whitelist'] ?? [];
        $stateData->attFmtWhitelistPasswordless = $registrationConfig['policy_passwordless']['attestation_format_whitelist'] ?? [];
        // phpcs:enable Generic.Files.LineLength.TooLong

        try {
            $stateData->store = Store::parseStoreConfig($moduleConfig->getArray('store'));
        } catch (Exception $e) {
            $this->logger::error(
                'webauthn: Could not create storage: ' . $e->getMessage(),
            );
        }

        $stateData->scope = $moduleConfig->getOptionalString('scope', null);
        $httpUtils = new Utils\HTTP();
        $baseurl = $httpUtils->getSelfHost();
        $hostname = parse_url($baseurl, PHP_URL_HOST);
        if ($hostname !== null) {
            $stateData->derivedScope = $hostname;
        }
        $stateData->usernameAttrib = $moduleConfig->getString('identifyingAttribute');
        $stateData->displaynameAttrib = $moduleConfig->getString('attrib_displayname');

        StaticProcessHelper::prepareState($stateData, $state);

        $metadataHandler = MetaDataStorageHandler::getMetadataHandler();
        $metadata = $metadataHandler->getMetaDataCurrent('saml20-idp-hosted');
        $state['Source'] = $metadata;
        $state['IdPMetadata'] = $metadata;
        // inflow users are not allowed to enter the Registration page. If they
        // did, kill the session
        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php')->toArray();

        if ($moduleConfig['registration']['use_inflow_registration']) {
            throw new Exception("Attempt to access the stand-alone registration page in inflow mode!");
        }

        $state['Registration'] = true;
        $state['FIDO2WantsRegister'] = true;
        if (isset($state['Attributes']['FIDO2AuthSuccessful']) && is_array($state['Attributes']['FIDO2AuthSuccessful']) && count($state['Attributes']['FIDO2AuthSuccessful']) > 0) {
            $state['FIDO2AuthSuccessful'] = $state['Attributes']['FIDO2AuthSuccessful'][0];
        }
        
        return new RunnableResponse([StaticProcessHelper::class, 'saveStateAndRedirect'], [&$state]);
    }
}
