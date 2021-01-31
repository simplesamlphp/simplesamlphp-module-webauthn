<?php

namespace SimpleSAML\Module\webauthn\Controller;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\StateData;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
use SimpleSAML\Module\webauthn\Store;
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
class Registration
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;

    /**
     * @var \SimpleSAML\Auth\Simple|string
     * @psalm-var \SimpleSAML\Auth\Simple|class-string
     */
    protected $authSimple = Auth\Simple::class;

    /**
     * @var \SimpleSAML\Logger|string
     * @psalm-var \SimpleSAML\Logger|class-string
     */
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
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->session = $session;
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
        $registrationAuthSource = $moduleConfig->getString('registration_auth_source', 'default-sp');

        /** @psalm-var class-string $authSimple */
        $authSimple = $this->authSimple;
        $as = new $authSimple($registrationAuthSource);
        $as->requireAuth();
        $attrs = $as->getAttributes();

        $state = [];
        $state['Attributes'] = $attrs;

        $stateData = new StateData();
        $stateData->requestTokenModel = $moduleConfig->getBoolean('request_tokenmodel', false);
        try {
            $stateData->store = Store::parseStoreConfig($moduleConfig->getArray('store'));
        } catch (Exception $e) {
            $this->logger::error(
                'webauthn: Could not create storage: ' . $e->getMessage()
            );
        }

        $stateData->scope = $moduleConfig->getString('scope', null);
        $baseurl = Utils\HTTP::getSelfHost();
        $hostname = parse_url($baseurl, PHP_URL_HOST);
        if ($hostname !== null) {
            $stateData->derivedScope = $hostname;
        }
        $stateData->usernameAttrib = $moduleConfig->getString('attrib_username');
        $stateData->displaynameAttrib = $moduleConfig->getString('attrib_displayname');
        $stateData->useInflowRegistration = true;

        StaticProcessHelper::prepareState($stateData, $state);

        $metadataHandler = MetaDataStorageHandler::getMetadataHandler();
        $metadata = $metadataHandler->getMetaDataCurrent('saml20-idp-hosted');
        $state['Source'] = $metadata;
        $state['IdPMetadata'] = $metadata;
        $state['Registration'] = true;
        $state['FIDO2AuthSuccessful'] = $state['FIDO2Tokens'][0][0] ?? false;
        $state['FIDO2WantsRegister'] = true;

        return new RunnableResponse([StaticProcessHelper::class, 'saveStateAndRedirect'], [&$state]);
    }
}
