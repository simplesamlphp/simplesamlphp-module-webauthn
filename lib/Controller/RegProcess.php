<?php

namespace SimpleSAML\Module\webauthn\Controller;

use Datetime;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\AAGUID;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnRegistrationEvent;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Controller class for the webauthn module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\webauthn
 */
class RegProcess
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
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\SimpleSAML\HTTP\RunnableResponse|\Symfony\Component\HttpFoundation\StreamedResponse
     *   A Symfony Response-object.
     */
    public function main(Request $request): Response
    {
//        if (session_status() != PHP_SESSION_ACTIVE) {
//            session_cache_limiter('nocache');
//        }

        $this->logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $debugEnabled = $this->config->getValue('logging.level', Logger::NOTICE) === Logger::DEBUG;

        /** @var array $state */
        $state = $this->authState::loadState($stateId, 'webauthn:request');

        // registering a credential is only allowed for new users or after being authenticated
        if (count($state['FIDO2Tokens']) > 0 && $state['FIDO2AuthSuccessful'] === false) {
            throw new Exception("Attempt to register new token in unacceptable context.");
        }

        $fido2Scope = ($state['FIDO2Scope'] === null ? $state['FIDO2DerivedScope'] : $state['FIDO2Scope']);
        if ($fido2Scope === null) {
            throw new Exception("FIDO2Scope cannot be null!");
        }

        $regObject = new WebAuthnRegistrationEvent(
            $request->request->get('type'),
            $fido2Scope,
            $state['FIDO2SignupChallenge'],
            $state['IdPMetadata']['entityid'],
            base64_decode($_POST['attestation_object']),
            $request->request->get('response_id'),
            $request->request->get('attestation_client_data_json'),
            $debugEnabled
        );

        // at this point, we need to talk to the DB
        /**
         * STEP 19 of the validation procedure in § 7.1 of the spec: see if this credential is already registered
         */
        $store = $state['webauthn:store'];
        if ($store->doesCredentialExist(bin2hex($regObject->getCredentialId())) === false) {
            // credential does not exist yet in database, good.
        } else {
            throw new Exception("The credential with ID " . $regObject->getCredentialId() . " already exists.");
        }

        // THAT'S IT. This is a valid credential and can be enrolled to the user.
        $friendlyName = $request->request->get('tokenname');

        // if we have requested the token model, add it to the name
        if ($state['requestTokenModel']) {
            $model = Translate::noop('unknown model');
            $vendor = Translate::noop('unknown vendor');
            $aaguiddict = AAGUID::getInstance();
            if ($aaguiddict->hasToken($regObject->getAAGUID())) {
                $token = $aaguiddict->get($regObject->getAAGUID());
                $model = $token['model'];
                $vendor = $token['O'];
            }
            $friendlyName .= " ($model [$vendor])";
        }

        /**
         * STEP 20 of the validation procedure in § 7.1 of the spec: store credentialId, credential,
         * signCount and associate with user
         */

        $store->storeTokenData(
            $state['FIDO2Username'],
            $regObject->getCredentialId(),
            $regObject->getCredential(),
            $regObject->getCounter(),
            $friendlyName
        );

        // make sure $state gets the news, the token is to be displayed to the user on the next page
        $state['FIDO2Tokens'][] = [
            0 => $regObject->getCredentialId(),
            1 => $regObject->getCredential(),
            2 => $regObject->getCounter(),
            3 => $friendlyName
        ];

        $id = $this->authState::saveState($state, 'webauthn:request');
        if ($debugEnabled === true) {
            $response = new StreamedResponse();
            $response->setCallback(function ($regObject, $id) {
                echo $regObject->getDebugBuffer();
                echo $regObject->getValidateBuffer();
                echo "<form id='regform' method='POST' action='" .
                    Module::getModuleURL('webauthn/webauthn.php?StateId=' . urlencode($id)) . "'>";
                echo "<button type='submit'>Return to previous page.</button>";
            });
        } elseif (array_key_exists('Registration', $state)) {
            $response = new RedirectResponse(Module::getModuleURL('webauthn/webauthn.php?StateId=' . urlencode($id)));
        } else {
            $response = new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
        }

        $response->setCache([
            'must_revalidate'  => true,
            'no_cache'         => true,
            'no_store'         => true,
            'no_transform'     => false,
            'public'           => false,
            'private'          => false,
        ]);
        $response->setExpires(new DateTime('Thu, 19 Nov 1981 08:52:00 GMT'));

        return $response;
    }
}
