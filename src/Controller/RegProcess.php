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
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;

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
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|\SimpleSAML\HTTP\RunnableResponse
     *   A Symfony Response-object.
     */
    public function main(Request $request): Response
    {
        $this->logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $moduleConfig = Configuration::getOptionalConfig('module_webauthn.php');
        $debugEnabled = $moduleConfig->getOptionalBoolean('debug', false);

        $state = $this->authState::loadState($stateId, 'webauthn:request');

        // registering a credential is only allowed for new users or after being authenticated
        if (WebAuthn::workflowStateMachine($state) !== WebAuthn::STATE_MGMT) {
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
            base64_decode($request->request->get('attestation_object')),
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

        /*
         * Observed with YubiKey 5: the transaction counter is 0 if the key has NEVER been used, but
         * the first transaction is also transaction #0.
         * i.e. 0 means "before first transaction OR the very first transaction has already taken place"
         *
         * The very first use of a key should not trigger the physical object cloning alert, so a
         * transaction counter == 0 should be allowed for the first authentication of a new key.
         * The best way to do this is to set the current counter value to -1 when registering a key
         * with a transaction counter of 0.
         */
        $currentCounterValue = -1;
        if ($regObject->getCounter() > 0) {
            $currentCounterValue = $regObject->getCounter();
        }

        // did we get any client extensions?
        $isResidentKey = 0;
        if (strlen($request->request->get('clientext')) > 0 && count(json_decode($request->request->get('clientext'), true)) > 0 ) {
            $extensions = json_decode($request->request->get('clientext'), true);
            if ($extensions['credProps']['rk'] === true) {
                $isResidentKey = 1;
            }
        }

        // we also need to store the hased user_id in case we need to retrieve
        // tokens in passwordless mode
        // use identical hashing as in JS generation step
        $configUtils = new Utils\Config();
        $username = hash('sha512', $state['FIDO2Username'] . '|' . $configUtils->getSecretSalt());
       
        $store->storeTokenData(
            $state['FIDO2Username'],
            $regObject->getCredentialId(),
            $regObject->getCredential(),
            $regObject->getAlgo(),
            $regObject->getPresenceLevel(),
            $isResidentKey,
            $currentCounterValue,
            $friendlyName,
            $username,
        );

        // make sure $state gets the news, the token is to be displayed to the user on the next page
        $state['FIDO2Tokens'][] = [
            0 => $regObject->getCredentialId(),
            1 => $regObject->getCredential(),
            2 => $currentCounterValue,
            3 => $friendlyName,
            4 => $regObject->getAlgo(),
            5 => $regObject->getPresenceLevel(),
            6 => $isResidentKey
        ];

        $id = $this->authState::saveState($state, 'webauthn:request');
        if ($debugEnabled === true) {
            $response = new RunnableResponse(
                function (WebAuthnRegistrationEvent $regObject, string $id) {
                    echo $regObject->getDebugBuffer();
                    echo $regObject->getValidateBuffer();
                    echo "<form id='regform' method='POST' action='" .
                        Module::getModuleURL('webauthn/webauthn?StateId=' . urlencode($id)) . "'>";
                    echo "<button type='submit'>Return to previous page.</button>";
                },
                [$regObject, $id]
            );
        } elseif (array_key_exists('Registration', $state)) {
            $response = new RedirectResponse(Module::getModuleURL('webauthn/webauthn?StateId=' . urlencode($id)));
        } else {
            $response = new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
        }

        $response->setExpires(new DateTime('Thu, 19 Nov 1981 08:52:00 GMT'));
        $response->setCache([
            'must_revalidate'  => true,
            'no_cache'         => true,
            'no_store'         => true,
            'no_transform'     => false,
            'public'           => false,
            'private'          => false,
        ]);

        return $response;
    }
}
