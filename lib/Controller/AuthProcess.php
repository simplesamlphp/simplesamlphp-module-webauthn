<?php

namespace SimpleSAML\Module\webauthn\Controller;

use Datetime;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnAbstractEvent;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnAuthenticationEvent;
use SimpleSAML\Session;
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
class AuthProcess
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
     * @return (\Symfony\Component\HttpFoundation\RedirectResponse|
     *         \SimpleSAML\HTTP\RunnableResponse|
     *         \Symfony\Component\HttpFoundation\StreamedResponse)  A Symfony Response-object.
     */
    public function main(Request $request): Response
    {
        $this->logger::info('FIDO2 - Accessing WebAuthn enrollment validation');

        $stateId = $request->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $debugEnabled = $this->config->getValue('logging.level', Logger::NOTICE) === Logger::DEBUG;

        /** @var array $state */
        $state = $this->authState::loadState($stateId, 'webauthn:request');

        $incomingID = bin2hex(WebAuthnAbstractEvent::base64urlDecode($request->get('response_id')));

        /**
         * §7.2 STEP 2 - 4 : check that the credential is one of those the particular user owns
         */
        $publicKey = false;
        $previousCounter = -1;

        foreach ($state['FIDO2Tokens'] as $oneToken) {
            if ($oneToken[0] == $incomingID) {
                // Credential ID is eligible for user $state['FIDO2Username'];
                // using publicKey $oneToken[1] with current counter value $oneToken[2]
                $publicKey = $oneToken[1];
                $previousCounter = $oneToken[2];
                break;
            }
        }

        if ($publicKey === false) {
            throw new Exception(
                "User attempted to authenticate with an unknown credential ID. This should already have been prevented by the browser!"
            );
        }

        /** @psalm-var array $oneToken */
        $authObject = new WebAuthnAuthenticationEvent(
            $request->get('type'),
            ($state['FIDO2Scope'] === null ? $state['FIDO2DerivedScope'] : $state['FIDO2Scope']),
            $state['FIDO2SignupChallenge'],
            $state['IdPMetadata']['entityid'],
            base64_decode($request->get('authenticator_data')),
            base64_decode($request->get('client_data_raw')),
            $oneToken[0],
            $oneToken[1],
            base64_decode($request->get('signature')),
            $debugEnabled
        );

        /**
         * §7.2 STEP 18 : detect physical object cloning on the token
         */
        $counter = $authObject->getCounter();
        if (($previousCounter != 0 || $counter != 0) && $counter > $previousCounter) {
            // Signature counter was incremented compared to last time, good
            $store = $state['webauthn:store'];
            $store->updateSignCount($oneToken[0], $counter);
        } else {
            throw new Exception(
                "Signature counter less or equal to a previous authentication! Token cloning likely (old: $previousCounter, new: $counter."
            );
        }

        // THAT'S IT. The user authenticated successfully. Remember the credential ID that was used.
        $state['FIDO2AuthSuccessful'] = $oneToken[0];

        // See if he wants to hang around for token management operations
        if ($request->get('credentialChange') === 'on') {
            $state['FIDO2WantsRegister'] = true;
        } else {
            $state['FIDO2WantsRegister'] = false;
        }

        $this->authState::saveState($state, 'webauthn:request');

        if ($debugEnabled) {
            $response = new StreamedResponse();
            $response->setCallback(function ($authObject, $state) {
                echo $authObject->getDebugBuffer();
                echo $authObject->getValidateBuffer();
                echo "Debug mode, not continuing to " . ($state['FIDO2WantsRegister'] ? "credential registration page." : "destination.");
            });
        } else {
            if ($state['FIDO2WantsRegister']) {
                $response = new RedirectResponse(Module::getModuleURL('webauthn/webauthn?StateId=' . urlencode($stateId)));
            } else {
                $response = new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
            }
        }

        $response->headers->set('Expires', 'Thu, 19 Nov 1981 08:52:00 GMT');
        $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0');
        $response->headers->set('Pragma', 'no-cache');

        /** Symfony 5 style */
        /**
        $response->setCache([
            'must_revalidate'  => true,
            'no_cache'         => true,
            'no_store'         => true,
            'no_transform'     => false,
            'public'           => false,
            'private'          => false,
        ]);
        $response->setExpires(new DateTime('Thu, 19 Nov 1981 08:52:00 GMT'));
        */

        return $response;
    }
}
