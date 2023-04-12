<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Controller;

use DateTime;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Auth\Source;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnAbstractEvent;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnAuthenticationEvent;
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
class AuthProcess
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
     * @return (
     *   \Symfony\Component\HttpFoundation\RedirectResponse|
     *   \SimpleSAML\HTTP\RunnableResponse
     * ) A Symfony Response-object.
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

        $incomingID = bin2hex(WebAuthnAbstractEvent::base64urlDecode($request->request->get('response_id')));

        /**
         * For passwordless auth, extract the userid from the response of the
         * discoverable credential, look up whether the credential used is one
         * that belongs to the claimed username
         *
         * Fail auth if not found, otherwise treat this auth like any other
         * (but check later whether UV was set during auth for the token at hand)
         */
        if ($state['FIDO2PasswordlessAuthMode'] === true) {
            $usernameBuffer = "";
            foreach (str_split(base64_decode($request->request->get('userHandle'))) as $oneChar) {
                $usernameBuffer .= bin2hex($oneChar);
            }
            $store = $state['webauthn:store'];
            $userForToken = $store->getUsernameByHashedId($usernameBuffer);
            if ($userForToken !== "") {
                $tokensForUser = $store->getTokenData($userForToken);
                $state['FIDO2Username'] = $userForToken;
                $state['FIDO2Tokens'] = $tokensForUser;
            } else {
                throw new Exception("Credential ID cannot be associated to any user!");
            }
        }

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
            $request->request->get('type'),
            ($state['FIDO2Scope'] === null ? $state['FIDO2DerivedScope'] : $state['FIDO2Scope']),
            $state['FIDO2SignupChallenge'],
            base64_decode($request->request->get('authenticator_data')),
            base64_decode($request->request->get('client_data_raw')),
            $oneToken[0],
            $oneToken[1],
            (int)$oneToken[4], // algo
            base64_decode($request->request->get('signature')),
            $debugEnabled
        );

        /** Custom check: if the token was initially registered with UV, but now
         * authenticates only UP, we don't allow this downgrade.
         *
         * This is not typically allowed by authenticator implementations anyway
         * (they typically require a full reset of the key to remove UV
         * protections) but to be safe: find out and tell user to re-enroll with
         * the lower security level. (level upgrades are of course OK.)
         */
        if ($oneToken[5] > $authObject->getPresenceLevel()) {
            throw new Exception("Token was initially registered with higher identification guarantees than now authenticated with (was: " . $oneToken[5] . " now " . $authObject->getPresenceLevel() . "!");
        }

        // no matter what: if we are passwordless it MUST be presence-verified
        if ($state['FIDO2PasswordlessAuthMode'] === true && $oneToken[5] != WebAuthnAbstractEvent::PRESENCE_LEVEL_VERIFIED) {
            throw new Exception("Attempt to authenticate without User Verification in passwordless mode!");
        }

        // if we didn't register the key as resident, do not allow its use in
        // passwordless mode
        if ($state['FIDO2PasswordlessAuthMode'] === true && $oneToken[6] != 1) {
            throw new Exception("Attempt to authenticate with a token that is not registered for passwordless mode!");
        }

        /**
         * §7.2 STEP 18 : detect physical object cloning on the token
         */
        $counter = $authObject->getCounter();
        if ($previousCounter == 0 && $counter == 0) {
            // no cloning check, it is a brand new token
        } elseif ($counter > $previousCounter) {
            // Signature counter was incremented compared to last time, good
            $store = $state['webauthn:store'];
            $store->updateSignCount($oneToken[0], $counter);
        } else {
            throw new Exception(
                "Signature counter less or equal to a previous authentication! Token cloning likely (old: $previousCounter, new: $counter)."
            );
        }

        // THAT'S IT. The user authenticated successfully. Remember the credential ID that was used.
        $state['FIDO2AuthSuccessful'] = $oneToken[0];

        // See if he wants to hang around for token management operations
        if ($request->request->get('credentialChange') === 'on') {
            $state['FIDO2WantsRegister'] = true;
        } else {
            $state['FIDO2WantsRegister'] = false;
        }

        $this->authState::saveState($state, 'webauthn:request');

        if ($debugEnabled) {
            $response = new RunnableResponse(
                function (WebAuthnAuthenticationEvent $authObject, array $state) {
                    echo $authObject->getDebugBuffer();
                    echo $authObject->getValidateBuffer();
                    echo "Debug mode, not continuing to " . ($state['FIDO2WantsRegister'] ? "credential registration page." : "destination.");
                },
                [$authObject, $state]
            );
        } else {
            if ($state['FIDO2WantsRegister']) {
                $response = new RedirectResponse(
                    Module::getModuleURL('webauthn/webauthn?StateId=' . urlencode($stateId))
                );
            } else {
                $response = new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
            }
        }

        if ($state['FIDO2PasswordlessAuthMode'] == true) {
            /**
             * But what about SAML attributes? As an authproc, those came in by the
             * first-factor authentication.
             * In passwordless, we're on our own. The one thing we know is the
             * username.
             */
            $state['Attributes'][$state['FIDO2AttributeStoringUsername']] = [ $state['FIDO2Username'] ];
            // in case this authentication happened in the Supercharged context
            // it may be that there is an authprocfilter for WebAuthN, too.
            
            // If so, remove it from $state as it is stupid to touch the token
            // twice; once in the Passwordless auth source and once as an
            // authprocfilter
            
            foreach ($state['IdPMetadata']['authproc'] as $index => $content) {
                if ($content['class'] == "webauthn:WebAuthn") {
                    unset( $state['IdPMetadata']['authproc'][$index] );
                }
            }
            
            // now properly return our final state to the framework
            Source::completeAuth($state);
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
//        throw new Exception("state is: ".print_r($state, true));
        return $response;
    }
}
