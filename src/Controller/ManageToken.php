<?php

namespace SimpleSAML\Module\webauthn\Controller;

use DateTime;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\webauthn\WebAuthn\StaticProcessHelper;
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
class ManageToken
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
     * @return \SimpleSAML\HTTP\RunnableResponse  A Symfony Response-object.
     */
    public function main(Request $request): RunnableResponse
    {
        $this->logger::info('FIDO2 - Accessing WebAuthn token management');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $state = $this->authState::loadState($stateId, 'webauthn:request');

        $ourState = WebAuthn::workflowStateMachine($state);
        if ($ourState !== WebAuthn::STATE_MGMT) {
            throw new Exception("Attempt to access the token management page unauthenticated.");
        }

        switch ($request->request->get('submit')) {
            case "NEVERMIND":
                $response = new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
                break;
            case "DELETE":
                $credId = $request->request->get('credId');
                if ($state['FIDO2AuthSuccessful'] == $credId) {
                    throw new Exception("Attempt to delete the currently used credential despite UI preventing this.");
                }

                $store = $state['webauthn:store'];
                $store->deleteTokenData($credId);

                if (array_key_exists('Registration', $state)) {
                    foreach ($state['FIDO2Tokens'] as $key => $value) {
                        if ($state['FIDO2Tokens'][$key][0] == $credId) {
                            unset($state['FIDO2Tokens'][$key]);
                            break;
                        }
                    }

                    $response = new RunnableResponse([StaticProcessHelper::class, 'saveStateAndRedirect'], [&$state]);
                } else {
                    $response = new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
                }
                break;
            default:
                throw new Exception("Unknown submit button state.");
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
