<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\Controller;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Auth\Source;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\Auth\Source\AuthSourceOverloader;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller class for the webauthn module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\webauthn
 */
class PushbackUserPass
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
        Session $session,
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
        $this->logger::info('FIDO2 Supercharged - Redirecting to username/password validation');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $state = $this->authState::loadState($stateId, 'webauthn:request');

        $authsources = Configuration::getConfig('authsources.php')->toArray();
        $authsourceString = $state['pushbackAuthsource'];
        $classname = get_class(Source::getById($authsourceString));
        class_alias($classname, '\SimpleSAML\Module\webauthn\Auth\Source\AuthSourceOverloader');
        $overrideSource = new class (
            ['AuthId' => $authsourceString],
            $authsources[$authsourceString],
        ) extends AuthSourceOverloader
        {
            public function loginOverload(string $username, string $password): array
            {
                return $this->login($username, $password);
            }
        };

        $attribs = $overrideSource->loginOverload($request->request->get("username"), $request->request->get("password"));

        // this is the confirmed username, we store it just like the Passwordless
        // one would have been
        $state['Attributes'][$state['FIDO2AttributeStoringUsername']] = [ $request->request->get("username") ];

        // we deliberately do not store any additional attributes - these have
        // to be retrieved from the same authproc that would retrieve them
        // in Passwordless mode
        unset($attribs);

        // now properly return our final state to the framework
        Source::completeAuth($state);
    }

    public function login(string $username, string $password): array
    {
        throw new Exception("Ugh ($username, $password).");
    }
}
