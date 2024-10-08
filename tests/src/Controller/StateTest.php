<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\webauthn\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\Controller;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "webauthn" module.
 *
 * @package SimpleSAML\Test
 */
class StateTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Logger */
    protected Logger $logger;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['webauthn' => true],
                'secretsalt' => 'abc123',
                'enable.saml20-idp' => true,
            ],
            '[ARRAY]',
            'simplesaml',
        );

        $this->session = Session::getSessionFromRequest();

        $this->logger = new class () extends Logger {
            public static function info(string $string): void
            {
                // do nothing
            }
        };
    }


    /**
     * @param string $method The method to be used for the test
     * @param string $controllerEndpoint The name of the endpoint of the controller to test
     * @param string $controllerClass The name of the controller class to test
     * @param string $controllerMethod The name of the controller method to test
     */
    #[DataProvider('stateTestsProvider')]
    public function testMissingState(
        string $method,
        string $controllerEndpoint,
        string $controllerClass,
        string $controllerMethod,
    ): void {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/' . $controllerEndpoint;
        $request = Request::create(
            '/' . $controllerEndpoint,
            $method,
        );

        $c = new $controllerClass($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing required StateId query parameter.');

        call_user_func([$c, $controllerMethod], $request);
    }


    /**
     * @param string $method The method to be used for the test
     * @param string $controllerEndpoint The name of the endpoint of the controller to test
     * @param string $controllerClass The name of the controller class to test
     * @param string $controllerMethod The name of the controller method to test
     */
    #[DataProvider('stateTestsProvider')]
    public function testNoState(
        string $method,
        string $controllerEndpoint,
        string $controllerClass,
        string $controllerMethod,
    ): void {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/' . $controllerEndpoint;
        $request = Request::create(
            '/' . $controllerEndpoint . '?StateId=someStateId',
            $method,
            [],
        );

        $c = new $controllerClass($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        call_user_func([$c, $controllerMethod], $request);
    }


    /**
     * @return array
     */
    public static function stateTestsProvider(): array
    {
        return [
            ['POST', 'authprocess', Controller\AuthProcess::class, 'main'],
            ['POST', 'managetoken', Controller\ManageToken::class, 'main'],
            ['POST', 'regprocess', Controller\RegProcess::class, 'main'],
            ['POST', 'webauthn', Controller\WebAuthn::class, 'main'],
        ];
    }
}
