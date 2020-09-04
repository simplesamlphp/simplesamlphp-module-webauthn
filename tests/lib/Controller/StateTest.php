<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\webauthn\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\Controller;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "webauthn" module.
 *
 * @package SimpleSAML\Test
 */
class StateTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Logger */
    protected $logger;

    /** @var \SimpleSAML\Session */
    protected $session;


    /**
     * Set up for each test.
     * @return void
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
            'simplesaml'
        );

        $this->session = Session::getSessionFromRequest();

        $this->logger = new class () extends Logger {
            public static function info(string $str): void
            {
                // do nothing
            }
        };
    }


    /**
     * @dataProvider stateTestsProvider
     *
     * @param string $method The method to be used for the test
     * @param string $controllerEndpoint The name of the endpoint of the controller to test
     * @param string $controllerClass The name of the controller class to test
     * @psalm-param class-string $controllerClass
     * @param string $controllerMethod The name of the controller method to test
     */
    public function testMissingState(string $method, string $controllerEndpoint, string $controllerClass, string $controllerMethod): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/' . $controllerEndpoint;
        $request = Request::create(
            '/' . $controllerEndpoint,
            $method
        );

        $c = new $controllerClass($this->config, $this->session);
        $c->setLogger($this->logger);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing required StateId query parameter.');

        call_user_func([$c, $controllerMethod], $request);
    }


    /**
     * @dataProvider stateTestsProvider
     *
     * @param string $method The method to be used for the test
     * @param string $controllerEndpoint The name of the endpoint of the controller to test
     * @param string $controllerClass The name of the controller class to test
     * @psalm-param class-string $controllerClass
     * @param string $controllerMethod The name of the controller method to test
     */
    public function testNoState(string $method, string $controllerEndpoint, string $controllerClass, string $controllerMethod): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/' . $controllerEndpoint;
        $request = Request::create(
            '/' . $controllerEndpoint,
            $method,
            ['StateId' => 'someStateId']
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
    public function stateTestsProvider(): array
    {
        return [
            ['POST', 'authprocess', Controller\AuthProcess::class, 'main'],
            ['POST', 'managetoken', Controller\ManageToken::class, 'main'],
            ['POST', 'regprocess', Controller\RegProcess::class, 'main'],
            ['POST', 'webauthn', Controller\WebAuthn::class, 'main'],
        ];
    }
}
