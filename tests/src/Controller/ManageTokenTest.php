<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\webauthn\Controller;

use Exception;
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
class ManageTokenTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected $module_config;

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
            'simplesaml'
        );

        $this->module_config = Configuration::loadFromArray(
            [
                'registration' => ['use_inflow_registration' => true],
            ]
        );

        Configuration::setPreLoadedConfig($this->config, 'config.php');
        Configuration::setPreLoadedConfig($this->module_config, 'module_webauthn.php');


        $this->session = Session::getSessionFromRequest();

        $this->logger = new class () extends Logger {
            public static function info(string $string): void
            {
                // do nothing
            }
        };
    }


    /**
     */
    public function testManageTokenWithSubmitNeverMind(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/managetoken';
        $request = Request::create(
            '/managetoken?StateId=someStateId',
            'POST',
            ['submit' => 'NEVERMIND']
        );


        $c = new Controller\ManageToken($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2AuthSuccessful' => true,
                    'FIDO2PasswordlessAuthMode' => false,
                ];
            }
        });

        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
    }


    /**
    public function testManageTokenWithSubmitDelete(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/managetoken';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $request = Request::create(
            '/managetoken?StateId=someStateId',
            'POST',
            ['submit' => 'DELETE']
        );


        $c = new Controller\ManageToken($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2AuthSuccessful' => true,
                ];
            }
        });

        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
    }
     */


    /**
     */
    public function testManageTokenWithoutSubmitThrowsException(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/managetoken';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $request = Request::create(
            '/managetoken?StateId=someStateId',
            'POST',
            ['submit' => 'submit']
        );


        $c = new Controller\ManageToken($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2AuthSuccessful' => true,
                    'FIDO2PasswordlessAuthMode' => false,
                ];
            }
        });

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unknown submit button state.');

        $c->main($request);
    }


    /**
     */
    public function testManageTokenWithoutAuthenticationThrowsException(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/managetoken';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $request = Request::create(
            '/managetoken?StateId=someStateId',
            'POST',
            ['submit' => 'submit']
        );


        $c = new Controller\ManageToken($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2AuthSuccessful' => false,
                    'FIDO2Tokens' => [0 => "foo"],
                    'FIDO2WantsRegister' => false,
                    'UseInflowRegistration' => false,
                    'FIDO2PasswordlessAuthMode' => false,
                ];
            }
        });

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Attempt to access the token management page unauthenticated.');

        $c->main($request);
    }
}
