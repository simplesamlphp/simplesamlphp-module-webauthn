<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\webauthn\Controller;

use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\Controller;
use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "webauthn" module.
 *
 * @package SimpleSAML\Test
 */
class AuthProcessTest extends TestCase
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
     */
    public function testAuthProcessWithoutProperTokenRaisesException(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/authprocess?StateId=someStateId';
        $request = Request::create(
            '/authprocess?StateId=someStateId',
            'POST',
            ['response_id' => 'abc123'],
        );


        $c = new Controller\AuthProcess($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2Displayname' => 'Donald Duck',
                    'FIDO2Username' => 'dduck',
                    'FIDO2Scope' => 'Ducktown',
                    'FIDO2Tokens' => [],
                    'FIDO2SignupChallenge' => 'abc123',
                    'FIDO2AuthSuccessful' => true,
                    'FIDO2PasswordlessAuthMode' => false,
                    'requestTokenModel' => 'something',
                ];
            }
        });

        $this->expectException(Exception::class);
        $this->expectExceptionMessage(
            "User attempted to authenticate with an unknown credential ID. This"
            . " should already have been prevented by the browser!",
        );
        $c->main($request);
    }
}
