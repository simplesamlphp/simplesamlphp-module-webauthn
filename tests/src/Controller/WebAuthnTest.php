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
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "webauthn" module.
 *
 * @package SimpleSAML\Test
 */
class WebAuthnTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Logger */
    protected $logger;

    /** @var \SimpleSAML\Session */
    protected $session;


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

        $this->session = Session::getSessionFromRequest();

        $this->logger = new class () extends Logger {
            public static function info(string $str): void
            {
                // do nothing
            }
        };
    }


    /**
     */
    public function testWebAuthn(): void
    {
        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/webauthn';
        $request = Request::create(
            '/webauthn',
            'POST',
            ['StateId' => 'someStateId']
        );


        $c = new Controller\WebAuthn($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2Displayname' => 'Donald Duck',
                    'FIDO2Username' => 'dduck',
                    'FIDO2Scope' => 'Ducktown',
                    'FIDO2Tokens' => [0 => 'A1B2C3', 1 => 'D4E5F6'],
                    'FIDO2SignupChallenge' => 'A1B2C3',
                    'FIDO2WantsRegister' => false,
                    'FIDO2AuthSuccessful' => false,
                    'requestTokenModel' => 'something',
                    'Source' => [
                        'entityid' => 'https://idp.example.com',
                    ],
                ];
            }
        });

        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
    }
}
