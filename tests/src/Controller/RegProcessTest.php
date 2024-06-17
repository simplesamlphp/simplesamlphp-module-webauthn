<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\webauthn\Controller;

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
class RegProcessTest extends TestCase
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
    public function testRegProcess(): void
    {
        $this->markTestSkipped('Breaks testsuite');

        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/regprocess';
        $request = Request::create(
            '/regprocess',
            'POST',
            [
                'StateId' => 'someStateId',
                'attestation_object' => 'some object',
                'type' => 'public-key',
                'response_id' => 'abc123',
                'attestation_client_data_json' => 'test',
            ],
        );


        $c = new Controller\RegProcess($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthState(new class () extends State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'FIDO2Scope' => 'Ducktown',
                    'FIDO2Tokens' => [0 => 'A1B2C3', 1 => 'D4E5F6'],
                    'FIDO2SignupChallenge' => 'abc123',
                    'FIDO2AuthSuccessful' => true,
                ];
            }
        });

        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
    }
}
