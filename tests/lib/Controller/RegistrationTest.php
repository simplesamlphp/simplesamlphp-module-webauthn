<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\webauthn\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
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
class RegistrationTest extends TestCase
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

        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    'attrib_username' => 'uid',
                    'attrib_displayname' => 'displayName',
                    'store' => [
                        'webauthn:Database',
                        'database.dsn' => 'mysql:host=db.example.org;dbname=fido2',
                        'database.username' => 'simplesaml',
                        'database.password' => 'sdfsdf',
                    ],
                ],
                '[ARRAY]',
                'simplesaml'
            ),
            'module_webauthn.php',
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
     * @return void
     */
    public function testRegistration(): void
    {
        $this->markTestSkipped('Breaks testsuite');

        $_SERVER['REQUEST_URI'] = '/module.php/webauthn/registration';
        $request = Request::create(
            '/registration',
            'GET',
            ['StateId' => 'someStateId']
        );


        $c = new Controller\Registration($this->config, $this->session);
        $c->setLogger($this->logger);
        $c->setAuthSimple(new class ('something') extends Auth\Simple {
            public function __construct(string $authSource, Configuration $config = null, Session $session = null)
            {
            }
            public function requireAuth(array $params = []): void
            {
            }
            public function getAttributes(): array
            {
                return ['uid' => ['dduck'], 'displayName' => ['Donald Duck']];
            }
        });

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                ];
            }
        });

        $response = $c->main($request);

        $this->assertTrue($response->isSuccessful());
    }
}
