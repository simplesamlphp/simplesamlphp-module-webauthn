<?php

namespace SimpleSAML\Module\webauthn\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the webauthn module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\webauthn
 */
class WebAuthn
{
    /** @var \SimpleSAML\Configuration */
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;

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
     * @return \SimpleSAML\XHTML\Template  A Symfony Response-object.
     */
    public function main(Request $request): Template
    {
        $this->logger::info('FIDO2 - Accessing WebAuthn interface');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        /** @var array $state */
        $state = $this->authState::loadState($stateId, 'webauthn:request');

        $templateFile = $state['UseInflowRegistration'] ? 'webauthn:webauthn.twig' : 'webauthn:authentication.twig';

        // Make, populate and layout consent form
        $t = new Template($this->config, $templateFile);
        $t->data['UserID'] = $state['FIDO2Username'];
        $t->data['FIDO2Tokens'] = $state['FIDO2Tokens'];

        $challenge = str_split($state['FIDO2SignupChallenge'], 2);
        $entityid = $state['Source']['entityid'];
        $username = str_split(
            hash('sha512', $state['FIDO2Username'] . '|' . Utils\Config::getSecretSalt() . '|' . $entityid),
            2
        );

        $challengeEncoded = [];
        foreach ($challenge as $oneChar) {
            $challengeEncoded[] = hexdec($oneChar);
        }

        $credentialIdEncoded = [];
        foreach ($state['FIDO2Tokens'] as $number => $token) {
            $idSplit = str_split($token[0], 2);
            $credentialIdEncoded[$number] = [];
            foreach ($idSplit as $credIdBlock) {
                $credentialIdEncoded[$number][] = hexdec($credIdBlock);
            }
        }

        $usernameEncoded = [];
        foreach ($username as $oneChar) {
            $usernameEncoded[] = hexdec($oneChar);
        }

        $frontendData = [];
        $frontendData['challengeEncoded'] = $challengeEncoded;
        $frontendData['state'] = [];
        foreach (['Source', 'FIDO2Scope','FIDO2Username','FIDO2Displayname','requestTokenModel'] as $stateItem) {
            $frontendData['state'][$stateItem] = $state[$stateItem];
        }

        $t->data['showExitButton'] = !array_key_exists('Registration', $state);
        $frontendData['usernameEncoded'] = $usernameEncoded;
        $frontendData['attestation'] = $state['requestTokenModel'] ? "indirect" : "none";
        $frontendData['credentialIdEncoded'] = $credentialIdEncoded;
        $t->data['frontendData'] = json_encode($frontendData);

        $t->data['FIDO2AuthSuccessful'] = $state['FIDO2AuthSuccessful'];
        if (
            count($state['FIDO2Tokens']) === 0 ||
            ($state['FIDO2WantsRegister'] === true && $state['FIDO2AuthSuccessful'] !== false)
        ) {
            $t->data['regURL'] = Module::getModuleURL('webauthn/regprocess.php?StateId=' . urlencode($stateId));
            $t->data['delURL'] = Module::getModuleURL('webauthn/managetoken.php?StateId=' . urlencode($stateId));
        }

        $t->data['authForm'] = "";
        if (
            count($state['FIDO2Tokens']) > 0 &&
            ($state['FIDO2WantsRegister'] !== true || $state['FIDO2AuthSuccessful'] === false)
        ) {
            $t->data['authURL'] = Module::getModuleURL('webauthn/authprocess.php?StateId=' . urlencode($stateId));
        }

        // dynamically generate the JS code needed for token registration
        return $t;
    }
}
