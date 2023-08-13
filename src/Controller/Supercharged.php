<?php

declare(strict_types=1);

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
use SimpleSAML\Module\webauthn\Store;

/**
 * Controller class for the webauthn module.
 *
 * This class serves the different views available in the module.
 *
 * @package SimpleSAML\Module\webauthn
 */
class Supercharged extends WebAuthn
{
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
        parent::__construct($config, $session);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template  A Symfony Response-object.
     */
    public function main(Request $request): Template
    {
        $this->logger::info('FIDO2 - Accessing Supercharged interface');

        $stateId = $request->query->get('StateId');
        if ($stateId === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $state = $this->authState::loadState($stateId, 'webauthn:request');

        $templateFile = 'webauthn:supercharged.twig';

        // Make, populate and layout consent form
        $t = new Template($this->config, $templateFile);
        $t->data['UserID'] = $state['FIDO2Username'];
        $t->data['FIDO2Tokens'] = $state['FIDO2Tokens'];

        $challenge = str_split($state['FIDO2SignupChallenge'], 2);
        $configUtils = new Utils\Config();
        $username = str_split(
            hash('sha512', $state['FIDO2Username'] . '|' . $configUtils->getSecretSalt()),
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
        foreach (['FIDO2Scope','FIDO2Username','FIDO2Displayname','requestTokenModel'] as $stateItem) {
            $frontendData['state'][$stateItem] = $state[$stateItem];
        }

        $t->data['showExitButton'] = !array_key_exists('Registration', $state);
        $frontendData['usernameEncoded'] = $usernameEncoded;
        $frontendData['attestation'] = $state['requestTokenModel'] ? "indirect" : "none";
        $frontendData['credentialIdEncoded'] = $credentialIdEncoded;
        $frontendData['FIDO2PasswordlessAuthMode'] = $state['FIDO2PasswordlessAuthMode'];
        $t->data['hasPreviouslyDonePasswordless'] = $_COOKIE['SuccessfullyUsedPasswordlessBefore'] ?? "NO";
        $t->data['frontendData'] = json_encode($frontendData);

        $t->data['authForm'] = "";
        $t->data['authURL'] = Module::getModuleURL('webauthn/authprocess?StateId=' . urlencode($stateId));
        $t->data['pushbackURL'] = Module::getModuleURL('webauthn/pushbackuserpass?StateId=' . urlencode($stateId));

        // dynamically generate the JS code needed for token registration
        return $t;
    }
}
