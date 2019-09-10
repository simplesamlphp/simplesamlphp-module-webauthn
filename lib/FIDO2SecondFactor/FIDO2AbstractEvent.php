<?php

namespace SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor;

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */
abstract class FIDO2AbstractEvent {

    /**
     * Scope of the FIDO2 attestation. Can only be in the own domain.
     *
     * @var string
     */
    private $scope;

    /**
     * The SHA256 hash of the clientDataJSON
     */
    protected $clientDataHash;

    /**
     * The challenge that was used to trigger this event
     */
    private $challenge;

    /**
     * Our IdP EntityId
     */
    private $idpEntityId;

    /**
     * the authenticator's signature counter
     */
    public $counter;

    /**
     * extensive debug information collection?
     */
    public $debugMode = false;

    /**
     * A string buffer to hold debug information in case we need it.
     */
    public $debugBuffer = "";

    /**
     * A string buffer to hold raw validation data in case we want to look at it.
     */
    public $validateBuffer = "";

    /**
     * the type of event requested. This is to be set in child class constructors
     * before calling the parent's.
     */
    protected $eventType;

    /**
     * the credential ID for this event (either the one that gets registered, or
     * the one that gets used to authenticate)
     * 
     * To be set by the constructors of the child classes.
     */
    public $credentialId;

    /**
     * the credential binary data for this event (either the one that gets 
     * registered, or the one that gets used to authenticate)
     *
     * To be set by the constructors of the child classes.
     */
    public $credential;

    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $idpEntityId     the entity ID of our IdP
     * @param string $authData        the authData / authenticatorData structure which is present in all types of events
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param bool   $debugMode       shall we collect and output some extensive debugging information along the way?
     */
    public function __construct($scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $debugMode = false) {
        $this->scope = $scope;
        $this->challenge = $challenge;
        $this->idpEntityId = $idpEntityId;
        $this->debugMode = $debugMode;
        /* eventType is already set by child constructor, otherwise the function will fail because of the missing type) */
        $this->clientDataHash = $this->verifyClientDataJSON($clientDataJSON);
        $this->counter = $this->validateAuthData($authData);
    }

    /**
     * The base64url decode function differs slightly from base64. Thanks.
     * 
     * taken from https://gist.github.com/nathggns/6652997
     * 
     * @param string $data the base64url-encoded source string
     * @return string the decoded string
     */
    public static function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * this function validates the content of clientDataJSON.
     * I.e. it performs 
     *   - for a REGistration session
     *     - the validation steps 2 through 8 of the validation
     *     - the parts of step 14 that relate to clientDataJSON
     *   - for a AUTHentication session
     *     - the validation steps 6 through 11 of the validation
     *     - the parts of step 15 that relate to clientDataJSON
     * 
     * @param string $challenge      the challenge which was used to trigger this event
     * @param string $idpEntityId    the entity ID of our IdP
     * @param string $clientDataJSON     the incoming data
     * @param string $requestedOperation are we validating a "REG" or an "AUTH?
     *
     * @return string
     */
    private function verifyClientDataJSON($clientDataJSON) {

        /**
         * §7.1 STEP 2 + 3 : convert to JSON and dissect JSON into PHP associative array
         * §7.2 STEP 6 + 7 : convert to JSON and dissect JSON into PHP associative array
         */
        $clientData = json_decode($clientDataJSON, true);
        switch ($this->eventType) {
            case "REG":
                if ($clientData['type'] == "webauthn.create") {
                    /**
                     * §7.1 STEP 4 wheck for webauthn.create
                     */
                    $this->pass("Registration requested; type has expected value");
                } else {
                    $this->fail("REG requested, but did not receive webauthn.create.");
                }
                break;
            case "AUTH":
                if ($clientData['type'] == "webauthn.get") {
                    /**
                     * §7.2 STEP 8: check for webauthn.get
                     */
                    $this->pass("Authentication requested; type has expected value");
                } else {
                    $this->fail("AUTH requested, but did not receive webauthn.get.");
                }
                break;
            default:
                $this->fail("Unexpected operation " . $this->eventType);
        }
        /**
         * §7.1 STEP 5 : check if incoming challenge matches issued challenge
         * §7.2 STEP 9 : check if incoming challenge matches issued challenge
         */
        if ($this->challenge == bin2hex(FIDO2AbstractEvent::base64url_decode($clientData['challenge']))) {
            $this->pass("Challenge matches");
        } else {
            $this->fail("Challenge does not match");
        }
        /**
         * §7.1 STEP 6 : check if incoming origin matches our hostname (taken from IdP metadata prefix)
         * §7.2 STEP 10: check if incoming origin matches our hostname (taken from IdP metadata prefix)
         */
        $expectedOrigin = substr($this->idpEntityId, 0, strpos($this->idpEntityId, '/', 8));
        if ($clientData['origin'] == $expectedOrigin) {
            $this->pass("Origin matches");
        } else {
            $this->fail("Origin does not match: " . $expectedOrigin);
        }
        /**
         * §7.1 STEP 7 : optional tokenBinding check. The Yubikey does not make use of that option.
         * §7.2 STEP 11: optional tokenBinding check. The Yubikey does not make use of that option.
         */
        if (!isset($clientData['tokenBinding'])) {
            $this->pass("No optional token binding data to validate.");
        } else {
            $this->warn("Validation of the present token binding data not implemented, continuing without!");
        }
        /**
         * STEP 14 (clientData part) of the validation procedure in § 7.1 of the spec: we did not request any client extensions, so none are allowed to be present
         */
        if (!isset($clientData['clientExtensions']) || count($clientData['clientExtensions']) == 0) {
            $this->pass("As expected, no client extensions.");
        } else {
            $this->fail("Incoming client extensions even though none were requested.");
        }
        /**
         * §7.1 STEP 8 : SHA-256 hashing the clientData
         */
        return hash("sha256", $_POST['attestation_client_data_json']);
    }

    /**
     * This function performs the required checks on the authData (REG) or authenticatorData (AUTH) structure
     * 
     * I.e. it performs 
     *   - for a REGistration session
     *     - the validation steps 10-12 of the validation
     *     - the parts of step 14 that relate to authData
     *   - for a AUTHentication session
     *     - the validation steps 12-14 of the validation
     *     - the parts of step 15 that relate to authData
     * 
     * @param string $authData           the authData / authenticatorData binary blob
     *
     * @return int the current counter value of the authenticator
     */
    private function validateAuthData($authData) {
        /**
         * §7.1 STEP 10: compare incoming RpId hash with expected value
         * §7.2 STEP 12: compare incoming RpId hash with expected value
         */
        if (bin2hex(substr($authData, 0, 32)) == hash("sha256", $this->scope)) {
            $this->pass("Relying Party hash correct.");
        } else {
            $this->fail("Mismatching Relying Party hash.");
        }
        $bitfield = substr($authData, 32, 1);
        /**
         * §7.1 STEP 14 (authData part): no extensions were requested, so none are allowed to be present
         * §7.2 STEP 15 (authData part): no extensions were requested, so none are allowed to be present
         */
        if ((128 & ord($bitfield)) > 0) {
            $this->fail("ED: Extension Data Included, even though we did not request any.");
        } else {
            $this->pass("ED: Extension Data not present.");
        }
        switch ($this->eventType) {
            case "REG":
                if ((64 & ord($bitfield)) > 0) {
                    $this->pass("AT: Attested Credential Data Included.");
                } else {
                    $this->fail("AT: not present, but required during registration.");
                }
                break;
            case "AUTH":
                if ((64 & ord($bitfield)) > 0) {
                    $this->fail("AT: Attested Credential Data Included.");
                } else {
                    $this->pass("AT: not present, like it should be during an authentication.");
                }
                break;

            default: $this->fail("unknown type of operation!");
        }
        /**
         * §7.1 STEP 11 + 12 : check user presence (this implementation does not insist on verification currently)
         * §7.2 STEP 13 + 14 : check user presence (this implementation does not insist on verification currently)
         */
        if (((4 & ord($bitfield)) > 0) || ((1 & ord($bitfield)) > 0)) {
            $this->pass("UV and/or UP indicated: User has token in his hands.");
        } else {
            $this->fail("Neither UV nor UP asserted: user is possibly not present at computer.");
        }
        $counterBin = substr($authData, 33, 4);
        
        $counterDec = intval(bin2hex($counterBin), 16);
        $this->debugBuffer .= "Signature Counter: $counterDec";
        return $counterDec;
    }

    protected function warn($text) {
        $this->validateBuffer .= "<span style='background-color:yellow;'>WARN: $text</span><br/>";
    }

    protected function fail($text) {
        $this->validateBuffer .= "<span style='background-color:red;'>FAIL: $text</span><br/>";
        if ($this->debugMode) {
            echo $this->debugBuffer;
            echo $this->validateBuffer;
        }
        throw new \Exception($text);
    }

    protected function pass($text) {
        $this->validateBuffer .= "<span style='background-color:green; color:white;'>PASS: $text</span><br/>";
    }

    protected function ignore($text) {
        $this->validateBuffer .= "<span style='background-color:blue; color:white;'>IGNORE: $text</span><br/>";
    }

}
