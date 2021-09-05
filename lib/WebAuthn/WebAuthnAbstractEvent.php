<?php

namespace SimpleSAML\Module\webauthn\WebAuthn;

use CBOR\Decoder;
use CBOR\OtherObject;
use CBOR\Tag;
use CBOR\StringStream;
use Exception;

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @package SimpleSAMLphp
 */
abstract class WebAuthnAbstractEvent
{
    /**
     * Scope of the FIDO2 attestation. Can only be in the own domain.
     *
     * @var string
     */
    private string $scope;

    /**
     * The SHA256 hash of the clientDataJSON
     *
     * @var string
     */
    protected string $clientDataHash;

    /**
     * The challenge that was used to trigger this event
     *
     * @var string
     */
    private string $challenge;

    /**
     * Our IdP EntityId
     *
     * @var string
     */
    private string $idpEntityId;

    /**
     * the authenticator's signature counter
     *
     * @var int
     */
    protected int $counter;

    /**
     * extensive debug information collection?
     *
     * @var bool
     */
    protected bool $debugMode = false;

    /**
     * A string buffer to hold debug information in case we need it.
     *
     * @var string
     */
    protected string $debugBuffer = "";

    /**
     * A string buffer to hold raw validation data in case we want to look at it.
     *
     * @var string
     */
    protected string $validateBuffer = "";

    /**
     * the type of event requested. This is to be set in child class constructors
     * before calling the parent's.
     *
     * @var string
     */
    protected string $eventType;

    /**
     * The rpIdHash, available once validated during constructor of base class
     */
    protected string $rpIdHash;

    /**
     * the credential ID for this event (either the one that gets registered, or
     * the one that gets used to authenticate)
     *
     * To be set by the constructors of the child classes.
     *
     * @var string
     */
    protected string $credentialId;

    /**
     * the credential binary data for this event (either the one that gets
     * registered, or the one that gets used to authenticate)
     *
     * To be set by the constructors of the child classes.
     *
     * @var string
     */
    protected string $credential;


    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $pubkeyCredType  PublicKeyCredential.type
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $idpEntityId     the entity ID of our IdP
     * @param string $authData        the authData / authenticatorData structure which is present in all types of events
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param bool   $debugMode       shall we collect and output some extensive debugging information along the way?
     */
    public function __construct(
        string $pubkeyCredType,
        string $scope,
        string $challenge,
        string $idpEntityId,
        string $authData,
        string $clientDataJSON,
        bool $debugMode = false
    ) {
        $this->scope = $scope;
        $this->challenge = $challenge;
        $this->idpEntityId = $idpEntityId;
        $this->debugMode = $debugMode;
        $this->debugBuffer .= "PublicKeyCredential.type: $pubkeyCredType<br/>";
        /**
         * This is not a required validation as per spec. Still odd that Firefox returns
         * "undefined" even though its own API spec says it will send "public-key".
         */
        switch ($pubkeyCredType) {
            case "public-key":
                $this->pass("Key Type OK");
                break;
            case "undefined":
                $this->warn("Key Type 'undefined' - Firefox or Yubikey issue?");
                break;
            default:
                $this->fail("Unknown Key Type: " . $_POST['type']);
                break;
        }

        /**
         * eventType is already set by child constructor, otherwise the function
         * will fail because of the missing type)
         */
        $this->clientDataHash = $this->verifyClientDataJSON($clientDataJSON);
        $this->counter = $this->validateAuthData($authData);
    }


    /**
     * @return int
     */
    public function getCounter(): int
    {
        return $this->counter;
    }


    /**
     * @return string
     */
    public function getCredential(): string
    {
        return $this->credential;
    }


    /**
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }


    /**
     * @return string
     */
    public function getDebugBuffer(): string
    {
        return $this->debugBuffer;
    }


    /**
     * @return string
     */
    public function getValidateBuffer(): string
    {
        return $this->validateBuffer;
    }


    /**
     * The base64url decode function differs slightly from base64. Thanks.
     *
     * taken from https://gist.github.com/nathggns/6652997
     *
     * @param string $data the base64url-encoded source string
     * @return string the decoded string
     */
    public static function base64urlDecode(string $data): string
    {
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
     * @param string $clientDataJSON the incoming data
     *
     * @return string
     */
    private function verifyClientDataJSON(string $clientDataJSON): string
    {
        /**
         * §7.1 STEP 2 + 3 : convert to JSON and dissect JSON into PHP associative array
         * §7.2 STEP 6 + 7 : convert to JSON and dissect JSON into PHP associative array
         */
        $this->debugBuffer .= "ClientDataJSON hash: " . hash("sha256", $clientDataJSON) . "<br/>";
        $clientData = json_decode($clientDataJSON, true);
        $this->debugBuffer .= "<pre>" . print_r($clientData, true) . "</pre>";
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
                break;
        }
        /**
         * §7.1 STEP 5 : check if incoming challenge matches issued challenge
         * §7.2 STEP 9 : check if incoming challenge matches issued challenge
         */
        if ($this->challenge == bin2hex(WebAuthnAbstractEvent::base64urlDecode($clientData['challenge']))) {
            $this->pass("Challenge matches");
        } else {
            $this->fail("Challenge does not match");
        }
        /**
         * §7.1 STEP 6 : check if incoming origin matches our hostname (taken from IdP metadata prefix)
         * §7.2 STEP 10: check if incoming origin matches our hostname (taken from IdP metadata prefix)
         */
        $slash = strpos($this->idpEntityId, '/', 8);
        $expectedOrigin = ($slash !== false) ? substr($this->idpEntityId, 0, $slash) : $slash;
        if ($clientData['origin'] === $expectedOrigin) {
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
         * §7.1 STEP 14 (clientData part): we did not request any client extensions, and do not allow any to be present
         * §7.2 STEP 15 (clientData part): we did not request any client extensions, and do not allow any to be present
         */
        if (!isset($clientData['clientExtensions']) || count($clientData['clientExtensions']) == 0) {
            $this->pass("As expected, no client extensions.");
        } else {
            $this->fail("Incoming client extensions even though none were requested.");
        }
        /**
         * §7.1 STEP 8 : SHA-256 hashing the clientData
         * §7.2 STEP 16: SHA-256 hashing the clientData
         */
        return hash("sha256", $clientDataJSON, true);
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
    private function validateAuthData(string $authData): int
    {
        $this->debugBuffer .= "AuthData: <pre>";
        $this->debugBuffer .= print_r($authData, true);
        $this->debugBuffer .= "</pre>";
        /**
         * §7.1 STEP 10: compare incoming RpId hash with expected value
         * §7.2 STEP 12: compare incoming RpId hash with expected value
         */
        if (bin2hex(substr($authData, 0, 32)) == hash("sha256", $this->scope)) {
            $this->pass("Relying Party hash correct.");
            $this->rpIdHash = hash("sha256", $this->scope);
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
            default:
                $this->fail("unknown type of operation!");
                break;
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
        $this->debugBuffer .= "Signature Counter: $counterDec<br/>";
        return $counterDec;
    }


    /**
     * this function takes a binary CBOR blob and decodes it into an associative PHP array.
     *
     * @param string $rawData the binary CBOR blob
     * @return array the decoded CBOR data
     */
    protected function cborDecode(string $rawData): array
    {
        $otherObjectManager = new OtherObject\OtherObjectManager();
        $otherObjectManager->add(OtherObject\SimpleObject::class);
        $otherObjectManager->add(OtherObject\FalseObject::class);
        $otherObjectManager->add(OtherObject\TrueObject::class);
        $otherObjectManager->add(OtherObject\NullObject::class);
        $otherObjectManager->add(OtherObject\UndefinedObject::class);
        $otherObjectManager->add(OtherObject\HalfPrecisionFloatObject::class);
        $otherObjectManager->add(OtherObject\SinglePrecisionFloatObject::class);
        $otherObjectManager->add(OtherObject\DoublePrecisionFloatObject::class);

        $tagManager = new Tag\TagObjectManager();
        $tagManager->add(Tag\EpochTag::class);
        $tagManager->add(Tag\TimestampTag::class);
        $tagManager->add(Tag\PositiveBigIntegerTag::class);
        $tagManager->add(Tag\NegativeBigIntegerTag::class);
        $tagManager->add(Tag\DecimalFractionTag::class);
        $tagManager->add(Tag\BigFloatTag::class);
        $tagManager->add(Tag\Base64UrlEncodingTag::class);
        $tagManager->add(Tag\Base64EncodingTag::class);
        $tagManager->add(Tag\Base16EncodingTag::class);

        $decoder = new Decoder($tagManager, $otherObjectManager);
        $stream = new StringStream($rawData);
        $object = $decoder->decode($stream);
        $finalData = $object->getNormalizedData(true);
        if ($finalData === null) {
            $this->fail("CBOR data decoding failed.");
        }
        /** @psalm-var array $finalData */
        return $finalData;
    }


    /**
     * @param string $text
     */
    protected function warn(string $text): void
    {
        $this->validateBuffer .= "<span style='background-color:yellow;'>WARN: $text</span><br/>";
    }


    /**
     * @param string $text
     * @throws \Exception
     */
    protected function fail(string $text): void
    {
        $this->validateBuffer .= "<span style='background-color:red;'>FAIL: $text</span><br/>";
        if ($this->debugMode === true) {
            echo $this->debugBuffer;
            echo $this->validateBuffer;
        }
        throw new Exception($text);
    }


    /**
     * @param string $text
     */
    protected function pass(string $text): void
    {
        $this->validateBuffer .= "<span style='background-color:green; color:white;'>PASS: $text</span><br/>";
    }


    /**
     * @param string $text
     */
    protected function ignore(string $text): void
    {
        $this->validateBuffer .= "<span style='background-color:blue; color:white;'>IGNORE: $text</span><br/>";
    }
}
