<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\WebAuthn;

use Cose\Key\Ec2Key;
use Cose\Key\RsaKey;
use Exception;
use SimpleSAML\Error\Error;
use SimpleSAML\Error\InvalidCredential;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\WebAuthn\AAGUID;
use SimpleSAML\Utils;
use SimpleSAML\Utils\Config as SSPConfig;
use SpomkyLabs\Pki\ASN1\Type\UnspecifiedType;

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */
class WebAuthnRegistrationEvent extends WebAuthnAbstractEvent
{
    /**
     * Public key algorithm supported. This is -7 - ECDSA with curve P-256, or -275 (RS256)
     */
    public const PK_ALGORITHM_ECDSA = "-7";
    public const PK_ALGORITHM_RSA = "-257";
    public const PK_ALGORITHM = [self::PK_ALGORITHM_ECDSA, self::PK_ALGORITHM_RSA];
    public const AAGUID_ASSURANCE_LEVEL_NONE = 'None';
    public const AAGUID_ASSURANCE_LEVEL_SELF = 'Self';
    public const AAGUID_ASSURANCE_LEVEL_BASIC = 'Basic';
    public const AAGUID_ASSURANCE_LEVEL_ATTCA = 'AttCA';

    // nomenclature from the MDS3 spec
    public const FIDO_REVOKED = "REVOKED";
    public const CERTIFICATION_NOT_REQUIRED = "CERTIFICATION_NOT_REQUIRED";
    public const FIDO_CERTIFIED_L1 = "FIDO_CERTIFIED_L1";
    public const FIDO_CERTIFIED_L1PLUS = "FIDO_CERTIFIED_L1plus";
    public const FIDO_CERTIFIED_L2 = "FIDO_CERTIFIED_L2";
    public const FIDO_CERTIFIED_L3 = "FIDO_CERTIFIED_L3";
    public const FIDO_CERTIFIED_L3PLUS = "FIDO_CERTIFIED_L3plus";
    /**
     * the AAGUID of the newly registered authenticator
     * @var string
     */
    protected string $AAGUID;

    /**
     * how sure are we about the AAGUID?
     * @var string
     */
    protected string $AAGUIDAssurance;

    /**
     * An array of known hardware tokens
     *
     * @var \SimpleSAML\Module\webauthn\WebAuthn\AAGUID
     */
    protected AAGUID $AAGUIDDictionary;
    protected string $AttFmt;

    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $pubkeyCredType  PublicKeyCredential.type
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $attestationData the attestation data CBOR blob
     * @param string $responseId      the response ID
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param bool $debugMode         print debugging statements?
     */
    public function __construct(
        string $pubkeyCredType,
        string $scope,
        string $challenge,
        string $attestationData,
        string $responseId,
        string $clientDataJSON,
        array $acceptabilityPolicy,
        bool $debugMode = false
    ) {
        $this->debugBuffer .= "attestationData raw: " . $attestationData . "<br/>";
        /**
         * §7.1 STEP 9 : CBOR decode attestationData.
         */
        $attestationArray = $this->cborDecode($attestationData);
        $authData = $attestationArray['authData'];
        $this->eventType = "REG";
        parent::__construct($pubkeyCredType, $scope, $challenge, $authData, $clientDataJSON, $debugMode);

        $this->AAGUIDDictionary = AAGUID::getInstance();

        // this function extracts the public key
        $this->validateAttestedCredentialData(substr($authData, 37), $responseId);
        // this function may need the public key to have been previously extracted
        $this->validateAttestationData($attestationData);
        // the following function sets the credential properties
        $this->debugBuffer .= "Attestation Data (bin2hex): " . bin2hex(substr($authData, 37)) . "<br/>";
        // now check if the authenticator is acceptable as per policy
        $this->verifyAcceptability($acceptabilityPolicy);
    }

    private function verifyAcceptability($acceptabilityPolicy)
    {
        if ($acceptabilityPolicy['minCertLevel'] == self::CERTIFICATION_NOT_REQUIRED) { // all is accepted
            return;
        }

        // if we care about the content of the attestation at all, make sure we
        // have a confidence level beyond "None".
        if ($this->AAGUIDAssurance == self::AAGUID_ASSURANCE_LEVEL_NONE) {
            throw new Exception("Authenticator did not provide a useful attestation level.");
        }
        if (in_array($this->AAGUID, $acceptabilityPolicy['aaguidWhitelist'])) {
            return;
        }
        if (in_array($this->AttFmt, $acceptabilityPolicy['attFmtWhitelist'])) {
            return;
        }

        $aaguidDb = AAGUID::getInstance();
        if (!$aaguidDb->hasToken($this->AAGUID)) {
            throw new Exception("Authenticator with AAGUID " . $this->AAGUID . " is not known to the FIDO MDS3 database.");
        }
        $authenticatorData = $aaguidDb->get($this->AAGUID);
        $certification = $authenticatorData['statusReports'][0]['status'];

        if ($certification == self::FIDO_REVOKED) {
            throw new InvalidCredential("FIDO Alliance has REVOKED certification of this device. It cannot be registered.");
        }

        switch ($acceptabilityPolicy['minCertLevel']) {
            case self::FIDO_CERTIFIED_L1:
                // note: always full string match - there is also a level NOT_FIDO_CERTIFIED !
                if ($certification == "FIDO_CERTIFIED" || $certification == self::FIDO_CERTIFIED_L1) {
                    return;
                }
            // intentional fall-through, higher levels are also okay
            case self::FIDO_CERTIFIED_L1PLUS:
                if ($certification == self::FIDO_CERTIFIED_L1PLUS) {
                    return;
                }
            // intentional fall-through, higher levels are also okay
            case self::FIDO_CERTIFIED_L2:
                if ($certification == self::FIDO_CERTIFIED_L2) {
                    return;
                }
            // intentional fall-through, higher levels are also okay
            case self::FIDO_CERTIFIED_L3:
                if ($certification == self::FIDO_CERTIFIED_L3) {
                    return;
                }
            // intentional fall-through, higher levels are also okay
            case self::FIDO_CERTIFIED_L3PLUS:
                if ($certification == self::FIDO_CERTIFIED_L3PLUS) {
                    return;
                }
                throw new Error("FIDO_CERTIFICATION_TOO_LOW");
            default:
                throw new Exception("Configuration error: unknown minimum certification level " . $acceptabilityPolicy['minCertLevel']);
        }
    }

    /**
     * Validate the incoming attestation data CBOR blob and return the embedded authData
     * @param string $attestationData
     * @return void
     */
    private function validateAttestationData(string $attestationData): void
    {
        /**
         * STEP 9 of the validation procedure in § 7.1 of the spec: CBOR-decode the attestationObject
         */
        $attestationArray = $this->cborDecode($attestationData);
        $this->debugBuffer .= "<pre>";
        $this->debugBuffer .= print_r($attestationArray, true);
        $this->debugBuffer .= "</pre>";

        /**
         * STEP 15 of the validation procedure in § 7.1 of the spec: verify attStmt values
         */
        $this->AttFmt = $attestationArray['fmt'];
        switch ($attestationArray['fmt']) {
            case "none":
                $this->validateAttestationFormatNone($attestationArray);
                break;
            case "packed":
                $this->validateAttestationFormatPacked($attestationArray);
                break;
            case "fido-u2f":
                $this->validateAttestationFormatFidoU2F($attestationArray);
                break;
            case "android-safetynet":
                $this->validateAttestationFormatAndroidSafetyNet($attestationArray);
                break;
            case "apple":
                $this->validateAttestationFormatApple($attestationArray);
                break;
            case "tpm":
                $this->fail("TPM attestation format not supported right now.");
                break;
            case "android-key":
                $this->validateAttestationFormatAndroidKey($attestationArray);
                break;
            default:
                $this->fail("Unknown attestation format.");
                break;
        }
        $this->AttFmt = $attestationArray['fmt'];
    }

    /**
     * @param array $attestationArray
     * @return void
     */
    private function validateAttestationFormatNone(array $attestationArray): void
    {
        // § 8.7 of the spec
        /**
         * § 7.1 Step 16 && §8.7 Verification Procedure: stmt must be an empty array
         * § 7.1 Step 17+18 are a NOOP if the format was "none" (which is acceptable as per this RPs policy)
         */
        if (count($attestationArray['attStmt']) === 0) {
            $this->pass("Attestation format and statement as expected, and no attestation authorities to retrieve.");
            $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_NONE;
            return;
        } else {
            $this->fail("Non-empty attestation authorities are not expected with 'attestationFormat = none'.");
        }
    }

    /**
     * @param array $attestationArray
     */
    private function validateAttestationFormatApple(array $attestationArray): void
    {
        // found at: https://www.apple.com/certificateauthority/private/

        $APPLE_WEBAUTHN_ROOT_CA = "-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----";
        // § 8.8 Bullet 1 of the draft spec at https://pr-preview.s3.amazonaws.com/alanwaketan/webauthn/pull/1491.html#sctn-apple-anonymous-attestation
        // draft implemented in state of 11 Feb 2021
        // I can't help but notice that the verification procedure does NOTHING with CA certs from the chain, nor is there a root to validate to!
        // Found the root CA with Google, see above, and will perform chain validation even if the spec doesn't say so.
        // first, clear the openssl error backlog. We might need error data in case things go sideways.
        while (openssl_error_string() !== false);

        $stmtDecoded = $attestationArray['attStmt'];
        if (!isset($stmtDecoded['x5c'])) {
            $this->fail("Apple attestation statement does not contain an x5c attestation statement!");
        }
        // § 8.8 Bullet 2
        $nonceToHash = $attestationArray['authData'] . $this->clientDataHash;
        // § 8.8 Bullet 3
        $cryptoUtils = new Utils\Crypto();
        $nonce = hash("sha256", $nonceToHash, true); // does raw_output have to be FALSE or TRUE?
        $certProps = openssl_x509_parse($cryptoUtils->der2pem($stmtDecoded['x5c'][0]));
        // § 8.8 Bullet 4
        if (
                !isset($certProps['extensions']['1.2.840.113635.100.8.2']) ||
                empty($certProps['extensions']['1.2.840.113635.100.8.2'])
        ) {
            $this->fail("The required nonce value is not present in the OID.");
        }
        $toCompare = substr($certProps['extensions']['1.2.840.113635.100.8.2'], 6);
        if ($nonce != $toCompare) {
            $this->fail("There is a mismatch between the nonce and the OID (XXX $nonce XXX , XXX $toCompare XXX ).");
        }

        // chain validation first
        foreach ($stmtDecoded['x5c'] as $runIndex => $runCert) {
            if (isset($stmtDecoded['x5c'][$runIndex + 1])) { // there is a next cert, so follow the chain
                $certResource = openssl_x509_read($cryptoUtils->der2pem($runCert));
                $signerPubKey = openssl_pkey_get_public($cryptoUtils->der2pem($stmtDecoded['x5c'][$runIndex + 1]));
                if (openssl_x509_verify($certResource, $signerPubKey) != 1) {
                    $this->fail("Error during chain validation of the attestation certificate (while validating cert #$runIndex, which is "
                            . $cryptoUtils->der2pem($runCert)
                            . "; next cert was "
                            . $cryptoUtils->der2pem($stmtDecoded['x5c'][$runIndex + 1]));
                }
            } else { // last cert, compare to the root
                $certResource = openssl_x509_read($cryptoUtils->der2pem($runCert));
                $signerPubKey = openssl_pkey_get_public($APPLE_WEBAUTHN_ROOT_CA);
                if (openssl_x509_verify($certResource, $signerPubKey) != 1) {
                    $this->fail(sprintf(
                        "Error during root CA validation of the attestation chain certificate, which is %s",
                        $cryptoUtils->der2pem($runCert)
                    ));
                }
            }
        }

        $keyResource = openssl_pkey_get_public($cryptoUtils->der2pem($stmtDecoded['x5c'][0]));
        if ($keyResource === false) {
            $this->fail(
                "Did not get a parseable X.509 structure out of the Apple attestation statement - x5c nr. 0 statement was: XXX "
                . $stmtDecoded['x5c'][0]
                . " XXX; PEM equivalent is "
                . $cryptoUtils->der2pem($stmtDecoded['x5c'][0])
                . ". OpenSSL error: "
                . openssl_error_string()
            );
        }

        // $this->credential is a public key in CBOR, not "PEM". We need to convert it first.
        $keyArray = $this->cborDecode(hex2bin($this->credential));
        $keyObject = new Ec2Key($keyArray);
        $credentialResource = openssl_pkey_get_public($keyObject->asPEM());

        if ($credentialResource === false) {
            $this->fail(
                "Could not create a public key from CBOR credential. XXX "
                . $this->credential
                . " XXX; PEM equivalent is "
                . $keyObject->asPEM()
                . ". OpenSSL error: "
                . openssl_error_string()
            );
        }

        // § 8.8 Bullet 5
        $credentialDetails = openssl_pkey_get_details($credentialResource);
        $keyDetails = openssl_pkey_get_details($keyResource);
        if (
            $credentialDetails['bits'] != $keyDetails['bits'] ||
            $credentialDetails['key'] != $keyDetails['key'] ||
            $credentialDetails['type'] != $keyDetails['type']
        ) {
            $this->fail(
                "The credential public key does not match the certificate public key in attestationData. ("
                . $credentialDetails['key']
                . " - "
                . $keyDetails['key']
                . ")"
            );
        }
        $this->pass("Apple attestation format verification passed.");
        return;
    }

    private function commonX5cSignatureChecks(array $attestationArray): void
    {
        $stmtDecoded = $attestationArray['attStmt'];
        /**
         * §8.2 Step 4 Bullet 1: check algorithm
         */
        if (!in_array($stmtDecoded['alg'], self::PK_ALGORITHM)) {
            $this->fail("Unexpected algorithm type in packed basic attestation: " . $stmtDecoded['alg'] . ".");
        }
        $keyObject = null;
        switch ($stmtDecoded['alg']) {
            case self::PK_ALGORITHM_ECDSA:
                $keyObject = new Ec2Key($this->cborDecode(hex2bin($this->credential)));
                $keyResource = openssl_pkey_get_public($keyObject->asPEM());
                if ($keyResource === false) {
                    $this->fail("Unable to construct ECDSA public key resource from PEM.");
                };
                break;
            case self::PK_ALGORITHM_RSA:
                $keyObject = new RsaKey($this->cborDecode(hex2bin($this->credential)));
                $keyResource = openssl_pkey_get_public($keyObject->asPEM());
                if ($keyResource === false) {
                    $this->fail("Unable to construct RSA public key resource from PEM.");
                }
                break;
            default:
                $this->fail("Unable to construct public key resource from PEM.");
        }
        /**
         * §8.2 Step 2: check x5c attestation
         */
        $sigdata = $attestationArray['authData'] . $this->clientDataHash;
        /**
         * §8.2 Step 2 Bullet 1: check signature
         */
        if (openssl_verify($sigdata, $stmtDecoded['sig'], $keyResource, OPENSSL_ALGO_SHA256) !== 1) {
            $this->fail("x5c attestation failed.");
        }
        $this->pass("x5c sig check passed.");
    }

    /**
     * @param array $attestationArray
     */
    private function validateAttestationFormatPacked(array $attestationArray): void
    {
        $stmtDecoded = $attestationArray['attStmt'];
        $this->debugBuffer .= "AttStmt: " . print_r($stmtDecoded, true) . "<br/>";
        $this->commonX5cSignatureChecks($attestationArray);
        /**
         * §7.1 Step 16: attestation is either done with x5c or ecdaa.
         */
        if (isset($stmtDecoded['x5c'])) {
            $this->validateAttestationFormatPackedX5C($attestationArray);
        } elseif (isset($stmtDecoded['ecdaa'])) {
            $this->fail("ecdaa attestation not supported right now.");
        } else {
            // if we are still here, we are in the "self" type.
            // signature checks already done, nothing more to do
            $this->pass("Self-Attestation veried.");
            $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_SELF;
        }
    }

    /**
     * @param array $attestationArray
     * @return void
     */
    private function validateAttestationFormatPackedX5C(array $attestationArray): void
    {
        $stmtDecoded = $attestationArray['attStmt'];
        // still need to perform sanity checks on the attestation certificate
        /**
         * §8.2 Step 2 Bullet 2: check certificate properties listed in §8.2.1
         */
        $certProps = openssl_x509_parse($this->der2pem($stmtDecoded['x5c'][0]));
        $this->debugBuffer .= "Attestation Certificate:" . print_r($certProps, true) . "<br/>";
        if (
                $certProps['version'] !== 2 || /** §8.2.1 Bullet 1 */
                $certProps['subject']['OU'] !== "Authenticator Attestation" || /** §8.2.1 Bullet 2 [Subject-OU] */
                !isset($certProps['subject']['CN']) || /** §8.2.1 Bullet 2 [Subject-CN] */
                !isset($certProps['extensions']['basicConstraints']) ||
                strstr("CA:FALSE", $certProps['extensions']['basicConstraints']) === false /** §8.2.1 Bullet 4 */
        ) {
            $this->fail("Attestation certificate properties are no good.");
        }

        if ($this->AAGUIDDictionary->hasToken($this->AAGUID)) {
            $token = $this->AAGUIDDictionary->get($this->AAGUID);
            /**
             * Checking the OID is not programmatically possible. Text per spec:
             * "If the related attetation root certificate is used for multiple
             * authenticator models, the Extension OID ... MUST be present."
             *
             * FIDO MDS3 metadata does not disclose whether the root CAs are
             * used for multiple models.
             */
            /* if ($token['multi'] === true) { // need to check the OID
                if (
                        !isset($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4']) || empty($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4'])
                ) { // §8.2.1 Bullet 3
                    $this->fail(
                            "This vendor uses one cert for multiple authenticator model attestations, but lacks the AAGUID OID."
                    );
                }
                /**
                 * §8.2 Step 2 Bullet 3: compare AAGUID values
                 */
                /* $AAGUIDFromOid = substr(bin2hex($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4']), 4);
                $this->debugBuffer .= "AAGUID from OID = $AAGUIDFromOid<br/>";
                if (strtolower($AAGUIDFromOid) !== strtolower($this->AAGUID)) {
                    $this->fail("AAGUID mismatch between attestation certificate and attestation statement.");
                }
            }*/
            // we would need to verify the attestation certificate against a known-good
            // root CA certificate to get more than basic
            /*
             * §7.1 Step 17 is to look at $token['RootPEMs']
             */
            foreach ($token['metadataStatement']['attestationRootCertificates'] as $oneRoot) {
                $caData = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n$oneRoot\n-----END CERTIFICATE-----", true);
            }
            /*
             * §7.1 Step 18 is skipped, and we unconditionally return "only" Basic.
             */
            $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_BASIC;
        } else {
            $this->warn("Unknown authenticator model found: " . $this->AAGUID . ".");
            // unable to verify all cert properties, so this is not enough for BASIC.
            // but it's our own fault, we should add the device to our DB.
            $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_SELF;
        }
        $this->pass("x5c attestation passed.");
        return;
    }

    // Keymaster 3 - KeyMint ???
    private const ORIGINS_3 = [ // https://source.android.com/docs/security/features/keystore/tags#origin
        0 => "GENERATED",
        1 => "DERIVED",
        2 => "IMPORTED",
        3 => "UNKNOWN",
        ];
    private const PURPOSE_3 = [
        0 => "ENCRYPT",
        1 => "DECRYPT",
        2 => "SIGN",
        3 => "VERIFY",
        4 => "DERIVE_KEY",
        5 => "WRAP_KEY",
    ];

    private const MIN_SUPPORTED_KEYMASTER_VERSION = 3;

    private function validateAttestationFormatAndroidKey(array $attestationArray): void
    {
        $stmtDecoded = $attestationArray['attStmt'];
        $this->debugBuffer .= "AttStmt: " . print_r($stmtDecoded, true) . "<br/>";
        $this->commonX5cSignatureChecks($attestationArray);
        // first certificate's properties
        $certProps = openssl_x509_parse($this->der2pem($stmtDecoded['x5c'][0]));
        $keyResource = openssl_pkey_get_public($this->der2pem($stmtDecoded['x5c'][0]));
        $keyDetails = openssl_pkey_get_details($keyResource);
        switch ($keyDetails['type']) {
            case OPENSSL_KEYTYPE_EC:
                $certPubkey = $keyDetails['ec'];
                break;
            case OPENSSL_KEYTYPE_RSA:
                $certPubkey = $keyDetails['rsa'];
                break;
            default:
                throw new Exception("Public key was neither a RSA nor EC key.");
        }
        $statementKeyData = $this->cborDecode(hex2bin($this->credential));
        // this will only work for ECDSA keys, screw RSA
        if (
            $statementKeyData['x'] != $certPubkey[-2] || $statementKeyData['y'] != $certPubkey[-3]
        ) {
            $this->fail("Certificate public key does not match credentialPublicKey in authenticatorData (" . print_r($certPubkey, true) . "###" . print_r($statementKeyData, true) . ").");
        }
        // throw new Exception(print_r($certProps, true));
        $rawAsn1Oid = $certProps['extensions']['1.3.6.1.4.1.11129.2.1.17'];
        $keyDescription = UnspecifiedType::fromDER($rawAsn1Oid)->asSequence();
        $attestationVersion = $keyDescription->at(0)->asInteger()->intNumber();
        $attestationChallenge = $keyDescription->at(4)->asOctetString()->string();
        $softwareEnforced = $keyDescription->at(6)->asSequence();
        $teeEnforced = $keyDescription->at(7)->asSequence();

        if ($this->clientDataHash !== $attestationChallenge) {
            $this->fail("ClientDataHash is not in certificate's extension data (attestationChallenge).");
        }

        if ($attestationVersion < self::MIN_SUPPORTED_KEYMASTER_VERSION) {
            $this->fail("Attestation versions below " . self::MIN_SUPPORTED_KEYMASTER_VERSION . " not supported, found $attestationVersion.");
        }

        if ($softwareEnforced->hasTagged(600) || $teeEnforced->hasTagged(600)) {
            $this->fail("Tag allApplications found!");
        }
        // need to go through both software and TEE and check origins and purpose

        if (
                ($softwareEnforced->hasTagged(702) && ($softwareEnforced->getTagged(702)->asExplicit()->asInteger()->intNumber() != array_search("GENERATED", self::ORIGINS_3))) ||
                ($teeEnforced->hasTagged(702) && ($teeEnforced->getTagged(702)->asExplicit()->asInteger()->intNumber() != array_search("GENERATED", self::ORIGINS_3)))
        ) {
            $this->fail("Incorrect value for ORIGIN!");
        }

        if ($softwareEnforced->hasTagged(1)) {
            $purposesSoftware = $softwareEnforced->getTagged(1)->asExplicit()->asSet();
            foreach ($purposesSoftware->elements() as $onePurpose) {
                if ($onePurpose->asInteger()->intNumber() != array_search("SIGN", self::PURPOSE_3)) {
                        $this->fail("Incorrect value for PURPOSE (softwareEnforced)!");
                }
            }
        }
        if ($teeEnforced->hasTagged(1)) {
            $purposesTee = $teeEnforced->getTagged(1)->asExplicit()->asSet();
            foreach ($purposesTee->elements() as $onePurpose) {
                if ($onePurpose->asInteger()->intNumber() != array_search("SIGN", self::PURPOSE_3)) {
                        $this->fail("Incorrect value for PURPOSE (teeEnforced)!");
                }
            }
        }

        $this->pass("Android Key attestation passed.");
        $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_BASIC;
    }

    /**
     * support legacy U2F tokens
     *
     * @param array $attestationData the incoming attestation data
     * @return void
     */
    private function validateAttestationFormatFidoU2F(array $attestationData): void
    {
        /**
         * §8.6 Verification Step 1 is a NOOP: if we're here, the attStmt was
         * already successfully CBOR decoded
         */
        $stmtDecoded = $attestationData['attStmt'];
        if (!isset($stmtDecoded['x5c'])) {
            $this->fail("FIDO U2F attestation needs to have the 'x5c' key");
        }
        /**
         * §8.6 Verification Step 2: extract attCert and sanity check it
         */
        if (count($stmtDecoded['x5c']) !== 1) {
            $this->fail("FIDO U2F attestation requires 'x5c' to have only exactly one key.");
        }
        $attCert = $this->der2pem($stmtDecoded['x5c'][0]);
        $key = openssl_pkey_get_public($attCert);
        $keyProps = openssl_pkey_get_details($key);
        if (!isset($keyProps['ec']['curve_name']) || $keyProps['ec']['curve_name'] !== "prime256v1") {
            $this->fail("FIDO U2F attestation public key is not P-256!");
        }
        /**
         * §8.6 Verification Step 3 is a NOOP as these properties are already
         * available as class members:
         *
         * $this->rpIdHash;
         * $this->credentialId;
         * $this->credential;
         */
        /**
         * §8.6 Verification Step 4: encode the public key in ANSI X9.62 format
         */
        if (
                isset($this->credential[-2]) &&
                strlen($this->credential[-2]) === 32 &&
                isset($this->credential[-3]) &&
                strlen($this->credential[-3]) === 32
        ) {
            $publicKeyU2F = chr(4) . $this->credential[-2] . $this->credential[-3];
        } else {
            $publicKeyU2F = false;
            $this->fail("FIDO U2F attestation: the public key is not as expected.");
        }
        /**
         * §8.6 Verification Step 5: create verificationData
         *
         * @psalm-var string $publicKeyU2F
         */
        $verificationData = chr(0) . $this->rpIdHash . $this->clientDataHash . $this->credentialId . $publicKeyU2F;
        /**
         * §8.6 Verification Step 6: verify signature
         */
        if (openssl_verify($verificationData, $stmtDecoded['sig'], $attCert, OPENSSL_ALGO_SHA256) !== 1) {
            $this->fail("FIDO U2F Attestation verification failed.");
        } else {
            $this->pass("Successfully verified FIDO U2F signature.");
        }
        /**
         * §8.6 Verification Step 7: not performed, this is optional as per spec
         */
        /**
         * §8.6 Verification Step 8: so we always settle for "Basic"
         */
        $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_BASIC;
    }

    /**
     * support Android authenticators (fingerprint etc.)
     *
     * @param array $attestationData the incoming attestation data
     * @return void
     */
    private function validateAttestationFormatAndroidSafetyNet(array $attestationData): void
    {
    }

    /**
     * The registration contains the actual credential. This function parses it.
     * @param string $attData    the attestation data binary blob
     * @param string $responseId the response ID
     * @return void
     */
    private function validateAttestedCredentialData(string $attData, string $responseId): void
    {
        $aaguid = substr($attData, 0, 16);
        $credIdLenBytes = substr($attData, 16, 2);
        $credIdLen = intval(bin2hex($credIdLenBytes), 16);
        $credId = substr($attData, 18, $credIdLen);
        $this->debugBuffer .= "AAGUID (hex) = " . bin2hex($aaguid) . "</br/>";
        $this->AAGUID = bin2hex($aaguid);
        $this->debugBuffer .= "Length Raw = " . bin2hex($credIdLenBytes) . "<br/>";
        $this->debugBuffer .= "Credential ID Length (decimal) = " . $credIdLen . "<br/>";
        $this->debugBuffer .= "Credential ID (hex) = " . bin2hex($credId) . "<br/>";
        if (bin2hex(WebAuthnAbstractEvent::base64urlDecode($responseId)) === bin2hex($credId)) {
            $this->pass("Credential IDs in authenticator response and in attestation data match.");
        } else {
            $this->fail(
                "Mismatch of credentialId (" . bin2hex($credId) . ") vs. response ID (" .
                bin2hex(WebAuthnAbstractEvent::base64urlDecode($responseId)) . ")."
            );
        }
        // so far so good. Now extract the actual public key from its COSE
        // encoding.
        // finding out the number of bytes to CBOR decode appears non-trivial.
        // The simple case is if no ED is present as the CBOR data then goes to
        // the end of the byte sequence.
        // since we don't know the algoritm yet, we don't know how many bytes
        // of credential CBOR follow. Let's read to the end; the CBOR decoder
        // silently ignores trailing extensions (if any)
        $pubKeyCBOR = substr($attData, 18 + $credIdLen);
        $arrayPK = $this->cborDecode($pubKeyCBOR);
        $this->debugBuffer .= "pubKey in canonical form: <pre>" . print_r($arrayPK, true) . "</pre>";
        /**
         * STEP 13 of the validation procedure in § 7.1 of the spec: is the algorithm the expected one?
         */
        if (in_array($arrayPK['3'], self::PK_ALGORITHM)) { // we requested -7 or -257, so want to see it here
            $this->algo = (int)$arrayPK['3'];
            $this->pass("Public Key Algorithm is expected (" . implode(' or ', WebAuthnRegistrationEvent::PK_ALGORITHM) . ").");
        } else {
            $this->fail("Public Key Algorithm mismatch!");
        }
        $this->credentialId = bin2hex($credId);
        $this->credential = bin2hex($pubKeyCBOR);

        // now that we know credential and its length, we can CBOR-decode the
        // trailing extensions
        switch ($this->algo) {
            case self::PK_ALGORITHM_ECDSA:
                $credentialLength = 77;
                break;
            case self::PK_ALGORITHM_RSA:
                $credentialLength = 272;
                break;
            default:
                $this->fail("No credential length information for $this->algo");
        }
        $extensions = substr($attData, 18 + $credIdLen + $credentialLength);
        if (strlen($extensions) !== 0) {
            $this->pass("Found the following extensions (" . strlen($extensions) . " bytes) during registration ceremony: ");
        }
    }

    /**
     * transform DER formatted certificate to PEM format
     *
     * @param string $derData blob of DER data
     * @return string the PEM representation of the certificate
     */
    private function der2pem(string $derData): string
    {
        $pem = chunk_split(base64_encode($derData), 64, "\n");
        $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
        return $pem;
    }

    /**
     * @return string
     */
    public function getAAGUID()
    {
        return $this->AAGUID;
    }

    /**
     * @return string
     */
    public function getAttestationLevel()
    {
        return $this->AAGUIDAssurance;
    }
}
