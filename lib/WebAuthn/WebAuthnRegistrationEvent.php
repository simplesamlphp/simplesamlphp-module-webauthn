<?php

namespace SimpleSAML\Module\webauthn\WebAuthn;

use Cose\Key\Ec2Key;
use SimpleSAML\Logger;
use SimpleSAML\Utils;

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @package SimpleSAMLphp
 */
class WebAuthnRegistrationEvent extends WebAuthnAbstractEvent
{
    /**
     * Public key algorithm supported. This is -7 - ECDSA with curve P-256
     */
    public const PK_ALGORITHM = "-7";
    public const AAGUID_ASSURANCE_LEVEL_NONE = 0;
    public const AAGUID_ASSURANCE_LEVEL_SELF = 1;
    public const AAGUID_ASSURANCE_LEVEL_BASIC = 2;
    public const AAGUID_ASSURANCE_LEVEL_ATTCA = 3;

    /**
     * the AAGUID of the newly registered authenticator
     * @var string
     */
    protected string $AAGUID;

    /**
     * how sure are we about the AAGUID?
     * @var int
     */
    protected int $AAGUIDAssurance;

    /**
     * An array of known hardware tokens
     *
     * @var \SimpleSAML\Module\webauthn\WebAuthn\AAGUID
     */
    protected AAGUID $AAGUIDDictionary;

    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $pubkeyCredType  PublicKeyCredential.type
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $idpEntityId     the entity ID of our IdP
     * @param string $attestationData the attestation data CBOR blob
     * @param string $responseId      the response ID
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param bool $debugMode         print debugging statements?
     */
    public function __construct(
        string $pubkeyCredType,
        string $scope,
        string $challenge,
        string $idpEntityId,
        string $attestationData,
        string $responseId,
        string $clientDataJSON,
        bool $debugMode = false
    ) {
        $this->debugBuffer .= "attestationData raw: " . $attestationData . "<br/>";
        /**
         * §7.1 STEP 9 : CBOR decode attestationData.
         */
        $attestationArray = $this->cborDecode($attestationData);
        $authData = $attestationArray['authData'];
        $this->eventType = "REG";
        parent::__construct($pubkeyCredType, $scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $debugMode);

        $this->AAGUIDDictionary = AAGUID::getInstance();

        // this function extracts the public key
        $this->validateAttestedCredentialData(substr($authData, 37), $responseId);
        // this function may need the public key to have been previously extracted
        $this->validateAttestationData($attestationData);
        // the following function sets the credential properties
        $this->debugBuffer .= "Attestation Data (bin2hex): " . bin2hex(substr($authData, 37)) . "<br/>";
    }


    /**
     * Validate the incoming attestation data CBOR blob and return the embedded authData
     * @param string $attestationData
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
            case "android-key":
                $this->fail("Attestation format " . $attestationArray['fmt'] . " validation not supported right now.");
                break;
            default:
                $this->fail("Unknown attestation format.");
                break;
        }
    }


    /**
     * @param array $attestationArray
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
	while(openssl_error_string() !== false);

        $stmtDecoded = $attestationArray['attStmt'];
	if (!isset($stmtDecoded['x5c'])) {
		$this->fail("Apple attestation statement does not contain an x5c attestation statement!");
	}
	// § 8.8 Bullet 2
        $nonceToHash = $attestationArray['authData'] . $this->clientDataHash;
	// § 8.8 Bullet 3
	$nonce = hash("sha256", $nonceToHash, true); // does raw_output have to be FALSE or TRUE?
        $cryptoUtils = new Utils\Crypto();
        $certProps = openssl_x509_parse($cryptoUtils->der2pem($stmtDecoded['x5c'][0]));
	// § 8.8 Bullet 4
        if (
           !isset($certProps['extensions']['1.2.840.113635.100.8.2'])
           || empty($certProps['extensions']['1.2.840.113635.100.8.2'])
                ) {
                    $this->fail( "The required nonce value is not present in the OID." );
                }
	$toCompare = substr($certProps['extensions']['1.2.840.113635.100.8.2'], 6);
	if ($nonce != $toCompare) {
		$this->fail("There is a mismatch between the nonce and the OID (XXX $nonce XXX , XXX $toCompare XXX ).");
	}

	// chain validation first
	foreach ( $stmtDecoded['x5c'] as $runIndex => $runCert ) {
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
                                $this->fail("Error during root CA validation of the attestation chain certificate, which is " . $cryptoUtils->der2pem($runCert));
                        }
		}
	}

        $keyResource = openssl_pkey_get_public($cryptoUtils->der2pem($stmtDecoded['x5c'][0]));
        if ($keyResource === FALSE) {
		$this->fail("Did not get a parseable X.509 structure out of the Apple attestation statement - x5c nr. 0 statement was: XXX "
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

        if ($credentialResource === FALSE) {
                $this->fail("Could not create a public key from CBOR credential. XXX "
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
	if ( $credentialDetails['bits'] != $keyDetails['bits'] ||
             $credentialDetails['key']  != $keyDetails['key']  ||
             $credentialDetails['type'] != $keyDetails['type'] ) {
		$this->fail("The credential public key does not match the certificate public key in attestationData. ("
              . $credentialDetails['key']
              . " - "
              . $keyDetails['key']
              . ")");
	}
	$this->pass("Apple attestation format verification passed.");
	return;
    }

    /**
     * @param array $attestationArray
     */
    private function validateAttestationFormatPacked(array $attestationArray): void
    {
        $stmtDecoded = $attestationArray['attStmt'];
        $this->debugBuffer .= "AttStmt: " . print_r($stmtDecoded, true) . "<br/>";
        /**
         * §7.1 Step 16: attestation is either done with x5c or ecdaa.
         */
        if (isset($stmtDecoded['x5c'])) {
            $this->validateAttestationFormatPackedX5C($attestationArray);
        } elseif (isset($stmtDecoded['ecdaa'])) {
            $this->fail("ecdaa attestation not supported right now.");
        } else {
            // if we are still here, we are in the "self" type.
            $this->validateAttestationFormatPackedSelf($attestationArray);
        }
    }


    /**
     * @param array $attestationArray
     */
    private function validateAttestationFormatPackedX5C(array $attestationArray): void
    {
        $cryptoUtils = new Utils\Crypto();
        $stmtDecoded = $attestationArray['attStmt'];
        /**
         * §8.2 Step 2: check x5c attestation
         */
        $sigdata = $attestationArray['authData'] . $this->clientDataHash;
        $keyResource = openssl_pkey_get_public($cryptoUtils->der2pem($stmtDecoded['x5c'][0]));
        if ($keyResource === false) {
            $this->fail("Unable to construct public key resource from PEM.");
        }
        /**
         * §8.2 Step 2 Bullet 1: check signature
         */
        if (openssl_verify($sigdata, $stmtDecoded['sig'], $keyResource, OPENSSL_ALGO_SHA256) !== 1) {
            $this->fail("x5c attestation failed.");
        }
        $this->pass("x5c sig check passed.");
        // still need to perform sanity checks on the attestation certificate
        /**
         * §8.2 Step 2 Bullet 2: check certificate properties listed in §8.2.1
         */
        $certProps = openssl_x509_parse($cryptoUtils->der2pem($stmtDecoded['x5c'][0]));
        $this->debugBuffer .= "Attestation Certificate:" . print_r($certProps, true) . "<br/>";
        if (
            $certProps['version'] !== 2 || /** §8.2.1 Bullet 1 */
            $certProps['subject']['OU'] !== "Authenticator Attestation" || /** §8.2.1 Bullet 2 [Subject-OU] */
            !isset($certProps['subject']['CN']) || /** §8.2.1 Bullet 2 [Subject-CN] */
            !isset($certProps['extensions']['basicConstraints']) ||
            strstr($certProps['extensions']['basicConstraints'], "CA:FALSE") === false /** §8.2.1 Bullet 4 */
        ) {
            $this->fail("Attestation certificate properties are no good.");
        }

        if ($this->AAGUIDDictionary->hasToken($this->AAGUID)) {
            $token = $this->AAGUIDDictionary->get($this->AAGUID);
            if (
                $certProps['subject']['O'] !== $token['O'] ||
                // §8.2.1 Bullet 2 [Subject-O]
                $certProps['subject']['C'] !== $token['C']
                // §8.2ubject-C]
            ) {
                $this->fail("AAGUID does not match vendor data.");
            }
            if ($token['multi'] === true) { // need to check the OID
                if (
                    !isset($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4'])
                    || empty($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4'])
                ) { /** §8.2.1 Bullet 3 */
                    $this->fail(
                        "This vendor uses one cert for multiple authenticator model attestations, but lacks the AAGUID OID."
                    );
                }
                /**
                 * §8.2 Step 2 Bullet 3: compare AAGUID values
                 */
                $AAGUIDFromOid = substr(bin2hex($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4']), 4);
                $this->debugBuffer .= "AAGUID from OID = $AAGUIDFromOid<br/>";
                if (strtolower($AAGUIDFromOid) !== strtolower($this->AAGUID)) {
                    $this->fail("AAGUID mismatch between attestation certificate and attestation statement.");
                }
            }
            // we would need to verify the attestation certificate against a known-good
            // root CA certificate to get more than basic
            /*
             * §7.1 Step 17 is to look at $token['RootPEMs']
             */
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


    /**
     * @param array $attestationArray
     */
    private function validateAttestationFormatPackedSelf(array $attestationArray): void
    {
        $stmtDecoded = $attestationArray['attStmt'];
        /**
         * §8.2 Step 4 Bullet 1: check algorithm
         */
        if ($stmtDecoded['alg'] !== self::PK_ALGORITHM) {
            $this->fail("Unexpected algorithm type in packed basic attestation: " . $stmtDecoded['alg'] . ".");
        }
        $keyObject = new Ec2Key($this->cborDecode(hex2bin($this->credential)));
        $keyResource = openssl_pkey_get_public($keyObject->asPEM());
        if ($keyResource === false) {
            $this->fail("Unable to construct public key resource from PEM.");
        }
        $sigdata = $attestationArray['authData'] . $this->clientDataHash;
        /**
         * §8.2 Step 4 Bullet 2: verify signature
         */
        if (openssl_verify($sigdata, $stmtDecoded['sig'], $keyResource, OPENSSL_ALGO_SHA256) === 1) {
            $this->pass("Self-Attestation veried.");
            /**
             * §8.2 Step 4 Bullet 3: return Self level
             */
            $this->AAGUIDAssurance = self::AAGUID_ASSURANCE_LEVEL_SELF;
        } else {
            $this->fail("Self-Attestation failed.");
        }
    }


    /**
     * support legacy U2F tokens
     *
     * @param array $attestationData the incoming attestation data
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
        $cryptoUtils = new Utils\Crypto();
        $attCert = $cryptoUtils->der2pem($stmtDecoded['x5c'][0]);
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
     */
    private function validateAttestationFormatAndroidSafetyNet(array $attestationData): void
    {
    }


    /**
     * The registration contains the actual credential. This function parses it.
     * @param string $attData    the attestation data binary blob
     * @param string $responseId the response ID
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
        // Since we made sure above that no ED is in the sequence, take the rest
        // of the sequence in its entirety.
        $pubKeyCBOR = substr($attData, 18 + $credIdLen);
        $arrayPK = $this->cborDecode($pubKeyCBOR);
        $this->debugBuffer .= "pubKey in canonical form: <pre>" . print_r($arrayPK, true) . "</pre>";
        /**
         * STEP 13 of the validation procedure in § 7.1 of the spec: is the algorithm the expected one?
         */
        if ($arrayPK['3'] === self::PK_ALGORITHM) { // we requested -7, so want to see it here
            $this->pass("Public Key Algorithm is the expected one (-7, ECDSA).");
        } else {
            $this->fail("Public Key Algorithm mismatch!");
        }
        $this->credentialId = bin2hex($credId);
        $this->credential = bin2hex($pubKeyCBOR);
    }


    /**
     * @return string
     */
    public function getAAGUID(): string
    {
        return $this->AAGUID;
    }
}
