<?php

namespace SimpleSAML\Module\webauthn\WebAuthn;

use Cose\Key\Ec2Key;

include_once 'AAGUID.php';

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */
class WebAuthnRegistrationEvent extends WebAuthnAbstractEvent {

    /**
     * Public key algorithm supported. This is -7 - ECDSA with curve P-256
     */
    const PK_ALGORITHM = -7;
    const AAGUID_ASSURANCE_LEVEL_NONE = 0;
    const AAGUID_ASSURANCE_LEVEL_SELF = 1;
    const AAGUID_ASSURANCE_LEVEL_BASIC = 2;
    const AAGUID_ASSURANCE_LEVEL_ATTCA = 3;

    /**
     * the AAGUID of the newly registered authenticator
     */
    public $AAGUID;

    /**
     * how sure are we about the AAGUID?
     */
    public $AAGUIDAssurance;

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
     * @param string $debugMode       print debugging statements?
     */
    public function __construct($pubkeyCredType, $scope, $challenge, $idpEntityId, $attestationData, $responseId, $clientDataJSON, $debugMode = false) {
        $this->debugBuffer .= "attestationData raw: " . $attestationData . "<br/>";
        /**
         * §7.1 STEP 9 : CBOR decode attestationData.
         */
        $attestationArray = $this->cborDecode($attestationData);
        $authData = $attestationArray['authData'];
        $this->eventType = "REG";
        parent::__construct($pubkeyCredType, $scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $debugMode);
        // this function extracts the public key
        $this->validateAttestedCredentialData(substr($authData, 37), $responseId);
        // this function may need the public key to have been previously extracted
        $this->validateAttestationData($attestationData, $clientDataJSON);
        // the following function sets the credential properties
        $this->debugBuffer .= "Attestation Data (bin2hex): " . bin2hex(substr($authData, 37)) . "<br/>";
    }

    /**
     * validate the incoming attestation data CBOR blob and return the embedded authData
     */
    private function validateAttestationData($attestationData, $clientDataJSON) {
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
                $this->validateAttestationFormatPacked($attestationArray, $clientDataJSON);
                break;
            case "tpm":
            case "android-key":
            case "android-safetynet":
            case "fido-u2f":
                $this->fail("Attestation format " . $attestationArray['fmt'] . " validation not supported right now.");
                break;
            default:
                $this->fail("Unknown attestation format.");
        }
    }

    private function validateAttestationFormatNone($attestationArray) {
        // § 8.7 of the spec
        /**
         * § 7.1 Step 16 && §8.7 Verification Procedure: stmt must be an empty array
         * § 7.1 Step 17+18 are a NOOP if the format was "none" (which is acceptable as per this RPs policy)
         */
        if (count($attestationArray['attStmt']) == 0) {
            $this->pass("Attestation format and statement as expected, and no attestation authorities to retrieve.");
            $this->AAGUIDAssurance = WebAuthnRegistrationEvent::AAGUID_ASSURANCE_LEVEL_NONE;
            return;
        } else {
            $this->fail("Non-empty attestation authorities are not expected with 'attestationFormat = none'.");
        }
    }

    private function validateAttestationFormatPacked($attestationArray, $clientDataJSON) {
        $stmtDecoded = $attestationArray['attStmt'];
        $this->debugBuffer .= "AttStmt: " . print_r($stmtDecoded, true) . "<br/>";
        /**
         * §7.1 Step 16: attestation is either done with x5c or ecdaa.
         */
        if (isset($stmtDecoded['x5c'])) {
            /**
             * §8.2 Step 2: check x5c attestation
             */
            $sigdata = $attestationArray['authData'] . hash("sha256", $clientDataJSON, true);
            $keyResource = openssl_pkey_get_public($this->der2pem($stmtDecoded['x5c'][0]));
            if ($keyResource === FALSE) {
                $this->fail("Unable to construct public key resource from PEM.");
            }
            /**
             * §8.2 Step 2 Bullet 1: check signature
             */
            if (openssl_verify($sigdata, $stmtDecoded['sig'], $keyResource, OPENSSL_ALGO_SHA256) != 1) {
                $this->fail("x5c attestation failed.");
            }
            $this->pass("x5c sig check passed.");
            // still need to perform sanity checks on the attestation certificate
            /**
             * §8.2 Step 2 Bullet 2: check certificate properties listed in §8.2.1
             */
            $certProps = openssl_x509_parse($this->der2pem($stmtDecoded['x5c'][0]));
            $this->debugBuffer .= "Attestation Certificate:" . print_r($certProps, true) . "<br/>";
            if ($certProps['version'] != 2 ||                                                                      /** §8.2.1 Bullet 1 */
                    $certProps['subject']['OU'] != "Authenticator Attestation" ||                                  /** §8.2.1 Bullet 2 [Subject-OU] */
                    !isset($certProps['subject']['CN']) ||                                                         /** §8.2.1 Bullet 2 [Subject-CN] */
                    !isset($certProps['extensions']['basicConstraints']) ||
                    strstr("CA:FALSE", $certProps['extensions']['basicConstraints']) === FALSE                     /** §8.2.1 Bullet 4 */
            ) {
                $this->fail("Attestation certificate properties are no good.");
            }
            if (isset(AAGUID::AAGUID_DICTIONARY[strtolower($this->AAGUID)])) {
                if ($certProps['subject']['O'] != AAGUID::AAGUID_DICTIONARY[strtolower($this->AAGUID)]['O'] ||     /** §8.2.1 Bullet 2 [Subject-O] */
                        $certProps['subject']['C'] != AAGUID::AAGUID_DICTIONARY[strtolower($this->AAGUID)]['C']) { /** §8.2.1 Bullet 2 [Subject-C] */
                    $this->fail("AAGUID does not match vendor data.");
                }
                if (AAGUID::AAGUID_DICTIONARY[strtolower($this->AAGUID)]['multi'] === TRUE) { // need to check the OID
                    if (!isset($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4'])) {                             /** §8.2.1 Bullet 3 */
                        $this->fail("This vendor uses one cert for multiple authenticator model attestations, but lacks the AAGUID OID.");
                    }
                    /**
                     * §8.2 Step 2 Bullet 3: compare AAGUID values
                     */
                    $AAGUIDFromOid = substr(bin2hex($certProps['extensions']['1.3.6.1.4.1.45724.1.1.4']), 4);
                    $this->debugBuffer .= "AAGUID from OID = $AAGUIDFromOid<br/>";
                    if (strtolower($AAGUIDFromOid) != strtolower($this->AAGUID)) {
                        $this->fail("AAGUID mismatch between attestation certificate and attestation statement.");
                    }
                }
                // we would need to verify the attestation certificate against a known-good root CA certificate to get more than basic
                /*
                 * §7.1 Step 17 is to look at AAGUID::AAGUID_DICTIONARY[strtolower($this->AAGUID)]['RootPEMs']
                 */
                /*
                 * §7.1 Step 18 is skipped, and we unconditionally return "only" Basic.
                 */
                $this->AAGUIDAssurance = WebAuthnRegistrationEvent::AAGUID_ASSURANCE_LEVEL_BASIC;
            } else {
                $this->warn("Unknown authenticator model found: " . $this->AAGUID . ".");
                // unable to verify all cert properties, so this is not enough for BASIC.
                // but it's our own fault, we should add the device to our DB.
                $this->AAGUIDAssurance = WebAuthnRegistrationEvent::AAGUID_ASSURANCE_LEVEL_SELF;
            }
            $this->pass("x5c attestation passed.");
        }
        if (isset($stmtDecoded['ecdaa'])) {
            $this->fail("ecdaa attestation not supported right now.");
        }
        // if we are still here, we are in the "self" type.
        /**
         * §8.2 Step 4 Bullet 1: check algorithm
         */
        if ($stmtDecoded['alg'] != WebAuthnRegistrationEvent::PK_ALGORITHM) {
            $this->fail("Unexpected algorithm type in packed basic attestation: " . $stmtDecoded['alg'] . ".");
        }
        $keyObject = new Ec2Key($this->cborDecode(hex2bin($this->credential)));
        $keyResource = openssl_pkey_get_public($keyObject->asPEM());
        if ($keyResource === FALSE) {
            $this->fail("Unable to construct public key resource from PEM.");
        }
        $sigdata = $attestationArray['authData'] . $this->clientDataHash;
        /**
         * §8.2 Step 4 Bullet 2: verify signature
         */
        if (openssl_verify($sigdata, $stmtDecoded['sig'], $keyResource) == 1) {
            $this->pass("Self-Attestation veried.");
            /**
             * §8.2 Step 4 Bullet 3: return Self level
             */
            $this->AAGUIDAssurance = FIDO2RegistrationEvent::AAGUID_ASSURANCE_LEVEL_SELF;
        } else {
            $this->fail("Self-Attestation failed.");
        }
    }

    /**
     * The registration contains the actual credential. This function parses it.
     * @param string $attData    the attestation data binary blob
     * @param string $responseId the response ID
     */
    private function validateAttestedCredentialData($attData, $responseId) {
        $aaguid = substr($attData, 0, 16);
        $credIdLenBytes = substr($attData, 16, 2);
        $credIdLen = intval(bin2hex($credIdLenBytes), 16);
        $credId = substr($attData, 18, $credIdLen);
        $this->debugBuffer .= "AAGUID (hex) = " . bin2hex($aaguid) . "</br/>";
        $this->AAGUID = bin2hex($aaguid);
        $this->debugBuffer .= "Length Raw = " . bin2hex($credIdLenBytes) . "<br/>";
        $this->debugBuffer .= "Credential ID Length (decimal) = " . $credIdLen . "<br/>";
        $this->debugBuffer .= "Credential ID (hex) = " . bin2hex($credId) . "<br/>";
        if (bin2hex(WebAuthnAbstractEvent::base64url_decode($responseId)) == bin2hex($credId)) {
            $this->pass("Credential IDs in authenticator response and in attestation data match.");
        } else {
            $this->fail("Mismatch of credentialId (" . bin2hex($credId) . ") vs. response ID (" . bin2hex(WebAuthnAbstractEvent::base64url_decode($responseId)) . ").");
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
        if ($arrayPK['3'] == WebAuthnRegistrationEvent::PK_ALGORITHM) { // we requested -7, so want to see it here
            $this->pass("Public Key Algorithm is the expected one (-7, ECDSA).");
        } else {
            $this->fail("Public Key Algorithm mismatch!");
        }
        $this->credentialId = bin2hex($credId);
        $this->credential = bin2hex($pubKeyCBOR);
    }

    /**
     * transform DER formatted certificate to PEM format
     * 
     * @param string $derData blob of DER data
     * @return string the PEM representation of the certificate
     */
    private function der2pem($derData) {
        $pem = chunk_split(base64_encode($derData), 64, "\n");
        $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
        return $pem;
    }

}
