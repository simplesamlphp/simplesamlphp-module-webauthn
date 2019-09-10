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
class FIDO2RegistrationEvent extends FIDO2AbstractEvent {

    /**
     * Public key algorithm supported. This is -7 - ECDSA with curve P-256
     */
    const PK_ALGORITHM = -7;

    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $idpEntityId     the entity ID of our IdP
     * @param string $attestationData the attestation data CBOR blob
     * @param string $responseId      the response ID
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param string $debugMode       print debugging statements?
     */
    public function __construct($scope, $challenge, $idpEntityId, $attestationData, $responseId, $clientDataJSON, $debugMode = false) {
        $this->eventType = "REG";
        $authData = $this->validateAttestationData($attestationData);
        parent::__construct($scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $debugMode);
        // the following function sets the credential properties
        $this->validateAttestedCredentialData(substr($authData, 37), $responseId);
    }

    /**
     * validate the incoming attestation data CBOR blob and return the embedded authData
     */
    private function validateAttestationData($attestationData) {
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
            case "none": // § 8.7 of the spec
                /**
                 * STEP 16 of the validation procedure in § 7.1 of the spec: stmt must be an empty array
                 */
                /**
                 * STEP 17 + 18 of the validation procedure in § 7.1 of the spec are a NOOP if the format was "none" (which is acceptable as per this RPs policy)
                 */
                if (count($attestationArray['attStmt']) == 0) {
                    $this->pass("Attestation format and statement as expected, and no attestation authorities to retrieve.");
                } else {
                    $this->fail("Non-empty attestation authorities not implemented, can't go on.");
                }
                break;
            case "packed":
            case "tpm":
            case "android-key":
            case "android-safetynet":
            case "fido-u2f":
                $this->fail("Attestation format " . $attestationArray['fmt'] . " validation not supported right now.");
                break;
            default:
                $this->fail("Unknown attestation format.");
        }
        return $attestationArray['authData'];
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
        $this->debugBuffer .= "Length Raw = " . bin2hex($credIdLenBytes) . "<br/>";
        $this->debugBuffer .= "Credential ID Length (decimal) = " . $credIdLen . "<br/>";
        $this->debugBuffer .= "Credential ID (hex) = " . bin2hex($credId) . "<br/>";
        if (bin2hex(FIDO2AbstractEvent::base64url_decode($responseId)) == bin2hex($credId)) {
            $this->pass("Credential IDs in authenticator response and in attestation data match.");
        } else {
            $this->fail("Mismatch of credentialId vs. response ID.");
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
        if ($arrayPK['3'] == FIDO2RegistrationEvent::PK_ALGORITHM) { // we requested -7, so want to see it here
            $this->pass("Public Key Algorithm is the expected one (-7, ECDSA).");
        } else {
            $this->fail("Public Key Algorithm mismatch!");
        }
        $this->credentialId = bin2hex($credId);
        $this->credential = bin2hex($pubKeyCBOR);
    }

}
