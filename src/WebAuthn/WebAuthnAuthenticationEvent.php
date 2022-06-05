<?php

namespace SimpleSAML\Module\webauthn\WebAuthn;

use Cose\Key\Ec2Key;

/**
 * FIDO2/WebAuthn Authentication Processing filter
 *
 * Filter for registering or authenticating with a FIDO2/WebAuthn token after
 * having authenticated with the primary authsource.
 *
 * @package SimpleSAMLphp
 */
class WebAuthnAuthenticationEvent extends WebAuthnAbstractEvent
{
    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $pubkeyCredType  PublicKeyCredential.type
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $idpEntityId     the entity ID of our IdP
     * @param string $authData        the authData binary string
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param string $credentialId    the credential ID
     * @param string $publicKey       the public key which is supposed to validate the sig
     *                                (COSE format, still needs to be converted to PEM!)
     * @param string $signature       the signature value to verify
     * @param bool $debugMode         print debugging statements?
     */
    public function __construct(
        string $pubkeyCredType,
        string $scope,
        string $challenge,
        string $idpEntityId,
        string $authData,
        string $clientDataJSON,
        string $credentialId,
        string $publicKey,
        string $signature,
        bool $debugMode = false
    ) {
        $this->eventType = "AUTH";
        $this->credential = $publicKey;
        $this->credentialId = $credentialId;
        parent::__construct($pubkeyCredType, $scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $debugMode);
        $this->validateSignature($authData . $this->clientDataHash, $signature);
    }


    /**
     * @param string $sigData
     * @param string $signature
     */
    private function validateSignature(string $sigData, string $signature): void
    {
        $keyArray = $this->cborDecode(hex2bin($this->credential));
        $keyObject = new Ec2Key($keyArray);
        $keyResource = openssl_pkey_get_public($keyObject->asPEM());
        if ($keyResource === false) {
            $this->fail("Unable to construct public key resource from PEM.");
        }
        /**
         * §7.2 STEP 17: validate signature
         */
        $sigcheck = openssl_verify($sigData, $signature, $keyResource, OPENSSL_ALGO_SHA256);
        switch ($sigcheck) {
            case 1:
                $this->pass("Signature validation succeeded!");
                break;
            case 0:
                $this->fail("Signature validation failed (sigdata = $sigData) (signature = $signature) !");
                break;
            default:
                $this->fail("There was an error executing the signature check.");
                break;
        }
    }
}
