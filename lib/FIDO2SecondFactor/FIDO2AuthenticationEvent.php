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
class FIDO2AuthenticationEvent extends FIDO2AbstractEvent {

    /**
     * Initialize the event object.
     *
     * Validates and parses the configuration.
     *
     * @param string $scope           the scope of the event
     * @param string $challenge       the challenge which was used to trigger this event
     * @param string $idpEntityId     the entity ID of our IdP
     * @param string $authData        the authData binary string
     * @param string $clientDataJSON  the client data JSON string which is present in all types of events
     * @param string $publicKey       the public key which is supposed to validate the sig (COSE format, still needs to be converted to PEM!)
     * @param string $signature       the signature value to verify
     * @param string $debugMode       print debugging statements?
     */
    public function __construct($scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $publicKey, $signature, $debugMode = false) {
        $this->eventType = "AUTH";
        parent::__construct($scope, $challenge, $idpEntityId, $authData, $clientDataJSON, $debugMode);
        $this->validateSignature($authData . $this->clientDataHash, $signature, $publicKey);
    }
    
    private function validateSignature($sigData, $signature, $publicKey) {
        $sigcheck = openssl_verify($sigData, $signature, KEY_UNFINISHED, OPENSSL_ALGO_SHA256);
        if ($sigcheck == 1 || true) {
            $this->ignore("NOT IMPLEMENTED YET - validation trivially succeeds!");
        } else {
            $this->fail("Signature validation failed!");
        }
    }
}
