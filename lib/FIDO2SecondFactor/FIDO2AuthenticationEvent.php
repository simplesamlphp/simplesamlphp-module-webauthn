<?php

namespace SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor;

use Cose\Key\Ec2Key;

use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;

include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/Utility/" . "BigInteger.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/Utility/" . "BigIntegerGmp.php";

include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/" . "Parsable.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/" . "ASNObject.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/" . "ExplicitlyTaggedObject.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/" . "Construct.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/" . "Identifier.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/" . "Base128.php";

include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/Universal/" . "OctetString.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/Universal/" . "BitString.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/Universal/" . "Integer.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/Universal/" . "ObjectIdentifier.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/fgrosse/phpasn1/lib/ASN1/Universal/" . "Sequence.php";

include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/web-auth/cose-lib/src/Key/" . "Key.php";
include_once dirname(dirname(dirname(dirname(__DIR__)))) . "/vendor/web-auth/cose-lib/src/Key/" . "Ec2Key.php";

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
        $keyArray = $this->cborDecode(hex2bin($publicKey));
        $keyObject = new Ec2Key($keyArray);
        $keyResource = openssl_pkey_get_public($keyObject->asPEM());
        if ($keyResource === FALSE) {
            fail("Unable to construct public key resource from PEM.");
        }
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
        }
    }
}
