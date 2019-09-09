<?php
use CBOR\Decoder;
use CBOR\OtherObject;
use CBOR\Tag;
use CBOR\StringStream;

include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Stream.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."StringStream.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."CBORObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."AbstractCBORObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."TagObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."MapObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."LengthCalculator.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."TextStringObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."MapItem.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."ByteStringObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."ByteStringWithChunkObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."ListObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."UnsignedIntegerObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."SignedIntegerObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/SimpleObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/FalseObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/TrueObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/NullObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/UndefinedObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/HalfPrecisionFloatObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/SinglePrecisionFloatObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/DoublePrecisionFloatObject.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."OtherObject/OtherObjectManager.php";

include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/EpochTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/TimestampTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/PositiveBigIntegerTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/NegativeBigIntegerTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/DecimalFractionTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/BigFloatTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/Base64UrlEncodingTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/Base64EncodingTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/Base16EncodingTag.php";
include_once dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Tag/TagObjectManager.php";

include dirname(dirname(dirname(__DIR__)))."/vendor/Spomky-labs/cbor-php/src/"."Decoder.php";

// taken from https://gist.github.com/nathggns/6652997

function base64url_decode($data) {
	return base64_decode(strtr($data, '-_', '+/'));
}

function warn($text) {
	global $validatebuffer;
	$validatebuffer .= "<span style='background-color:yellow;'>WARN: $text</span><br/>";
}

function fail($text) {
	global $validatebuffer;
	global $debugbuffer;
	global $debugEnabled;
	$validatebuffer .= "<span style='background-color:red;'>FAIL: $text</span><br/>";
	if ($debugEnabled) {
		echo $debugbuffer;
		echo $validatebuffer;
	}
	throw new Exception($text);
}

function pass($text) {
	global $validatebuffer;
	$validatebuffer .= "<span style='background-color:green; color:white;'>PASS: $text</span><br/>";
}

function ignore($text) {
	global $validatebuffer;
	$validatebuffer .= "<span style='background-color:blue; color:white;'>IGNORE: $text</span><br/>";
}

/**
 * this function takes a binary CBOR blob and decodes it into an associative PHP array.
 *
 * @param string $rawData the binary CBOR blob
 * @return array the decoded CBOR data
 */
function cborDecode($rawData) {
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
	return $object->getNormalizedData(true);
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
 * @param array  $state              the session state
 * @param string $clientDataJSON     the incoming data
 * @param string $requestedOperation are we validating a "REG" or an "AUTH?
 *
 * @return string
 */
function verifyClientDataJSON($state, $clientDataJSON, $requestedOperation) {

	/**
	 * §7.1 STEP 2 + 3 : convert to JSON and dissect JSON into PHP associative array
	 * §7.2 STEP 6 + 7 : convert to JSON and dissect JSON into PHP associative array
	 */
	$clientData = json_decode($clientDataJSON, true);
	switch ($requestedOperation) {
	case "REG":
		if($clientData['type'] == "webauthn.create") {
			/**
			 * §7.1 STEP 4 wheck for webauthn.create
			 */
			pass("Registration requested; type has expected value");

		} else {
			fail("REG requested, but did not receive webauthn.create.");
		}
		break;
	case "AUTH":
		if($clientData['type'] == "webauthn.get") {
			/**
			 * §7.2 STEP 8: check for webauthn.get
			 */
			pass("Authentication requested; type has expected value");
		} else {
			fail("AUTH requested, but did not receive webauthn.get.");
		}
		break;
	default:
		fail("Unexpected operation ".$operation );
	}
	/**
	 * §7.1 STEP 5 : check if incoming challenge matches issued challenge
         * §7.2 STEP 9 : check if incoming challenge matches issued challenge
	 */
	if ($state['FIDO2SignupChallenge'] == bin2hex(base64url_decode($clientData['challenge']))) {
		pass("Challenge matches");
	} else {
		fail("Challenge does not match");
	}
	/**
	 * §7.1 STEP 6 : check if incoming origin matches our hostname (taken from IdP metadata prefix)
	 * §7.2 STEP 10: check if incoming origin matches our hostname (taken from IdP metadata prefix)
	 */
	$expectedOrigin = substr($state['IdPMetadata']['entityid'],0,strpos($state['IdPMetadata']['entityid'],'/',8));
	if ($clientData['origin'] == $expectedOrigin) {
		pass("Origin matches");
	} else {
		fail("Origin does not match: ".$expectedOrigin);
	}
	/**
	 * §7.1 STEP 7 : optional tokenBinding check. The Yubikey does not make use of that option.
	 * §7.2 STEP 11: optional tokenBinding check. The Yubikey does not make use of that option.
	 */
	if (!isset($clientData['tokenBinding'])) {
	        pass("No optional token binding data to validate.");
	} else {
	        warn("Validation of the present token binding data not implemented, continuing without!");
	}
        /**
         * STEP 14 (clientData part) of the validation procedure in § 7.1 of the spec: we did not request any client extensions, so none are allowed to be present
         */
	if (!isset($clientData['clientExtensions']) || count($clientData['clientExtensions']) == 0) {
		pass("As expected, no client extensions.");
	} else {
		fail("Incoming client extensions even though none were requested.");
	}
	/**
	 * §7.1 STEP 8 : SHA-256 hashing the clientData
	 */
	return hash("sha256",$_POST['attestation_client_data_json'] );
};

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
 * @param array  $state              the current authentication state
 * @param string $authData           the authData / authenticatorData binary blob
 * @param string $requestedOperation "REG" or "AUTH"
 *
 * @return int the current counter value of the authenticator
 */
function validateAuthData($state, $authData, $requestedOperation) {
	/**
	 * §7.1 STEP 10: compare incoming RpId hash with expected value
	 * §7.2 STEP 12: compare incoming RpId hash with expected value
	 */
	if (bin2hex(substr($authData,0,32)) == hash("sha256",$state['FIDO2Scope'])) {
		pass("Relying Party hash correct.");
	} else {
		fail("Mismatching Relying Party hash.");
	}
	$bitfield = substr($authData,32,1);
        /**
         * §7.1 STEP 14 (authData part): no extensions were requested, so none are allowed to be present
         * §7.2 STEP 15 (authData part): no extensions were requested, so none are allowed to be present
         */
	if ((128 & ord($bitfield)) > 0) {
                        fail("ED: Extension Data Included, even though we did not request any.");
                } else {
                        pass("ED: Extension Data not present.");
                }
	switch ($requestedOperation) {
	case "REG":
	        if ((64 & ord($bitfield)) > 0) {
        		pass("AT: Attested Credential Data Included.");
		        } else {
        	fail("AT: not present, but required during registration.");
	        }
        	break;
	case "AUTH":
		if ((64 & ord($bitfield)) > 0) {
                        fail("AT: Attested Credential Data Included.");
                } else {
                	pass("AT: not present, like it should be during an authentication.");
                }
                break;

	default: fail("unknown type of operation!");
	}
	/** 
	 * §7.1 STEP 11 + 12 : check user presence (this implementation does not insist on verification currently)
	 * §7.2 STEP 13 + 14 : check user presence (this implementation does not insist on verification currently)
	 */
	if (((4 & ord($bitfield)) > 0) || ((1 & ord($bitfield)) > 0)) {
	pass("UV and/or UP indicated: User has token in his hands.");
	} else {
	fail("Neither UV nor UP asserted: user is possibly not present at computer.");
	}
	$counterBin = substr($authData,33,4);
	return intval(bin2hex($counterBin),16);
}
?>
