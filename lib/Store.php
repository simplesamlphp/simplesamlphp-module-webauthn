<?php

namespace SimpleSAML\Module\webauthn;

use Exception;
use SimpleSAML\Module;
use SimpleSAML\Utils;

/**
 * Base class for consent storage handlers.
 *
 * @package SimpleSAMLphp
 * @author Olav Morken <olav.morken@uninett.no>
 * @author JAcob Christiansen <jach@wayf.dk>
 */

abstract class Store
{
    /**
     * Constructor for the base class.
     *
     * This constructor should always be called first in any class which implements this class.
     *
     * @param array &$config The configuration for this storage handler.
     */
    protected function __construct(array &$config)
    {
    }

    /**
     * is the user subject to 2nd factor at all?
     *
     * This function checks whether a given user has been enabled for WebAuthn.
     *
     * @param string $userId        The hash identifying the user at an IdP.
     * @param bool   $defaultIfNx   if not found in the DB, should the user be considered enabled (true)
     *                              or disabled(false)
     *
     * @return bool True if the user is enabled for 2FA, false if not
     */
    abstract public function is2FAEnabled(string $userId, bool $defaultIfNx): bool;

    /**
     * does a given credentialID already exist?
     *
     * This function checks whether a given credential ID already exists in the database
     *
     * @param string $credIdHex The hex representation of the credentialID to look for.
     *
     * @return bool True if the credential exists, false if not
     */
    abstract public function doesCredentialExist(string $credIdHex): bool;

    /**
     * store newly enrolled token data
     *
     * @param string $userId        The user.
     * @param string $credentialId  The id identifying the credential.
     * @param string $credential    The credential.
     * @param int    $signCounter   The signature counter for this credential.
     * @param string $friendlyName  A user-supplied name for this token.
     *
     * @return bool
     */
    abstract public function storeTokenData(string $userId, string $credentialId, string $credential, int $signCounter, string $friendlyName): bool;

    /**
     * remove an existing credential from the database
     *
     * @param string $credentialId the credential
     * @return true
     */
    abstract public function deleteTokenData(string $credentialId): bool;

    /**
     * increment the signature counter after a successful authentication
     *
     * @param string $credentialId the credential
     * @param int    $signCounter  the new counter value
     * @return true
     */
    abstract public function updateSignCount(string $credentialId, int $signCounter): bool;

    /**
     * Retrieve existing token data
     *
     * @param string $userId the username
     * @return array Array of all crypto data we have on file.
     */
    abstract public function getTokenData(string $userId): array;

    /**
     * Get statistics for all consent given in the consent store
     *
     * @return mixed Statistics from the consent store
     *
     * @throws \Exception
     */
    public function getStatistics()
    {
        throw new Exception('Not implemented: getStatistics()');
    }


    /**
     * Parse consent storage configuration.
     *
     * This function parses the configuration for a consent storage method. An exception will be thrown if
     * configuration parsing fails.
     *
     * @param mixed $config The configuration.
     *
     * @return \SimpleSAML\Module\webauthn\Store An object which implements the \SimpleSAML\Module\webauthn\Store class.
     *
     * @throws \Exception if the configuration is invalid.
     */
    public static function parseStoreConfig($config): Store
    {
        if (is_string($config)) {
            $config = Utils\Arrays::arrayize($config);
        }

        if (!is_array($config)) {
            throw new Exception('Invalid configuration for consent store option: ' . var_export($config, true));
        }

        if (!array_key_exists(0, $config)) {
            throw new Exception('Consent store without name given.');
        }

        $className = Module::resolveClass(
            $config[0],
            'WebAuthn\Store',
            '\SimpleSAML\Module\webauthn\Store'
        );
//        unset($config[0]);

        /** @psalm-suppress InvalidStringClass */
        return new $className($config);
    }
}
