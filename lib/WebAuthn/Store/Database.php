<?php

namespace SimpleSAML\Module\webauthn\WebAuthn\Store;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\webauthn\Store;

/**
 * Store FIDO2 information in database.
 *
 * This class implements a store which stores the FIDO2 information in a
 * database. It is tested with MySQL, others might work, too.
 *
 * It has the following options:
 * - dsn: The DSN which should be used to connect to the database server. See
 *   the PHP Manual for supported drivers and DSN formats.
 * - username: The username used for database connection.
 * - password: The password used for database connection.
 *
 * @author Stefan Winter <stefan.winter@restena.lu>
 * @package SimpleSAMLphp
 */

class Database extends Store
{
    /**
     * Database handle.
     *
     * This variable can't be serialized.
     */
    private $db;


    /**
     * The configuration for our database store.
     *
     * @var array
     */
    private $config;


    /**
     * Parse configuration.
     *
     * This constructor parses the configuration.
     *
     * @param array $config Configuration for database consent store.
     *
     * @throws \Exception in case of a configuration error.
     */
    public function __construct(array $config)
    {
        parent::__construct($config);
        $this->config = $config;
        $this->db = \SimpleSAML\Database::getInstance(Configuration::loadFromArray($config));
    }

    /**
     * Called before serialization.
     *
     * @return array The variables which should be serialized.
     */
    public function __sleep(): array
    {
        return [
            'config',
        ];
    }


    /**
     * Called after unserialization.
     * @return void
     */
    public function __wakeup(): void
    {
        $this->db = \SimpleSAML\Database::getInstance(Configuration::loadFromArray($this->config));
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
    public function is2FAEnabled(string $userId, bool $defaultIfNx): bool
    {
        $st = $this->db->read('SELECT fido2Status FROM userstatus WHERE user_id = :userId', ['userId' => $userId]);

        if ($st === false) {
            return false;
        }

        $rowCount = $st->rowCount();
        if ($rowCount === 0) {
            Logger::debug('User does not exist in DB, returning desired default.');
            return $defaultIfNx;
        } else {
            $st2 = $this->db->read(
                'SELECT fido2Status FROM userstatus WHERE user_id = :userId AND fido2Status = "FIDO2Disabled"',
                ['userId' => $userId]
            );
            $rowCount2 = $st2->rowCount();
            if ($rowCount2 === 1 /* explicitly disabled user in DB */) {
                return false;
            }
            Logger::debug('User exists and is not disabled -> enabled.');
            return true;
        }
    }


    /**
     * does a given credentialID already exist?
     *
     * This function checks whether a given credential ID already exists in the database
     *
     * @param string $credIdHex The hex representation of the credentialID to look for.
     *
     * @return bool True if the credential exists, false if not
     */
    public function doesCredentialExist(string $credIdHex): bool
    {
        $st = $this->db->read(
            'SELECT credentialId FROM credentials WHERE credentialId = :credentialId',
            ['credentialId' => $credIdHex]
        );

        if ($st === false) {
            return false;
        }

        $rowCount = $st->rowCount();
        if ($rowCount === 0) {
            Logger::debug('Credential does not exist yet.');
            return false;
        } else {
            Logger::debug('Credential exists.');
            return true;
        }
    }


    /**
     * store newly enrolled token data
     *
     * @param string $userId        The user.
     * @param string $credentialId  The id identifying the credential.
     * @param string $credential    The credential.
     * @param int    $signCounter   The signature counter for this credential.
     * @param string $friendlyName  A user-supplied name for this token.
     *
     * @return true
     */
    public function storeTokenData(
        string $userId,
        string $credentialId,
        string $credential,
        int $signCounter,
        string $friendlyName
    ): bool {
        $st = $this->db->write(
            'INSERT INTO credentials ' .
            '(user_id, credentialId, credential, signCounter, friendlyName) VALUES (:userId,:credentialId,' .
            ':credential,:signCounter,:friendlyName)',
            [
                'userId' => $userId,
                'credentialId' => $credentialId,
                'credential' => $credential,
                'signCounter' => $signCounter,
                'friendlyName' => $friendlyName
            ]
        );

        if ($st === false) {
            throw new \Exception("Unable to save new token in database!");
        }

        return true;
    }


    /**
     * remove an existing credential from the database
     *
     * @param string $credentialId the credential
     * @return true
     */
    public function deleteTokenData(string $credentialId): bool
    {
        $st = $this->db->write(
            'DELETE FROM credentials WHERE credentialId = :credentialId',
            ['credentialId' => $credentialId]
        );

        if ($st !== false) {
            Logger::debug('webauthn:Database - DELETED credential.');
        } else {
            throw new \Exception("Database execution did not work.");
        }
        return true;
    }


    /**
     * increment the signature counter after a successful authentication
     *
     * @param string $credentialId the credential
     * @param int    $signCounter  the new counter value
     * @return true
     */
    public function updateSignCount(string $credentialId, int $signCounter): bool
    {
        $st = $this->db->write(
            'UPDATE credentials SET signCounter = :signCounter WHERE credentialId = :credentialId',
            ['signCounter' => $signCounter, 'credentialId' => $credentialId]
        );

        if ($st !== false) {
            Logger::debug('webauthn:Database - UPDATED signature counter.');
        } else {
            throw new \Exception("Database execution did not work.");
        }
        return true;
    }


    /**
     * Retrieve existing token data
     *
     * @param string $userId the username
     * @return array Array of all crypto data we have on file.
     */
    public function getTokenData(string $userId): array
    {
        $ret = [];

        $st = $this->db->read(
            'SELECT credentialId, credential, signCounter, friendlyName FROM credentials WHERE user_id = :userId',
            ['userId' => $userId]
        );

        if ($st === false) {
            return [];
        }

        while ($row = $st->fetch(\PDO::FETCH_NUM)) {
            $ret[] = $row;
        }

        return $ret;
    }
}
