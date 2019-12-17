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
     * @param string $userId The hash identifying the user at an IdP.
     * @param bool $defaultIfNx if not found in the DB, should the user be considered enabled (true)
     *                              or disabled(false)
     * @param bool $useDatabase a bool that determines whether to use local database or not
     * @param bool $toggle variable which is associated with $force because it determines its meaning, it either
     *                     simply means whether to trigger webauthn authentication or switch the default settings,
     * @param bool $force switch that determines how $toggle will be used, if true then value of $toggle
     *                    will mean whether to trigger (true) or not (false) the webauthn authentication,
     *                    if false then $toggle means whether to switch the value of $defaultEnabled and then use that
     *
     * @return bool True if the user is enabled for 2FA, false if not
     */
    public function is2FAEnabled(
        string $userId,
        bool $defaultIfNx,
        bool $useDatabase = true,
        bool $toggle = false,
        bool $force = true
    ): bool {
        if (!$useDatabase) {
            if ($force) {
                return $toggle;
            } else {
                return $toggle ? !$defaultIfNx : $defaultIfNx;
            }
        }
        $st = $this->db->read('SELECT COUNT(*) FROM userstatus WHERE user_id = :userId', ['userId' => $userId]);

        $c = $st->fetchColumn();
        if ($c == 0) {
            Logger::debug('User does not exist in DB, returning desired default.');
            return $defaultIfNx;
        } else {
            $st2 = $this->db->read(
                'SELECT COUNT(*) FROM userstatus WHERE user_id = :userId AND fido2Status = "FIDO2Disabled"',
                ['userId' => $userId]
            );
            $rowCount2 = $st2->fetchColumn();
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
            'SELECT COUNT(*) FROM credentials WHERE credentialId = :credentialId',
            ['credentialId' => $credIdHex]
        );

        $rowCount = $st->fetchColumn();
        if (!$rowCount) {
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

        Logger::debug('webauthn:Database - DELETED credential.');

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

        Logger::debug('webauthn:Database - UPDATED signature counter.');

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

        while ($row = $st->fetch(\PDO::FETCH_NUM)) {
            $ret[] = $row;
        }

        return $ret;
    }
}
