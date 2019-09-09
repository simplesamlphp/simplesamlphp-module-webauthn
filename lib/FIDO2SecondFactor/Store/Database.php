<?php

namespace SimpleSAML\Module\fido2SecondFactor\FIDO2SecondFactor\Store;

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
class Database extends \SimpleSAML\Module\fido2SecondFactor\Store {

    /**
     * DSN for the database.
     */
    private $dsn;

    /**
     * The DATETIME SQL function to use
     */
    private $dateTime;

    /**
     * Username for the database.
     */
    private $username;

    /**
     * Password for the database;
     */
    private $password;

    /**
     * Options for the database;
     */
    private $options;

    /**
     * The timeout of the database connection.
     *
     * @var int|null
     */
    private $timeout = null;

    /**
     * Database handle.
     *
     * This variable can't be serialized.
     */
    private $db;

    /**
     * Parse configuration.
     *
     * This constructor parses the configuration.
     *
     * @param array $config Configuration for database consent store.
     *
     * @throws \Exception in case of a configuration error.
     */
    public function __construct($config) {
        parent::__construct($config);

        if (!array_key_exists('dsn', $config)) {
            throw new \Exception('fido2SecondFactor:Database - Missing required option \'dsn\'.');
        }
        if (!is_string($config['dsn'])) {
            throw new \Exception('fido2SecondFactor:Database - \'dsn\' is supposed to be a string.');
        }

        $this->dsn = $config['dsn'];
        $this->dateTime = (0 === strpos($this->dsn, 'sqlite:')) ? 'DATETIME("NOW")' : 'NOW()';

        if (array_key_exists('username', $config)) {
            if (!is_string($config['username'])) {
                throw new \Exception('fido2SecondFactor:Database - \'username\' is supposed to be a string.');
            }
            $this->username = $config['username'];
        } else {
            $this->username = null;
        }

        if (array_key_exists('password', $config)) {
            if (!is_string($config['password'])) {
                throw new \Exception('fido2SecondFactor:Database - \'password\' is supposed to be a string.');
            }
            $this->password = $config['password'];
        } else {
            $this->password = null;
        }

        if (array_key_exists('options', $config)) {
            if (!is_array($config['options'])) {
                throw new \Exception('fido2SecondFactor:Database - \'options\' is supposed to be an array.');
            }
            $this->options = $config['options'];
        } else {
            $this->options = null;
        }

        if (isset($config['timeout'])) {
            if (!is_int($config['timeout'])) {
                throw new \Exception('fido2SecondFactor:Database - \'timeout\' is supposed to be an integer.');
            }
            $this->timeout = $config['timeout'];
        }
    }

    /**
     * Called before serialization.
     *
     * @return array The variables which should be serialized.
     */
    public function __sleep() {
        return [
            'dsn',
            'dateTime',
            'username',
            'password',
            'timeout',
        ];
    }

    /**
     * is the user subject to 2nd factor at all?
     *
     * This function checks whether a given user has been enabled for FIDO2 second factor.
     *
     * @param string $userId        The hash identifying the user at an IdP.
     *
     * @return bool True if the user is enabled for 2FA, false if not
     */
    public function is2FAEnabled($userId) {
        assert(is_string($userId));

        $query = 'SELECT fido2Status FROM fido2UserStatus WHERE user_id = ?';

        $st = $this->execute($query, [$userId]);

        if ($st === false) {
            return false;
        }

        $rowCount = $st->rowCount();
        if ($rowCount === 0) {
            \SimpleSAML\Logger::debug('User does not exist in DB, default to 2FA DISABLED.');
            return false;
        } else {
            $query2 = 'SELECT fido2Status FROM fido2UserStatus WHERE user_id = ? AND fido2Status = "FIDO2Disabled"';
            $st2 = $this->execute($query2, [$userId]);
            $rowCount2 = $st2->rowCount();
            if ($rowCount2 === 1 /* explicitly disabled user in DB */) {
                return false;
            }
            \SimpleSAML\Logger::debug('User exists and is not disabled -> enabled.');
            return true;
        }
    }

    /**
     * enrolling a new FIDO2 token allowed?
     *
     * This function checks whether a given user has authorized the release of
     * the attributes identified by $attributeSet from $source to $destination.
     *
     * @param string $userId        The hash identifying the user at an IdP.
     *
     * @return bool True if the user is allowed to enroll, false if not
     */
    public function enrollAllowed($userId) {
        assert(is_string($userId));

        $query = 'SELECT fido2Status FROM fido2UserStatus WHERE user_id = ? AND fido2Status = "FIDO2EnrollEnabled"';

        $st = $this->execute($query, [$userId]);

        if ($st === false) {
            return false;
        }

        $rowCount = $st->rowCount();
        if ($rowCount === 1) {
            \SimpleSAML\Logger::debug('User is allowed to enroll.');
            return true;
        } else {
            $query2 = 'SELECT * from fido2SecondFactor WHERE user_id = ?';
            $st2 = $this->execute($query2, [$userId]);
            $rowCount2 = $st2->rowCount();
            $query3 = 'SELECT fido2Status FROM fido2UserStatus WHERE user_id = ? AND fido2Status = "FIDO2Enabled"';
            $st3 = $this->execute($query3, [$userId]);
            $rowCount3 = $st3->rowCount();
            if ($rowCount3 === 1 /* FIDO2 enabled */ && $rowCount2 === 0 /* no credentials yet */) {
                return true;
            }
            \SimpleSAML\Logger::debug('User is not allowed to enroll a new FIDO2 token.');
            return false;
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
    public function doesCredentialExist($credIdHex) {
        assert(is_string($userId));

        $query = 'SELECT credentialId FROM fido2SecondFactor ' .
                'WHERE credentialId = ?';

        $st = $this->execute($query, [$credIdHex]);

        if ($st === false) {
            return false;
        }

        $rowCount = $st->rowCount();
        if ($rowCount === 0) {
            \SimpleSAML\Logger::debug('Credential does not exist yet.');
            return false;
        } else {
            \SimpleSAML\Logger::debug('Credential exists.');
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
    public function storeTokenData($userId, $credentialId, $credential, $signCounter, $friendlyName) {
        assert(is_string($userId));

        $st = $this->execute(
                'INSERT INTO fido2SecondFactor ' .
                '(user_id, credentialId, credential, signCounter, friendlyName) VALUES (?,?,?,' . $signCounter . ',?)',
                [$userId, $credentialId, $credential, $friendlyName]
        );

        if ($st !== false) {
            \SimpleSAML\Logger::debug('fido2SecondFactor:Database - Saved enrollment data.');
        }

        $st2 = $this->execute(
                'UPDATE fido2UserStatus  ' .
                'SET fido2Status = ? WHERE user_id = ?',
                ["FIDO2Enabled", $userId]
        );

        if ($st2 !== false) {
            \SimpleSAML\Logger::debug('fido2SecondFactor:Database - downgraded user status to usage only, now that enrollment is complete.');
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
    public function updateSignCount($credentialId, $signCounter) {
        $st = $this->execute(
                'UPDATE fido2SecondFactor SET signCounter = ? WHERE credentialId = ?',
                [$signCounter, $credentialId]
        );

        if ($st !== false) {
            \SimpleSAML\Logger::debug('fido2SecondFactor:Database - UPDATED signature counter.');
        } else {
            throw new Exception("Database execution did not work.");
        }
        return true;
    }

    /**
     * Retrieve existing token data
     *
     * @param string $userId the username
     * @return array Array of all crypto data we have on file.
     */
    public function getTokenData($userId) {
        assert(is_string($userId));

        $ret = [];

        $st = $this->execute(
                'SELECT credentialId, credential, signCounter, friendlyName FROM fido2SecondFactor WHERE user_id = ?',
                [$userId]
        );

        if ($st === false) {
            return [];
        }

        while ($row = $st->fetch(\PDO::FETCH_NUM)) {
            $ret[] = $row;
        }

        return $ret;
    }

    /**
     * Prepare and execute statement.
     *
     * This function prepares and executes a statement. On error, false will be
     * returned.
     *
     * @param string $statement  The statement which should be executed.
     * @param array  $parameters Parameters for the statement.
     *
     * @return \PDOStatement|bool  The statement, or false if execution failed.
     */
    private function execute($statement, $parameters) {
        assert(is_string($statement));
        assert(is_array($parameters));

        $db = $this->getDB();
        if ($db === false) {
            return false;
        }

        $st = $db->prepare($statement);
        if ($st === false) {
            \SimpleSAML\Logger::error(
                    'consent:Database - Error preparing statement \'' .
                    $statement . '\': ' . self::formatError($db->errorInfo())
            );
            return false;
        }

        if ($st->execute($parameters) !== true) {
            \SimpleSAML\Logger::error(
                    'consent:Database - Error executing statement \'' .
                    $statement . '\': ' . self::formatError($st->errorInfo())
            );
            return false;
        }

        return $st;
    }

    /**
     * Get database handle.
     *
     * @return \PDO|false Database handle, or false if we fail to connect.
     */
    private function getDB() {
        if ($this->db !== null) {
            return $this->db;
        }

        $driver_options = [];
        if (isset($this->timeout)) {
            $driver_options[\PDO::ATTR_TIMEOUT] = $this->timeout;
        }
        if (isset($this->options)) {
            $this->options = array_merge($driver_options, $this->options);
        } else {
            $this->options = $driver_options;
        }

        $this->db = new \PDO($this->dsn, $this->username, $this->password, $this->options);

        return $this->db;
    }

    /**
     * Format PDO error.
     *
     * This function formats a PDO error, as returned from errorInfo.
     *
     * @param array $error The error information.
     *
     * @return string Error text.
     */
    private static function formatError($error) {
        assert(is_array($error));
        assert(count($error) >= 3);

        return $error[0] . ' - ' . $error[2] . ' (' . $error[1] . ')';
    }

}
