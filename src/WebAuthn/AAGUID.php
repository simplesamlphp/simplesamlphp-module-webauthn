<?php

declare(strict_types=1);

namespace SimpleSAML\Module\webauthn\WebAuthn;

use SimpleSAML\Logger;
use SimpleSAML\Utils\Config as SSPConfig;

/**
 * Class AAGUID
 *
 * @package SimpleSAML\Module\webauthn\WebAuthn
 */
class AAGUID
{
    /**
     * The name of the configuration file where we should expect the AAGUID dictionary.
     */
    public const AAGUID_CONFIG_FILE = 'webauthn-aaguid.json';


    /**
     * The actual dictionary containing all known tokens.
     *
     * @var array
     */
    protected array $dictionary = [];

    /**
     * The singleton instance.
     *
     * @var \SimpleSAML\Module\webauthn\WebAuthn\AAGUID
     */
    protected static AAGUID $instance;


    /**
     * AAGUID constructor.
     */
    protected function __construct()
    {
        $config = new SSPConfig();
        $path = $config->getConfigDir() . '/' . self::AAGUID_CONFIG_FILE;
        if (!file_exists($path)) {
            Logger::warning("Missing AAGUID configuration file ($path). No device will be recognized.");
            return;
        }

        $data = file_get_contents($path);
        $json = json_decode($data, true);
        if (!is_array($json)) {
            // there was probably an error decoding the config, log the error and pray for the best
            Logger::warning('Broken configuration file "' . $path . '": could not JSON-decode it.');
        } else {
            $this->dictionary = $json;
        }
    }


    /**
     * Get the singleton instance of the AAGUID dictionary.
     *
     * @return self
     */
    public static function getInstance(): self
    {
        if (!isset(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }


    /**
     * Determine if an AAGUID is known
     *
     * @param string $aaguid The AAGUID that we want to check.
     *
     * @return bool True if we know about this token, false otherwise.
     */
    public function hasToken(string $aaguid): bool
    {
        $lowerAaguid = strtolower($aaguid);
        if (array_key_exists($lowerAaguid, $this->dictionary)) {
            return true;
        } else {
            Logger::info("AAGUID $lowerAaguid not found in dictionary, device is unknown.");
            return false;
        }
    }


    /**
     * Get the information for a given AAGUID.
     *
     * @param string $aaguid The AAGUID we want to get.
     *
     * @return array An array containing information about the given AAGUID, or an empty array if that AAGUID is
     * unknown.
     */
    public function get(string $aaguid): array
    {
        if (!$this->hasToken($aaguid)) {
            return [];
        }
        return $this->dictionary[$aaguid];
    }
}
