<?php

require_once(dirname(dirname(dirname(__DIR__))) . '/vendor/autoload.php');

use Lcobucci\JWT\Parser;
use SimpleSAML\Utils\Config as SSPConfig;
use SimpleSAML\Module\webauthn\WebAuthn\AAGUID;
use SimpleSAML\Module\webauthn\WebAuthn\WebAuthnRegistrationEvent;

if ($argc < 2) {
    throw new Exception(
        'No token specified for the metadata service. Please pass your own token as the first argument'
    );
}

$toc = file_get_contents('https://mds2.fidoalliance.org/?token=' . $argv[1]);

const YUBICO_CA = "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==";

$token = (new Parser())->parse($toc); // Parses from a string

$res = [];
foreach ($token->getClaim('entries') as $oneEntryObject) {
    $thisUrl = $oneEntryObject->url . "?token=" . $argv[1];
    $mdB64 = file_get_contents($thisUrl);
    $mdArray = json_decode(base64_decode($mdB64), true);
    if (isset($mdArray['aaguid']) && isset($mdArray['attestationRootCertificates'][0])) {
        $compressedAaguid = strtolower(str_replace('-', '', $mdArray['aaguid']));
        // we need C and O values for the attestation certificates. Extract those from the first root
        $x509 = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n" . $mdArray['attestationRootCertificates'][0] . "\n-----END CERTIFICATE-----");
        // print_r($x509);
        if (isset($x509['subject']['C']) && isset($x509['subject']['O'])) {
            $res[$compressedAaguid] = [
                "C"        => $x509['subject']['C'],
                "O"        => $x509['subject']['O'],
                "model"    => $mdArray['description'],
                "RootPEMs" => $mdArray['attestationRootCertificates'],
                "multi"    => null
            ];
        }
    }
}
// no Yubico nor Microsoft in the list? (2019-09-12)
// add those manually but this is REALLY bad news if the MDS does not have complete information
//     * Yubico values from: https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual#AAGUID_Valuesbu3ryn
//     * Microsoft values from: https://docs.microsoft.com/en-us/microsoft-edge/dev-guide/windows-integration/web-authentication

$res["fa2b99dc9e3942578f924a30d23c4118"] = [
    "C"        => "SE",
    "O"        => "Yubico AB",
    "model"    => "YubiKey 5 NFC",
    "RootPEMs" => [YUBICO_CA],
    "multi"    => null
];
$res["cb69481e8ff7403993ec0a2729a154a8"] = [
    "C"        => "SE",
    "O"        => "Yubico AB",
    "model"    => "YubiKey 5C/5C Nano/5 Nano",
    "RootPEMs" => [YUBICO_CA],
    "multi"    => null
];
$res["c5ef55ffad9a4b9fb580adebafe026d0"] = [
    "C"        => "SE",
    "O"        => "Yubico AB",
    "model"    => "YubiKey 5Ci",
    "RootPEMs" => [YUBICO_CA],
    "multi"    => null
];
$res["6028b017b1d44c02b4b3afcdafc96bb2"] = [
    "C"     => "US",
    "O"     => "Microsoft Corporation",
    "model" => "Windows Hello software authenticator",
    "multi" => null
];
$res["6e96969ea5cf4aad9b56305fe6c82795"] = [
    "C"     => "US",
    "O"     => "Microsoft Corporation",
    "model" => "Windows Hello VBS software authenticator",
    "multi" => null
];
$res["08987058cadc4b81b6e130de50dcbe96"] = [
    "C"     => "US",
    "O"     => "Microsoft Corporation",
    "model" => "Windows Hello hardware authenticator",
    "multi" => null
];
$res["9ddd1817af5a4672a2b93e3dd95000a9"] = [
    "C"     => "US",
    "O"     => "Microsoft Corporation",
    "model" => "Windows Hello VBS hardware authenticator",
    "multi" => null
];

file_put_contents(
    SSPConfig::getConfigDir() . '/' . AAGUID::AAGUID_CONFIG_FILE,
    json_encode($res, JSON_PRETTY_PRINT)
);
