#!/usr/bin/php
<?php

declare(strict_types=1);

if (!isset($argv[1])) {
    // phpcs:ignore Generic.Files.LineLength.TooLong
    echo "First and only argument is the filename of the FIDO Alliance Metadata v3 blob as can be downloaded from: https://mds3.fidoalliance.org/ \n";
    exit(1);
}
$token = file_get_contents($argv[1]);
$blobContent = json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', explode('.', $token)[1]))), true);
$outFormat = [];
foreach ($blobContent['entries'] as $oneEntry) {
    if (isset($oneEntry['aaguid'])) {
        $outFormat[str_replace('-', '', $oneEntry['aaguid'])] = $oneEntry;
    }
}
echo json_encode($outFormat, JSON_PRETTY_PRINT);
