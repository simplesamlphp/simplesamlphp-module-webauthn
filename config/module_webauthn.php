<?php

$config = [		'store' => [
			'webauthn:Database',
			'database.dsn' => 'mysql:host=localhost;dbname=fido2',
			'database.username' => 'webauthn',
			'database.password' => 'password',
			],
			
		'attrib_username' => 'uid',
		'attrib_displayname' => 'displayName',
		'scope' => 'ip-78-128-251-71.flt.cloud.muni.cz',
		'request_tokenmodel' => true,
		'default_enable' => false,
		'force' => false,
		'attrib_toggle' => 'toggle',
		'use_database' => false,
        'use_inflow_registration' => false,
		];
