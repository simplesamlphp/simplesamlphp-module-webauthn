FIDO2 as Second Factor module
==============

<!-- {{TOC}} -->


The module is implemented as an Authentication Processing Filter. That 
means it can be configured in the global config.php file or the SP remote or 
IdP hosted metadata.

  * [Read more about processing filters in SimpleSAMLphp](simplesamlphp-authproc)


How to setup the fido2SecondFactor module
-----------------------------------------

Using storage
-------------

You first need to setup the database. 

Here is the initialization SQL script:

	CREATE TABLE fido2SecondFactor (
		creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		user_id VARCHAR(80) NOT NULL,
		credentialId VARCHAR(800) NOT NULL,
		credential MEDIUMBLOB NOT NULL,
		signCounter INT NOT NULL,
		friendlyName VARCHAR(100) DEFAULT "Unnamed Token",
		UNIQUE (user_id,credentialId)
	);

	CREATE TABLE fido2UserStatus (
                user_id VARCHAR(80) NOT NULL,
		fido2Status ENUM("FIDO2Disabled","FIDO2Enabled","FIDO2EnrollEnabled") NOT NULL DEFAULT "FIDO2Disabled",
		fido2PendingChallenge VARCHAR(128) DEFAULT NULL,
		UNIQUE (user_id)
	);

The `fido2SecondFactor:Database` backend storage has the following options:

`class`
:   Must be set to `fido2SecondFactor:Database`.

`dsn`
:   Data Source Name must comply to the syntax for the PHP PDO layer.

`username`
:   Username for the database user to be used for the connection.

`password`
:   Password for the database user used for the connection.

`timeout`
:   The number of seconds to wait for a connection to the database server. This option is optional. If unset, it uses the default from the database-driver.

Example config using PostgreSQL database:

    90 => array(
        'class'	=> 'fido2SecondFactor:FIDO2SecondFactor', 
        'store'	=> array(
            'fido2SecondFactor:Database', 
            'dsn' => 'pgsql:host=sql.example.org;dbname=fido2',
            'username' => 'simplesaml',
            'password' => 'sdfsdf',
        ),
    ),

Example config using MySQL database:

    90 => array(
        'class'	=> 'fido2SecondFactor:FIDO2SecondFactor', 
        'store'	=> array(
            'fido2SecondFactor:Database', 
            'dsn' => 'mysql:host=db.example.org;dbname=fido2',
            'username' => 'simplesaml',
            'password' => 'sdfsdf',
        ),
    ),


Options
-------

External options
----------------

Disabling FIDO2 Second Factor
-----------------------------
