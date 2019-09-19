FIDO2 as Second Factor module
==============

<!-- {{TOC}} -->


The module is implemented as an Authentication Processing Filter. That 
means it can be configured in the global config.php file or the SP remote or 
IdP hosted metadata.

How to setup the fido2SecondFactor module
-----------------------------------------
You need to enable and configure the module's authprocfilter at a priority level
so that it takes place AFTER the first-factor authentication. E.g. at 100:

100 => 
    ['class' => 'fido2SecondFactor:FIDO2SecondFactor',

    /* required configuration parameters */

        'store' => [
            'fido2SecondFactor:Database',
            'dsn' => 'mysql:host=db.example.org;dbname=fido2',
            'username' => 'simplesaml',
            'password' => 'sdfsdf',
        ],
        
    'attrib_username' => 'urn:oid:1.3.6.1.4.1.23735.100.0',
    'attrib_displayname' => 'urn:oid:2.5.4.3',

    /* optional configuration parameters */

    /* FIDO2 is phishing-resistent by binding generated credentials to a scope.
     * Browsers will only invoke the registration/authentication if the scope
     * matches the principal domain name the user is currently visiting.
     * If not specified, the scope will be the hostname of the IdP as per 
     * its metadata. It is permissible to widen the scope up to the prinicpal
     * domain though (e.g. authentication service is "saml.example.com" => scope
     * can be extended to "example.com"; but not "examp1e.com". A registered
     * FIDO2 token can then also be used on other servers in the same domain.
     * If configuring this item, be sure that the authentication server name and
     * the desired scope are a suffix match.
     */
    'scope' => 'example.com',

    /* the following will interactively ask the user if he is willing to share
     * manufacturer and model information during credential registration. 
     * The user can decline, in which case registration will still succeed but
     * vendor and model will be logged as "unknown model [unknown vendor]"
     *
     * When not requesting this, there is one less user interaction during the
     * registration process; and no model information will be saved.
     *
     * defaults to "false"
     */
    'request_tokenmodel' => true,

    /* should FIDO2 be enabled by default for all users? If not, users need to
     * be white-listed in the database - other users simply pass through the
     * filter without being subjected to 2FA.
     *
     * defaults to "disabled by default" === false
     */
    'default_enable' => false,

    ],

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
		fido2Status ENUM("FIDO2Disabled","FIDO2Enabled") NOT NULL DEFAULT "FIDO2Disabled",
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

    100 => array(
        'class'	=> 'fido2SecondFactor:FIDO2SecondFactor', 
        'store'	=> array(
            'fido2SecondFactor:Database', 
            'dsn' => 'pgsql:host=sql.example.org;dbname=fido2',
            'username' => 'simplesaml',
            'password' => 'sdfsdf',
        ),
    ),

Example config using MySQL database:

    100 => array(
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
`scope`
:    FIDO2 is phishing-resistent by binding generated credentials to a scope. Browsers will only invoke the registration/authentication if the scope matches the principal domain name the user is currently visiting. If not specified, the scope will be the hostname of the IdP as per its metadata. It is permissible to widen the scope up to the prinicpal domain though (e.g. authentication service is "saml.example.com" => scope can be extended to "example.com"; but not "examp1e.com". A registered FIDO2 token can then also be used on other servers in the same domain. If configuring this item, be sure that the authentication server name and the desired scope are a suffix match.

`request_tokenmodel`
:    The following will interactively ask the user if he is willing to share manufacturer and model information during credential registration. The user can decline, in which case registration will still succeed but vendor and model will be logged as "unknown model [unknown vendor]". When not requesting this, there is one less user interaction during the registration process; and no model information will be saved. Defaults to "false".
    
`default_enable`
:    Should FIDO2 be enabled by default for all users? If not, users need to be white-listed in the database - other users simply pass through the filter without being subjected to 2FA. Defaults to "disabled by default" === false    

Device model detection
----------------------
The option request_tokenmodel can be used to get a token's so-called AAGUID
which uniquely identifies the model and manufacturer (it is not a serial 
number). 

Mapping the AAGUID to a cleartext model and manufacturer name is done by having
(or not) meta-information about the AAGUID. The FIDO Alliance operates a
Metadata Service (MDS) which has a good number of AAGUIDs registered. However,
manufacturers are not required to submit their AAGUIDs and metadata to that MDS,
and indeed, some manufacturers are missing.

The module contains a full list of AAGUIDs and relevant metadata as pulled from
the FIDO MDS. It also has a limited amount of manually curated information of
some AAGUIDs which are not in the FIDO MDS, namely for Yubico products and 
Microsoft.

As a consequence, depending on the token model the user uses, even if the AAGUID
is being sent as part of the registration process, it may be that the device is
still stored as unknown model/unknown vendor.

I contacted FIDO Alliance to ask about the lack of complete information in their
MDS. Purportedly, listing in the MDS has chances of becoming mandatory in a
future FIDO Certification. Until then, there is no good solution to the problem.

Disabling FIDO2 Second Factor
-----------------------------
You can disable the module entirely by not listing it as an authprocfilter.

You can disable the module by default by setting default_enable = false. You can
then enable FIDO2 second-factor authentication for individual users by adding
them with status "FIDO2Enabled" to the fido2UserStatus table.

If the module is enabled by default, you can selectively disable FIDO second-
factor authentication by adding the username with status FIDO2Disabled to the
fido2UserStatus table.