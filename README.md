WebAuthn as Second Factor module
==============

<!-- {{TOC}} -->


The module is implemented as an Authentication Processing Filter. That 
means it can be configured in the global config.php file or the SP remote or 
IdP hosted metadata.

Installation
------------

You can install this module with composer:

```bash
% composer require simplesamlphp/simplesamlphp-module-webauthn
```


How to setup the webauthn module
-----------------------------------------
You need to enable the module's authprocfilter at a priority level
so that it takes place AFTER the first-factor authentication. E.g. at 100 and
if standalone registration and name2oid are used together, then the WebAuthn
 auth proc filter has to run after name2oid.

```php
100 => [
        'class' => 'webauthn:WebAuthn',
    ],
```
Then you need to copy config-templates/module_webauthn.php to your config directory
 and adjust settings accordingly. See the file for parameters description.

Using storage
-------------

You first need to setup the database. 

Here is the initialization SQL script:

```sql
CREATE TABLE credentials (
    creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(80) NOT NULL,
    credentialId VARCHAR(500) NOT NULL,
    credential MEDIUMBLOB NOT NULL,
    signCounter INT NOT NULL,
    friendlyName VARCHAR(100) DEFAULT "Unnamed Token",
    UNIQUE (user_id,credentialId)
);

GRANT SELECT,INSERT,UPDATE,DELETE ON ...credentials TO '...dbuser'@'1.2.3.4' IDENTIFIED BY '...dbpass';

CREATE TABLE userstatus (
    user_id VARCHAR(80) NOT NULL,
    fido2Status ENUM("FIDO2Disabled","FIDO2Enabled") NOT NULL DEFAULT "FIDO2Disabled",
    UNIQUE (user_id)
);

GRANT SELECT ON ...userstatus TO '...dbuser'@'1.2.3.4' IDENTIFIED BY '...dbpass';
```

The `webauthn:Database` backend storage has the following options:

`class`
:   Must be set to `webauthn:Database`.

`database.dsn`
:   Data Source Name must comply to the syntax for the PHP PDO layer.

`database.username`
:   Username for the database user to be used for the connection.

`database.password`
:   Password for the database user used for the connection.

`timeout`
:   The number of seconds to wait for a connection to the database server. This option is optional. If unset, it uses the default from the database-driver.

Example config using PostgreSQL database:

```php
    100 => array(
        'class'	=> 'webauthn:WebAuthn', 
        'store'	=> array(
            'webauthn:Database', 
            'database.dsn' => 'pgsql:host=sql.example.org;dbname=fido2',
            'database.username' => 'simplesaml',
            'database.password' => 'sdfsdf',
        ),
    ),
```

Example config using MySQL database:

```php
    100 => array(
        'class'	=> 'webauthn:WebAuthn', 
        'store'	=> array(
            'webauthn:Database', 
            'database.dsn' => 'mysql:host=db.example.org;dbname=fido2',
            'database.username' => 'simplesaml',
            'database.password' => 'sdfsdf',
        ),
    ),
```

Options
-------
`scope`
:    FIDO2 is phishing-resistent by binding generated credentials to a scope. Browsers will only invoke the registration/authentication if the scope matches the principal domain name the user is currently visiting. If not specified, the scope will be the hostname of the IdP as per its metadata. It is permissible to widen the scope up to the prinicpal domain though (e.g. authentication service is "saml.example.com" => scope can be extended to "example.com"; but not "examp1e.com". A registered FIDO2 token can then also be used on other servers in the same domain. If configuring this item, be sure that the authentication server name and the desired scope are a suffix match.

`request_tokenmodel`
:    The following will interactively ask the user if he is willing to share manufacturer and model information during credential registration. The user can decline, in which case registration will still succeed but vendor and model will be logged as "unknown model [unknown vendor]". When not requesting this, there is one less user interaction during the registration process; and no model information will be saved. Defaults to "false".
    
`default_enable`
:    Should WebAuthn be enabled by default for all users? If not, users need to be white-listed in the database - other users simply pass through the filter without being subjected to 2FA. Defaults to "disabled by default" === false    

`force`
:    This parameter is used only if "use_database" is false. If the value of "force" is true then we trigger WebAuthn only if "attrib_toggle" from the user is not empty. If the value of "force" is false then we switch the value of "default_enable" only if "attrib_toggle" from the user is not empty. Default value is true.

`attrib_toggle`
:    This parameter stores the name of the attribute that is sent with user and which determines whether to trigger WebAuthn. Default value is 'toggle'.

`use_database`
:    This parameter determines if the database will be used to check whether to trigger second factor authentication or use the "attrib_toggle" instead. Default value of this attribute is true.

`use_inflow_registration`
:    Optional parameter which determines whether you will be able to register and manage tokens while authenticating or you want to use the standalone registration page for these purposes. If set to false => standalone registration page, if true => inflow registration. If this parameter is not explicitly set, the value is considered to be true.

User Experience / Workflow
--------------------------
Users for which WebAuthn is enabled cannot continue without a FIDO2 token. The
UI is different depending on the number of tokens the user has registered:

- User has 0 tokens: UI requires the user to register a token. The user can 
  choose a convenient name for the token to recognise it later. If 
  request_tokenmodel is set, the name will be appended with the token model and
  vendor. 
  After successful registration, the authprocfilter is done (user continues to 
  SP)
- User has 1 token: UI requires the user to authenticate. After the 
  authentication, user can optionally enroll another token.
- User has 2+ tokens: UI requires the user to authenticate. After the 
  authentication, user can optionally enroll another token or delete an obsolete
  one.

If a user is enabled but has forgotten all of his tokens, the person would need
to contact his administrator and have his account temporarily disabled for two-
factor authentication.

As long as a user account has 0 tokens there is no benefit yet; it's effectively
still single factor authentication because anyone with the user's password can 
register any token. That is in the nature of things. It could be avoided with
an out-of-band registration process (in the same scope).

If the standalone registration page is used, the user can't optionally enroll and manage tokens while logging in.
The standalone registration page can be found under webauthn/registration.php, it requires authentication
and after that you are redirected to a page where you can manage tokens.

Device model detection
----------------------
The option `request_tokenmodel` can be used to get a token's so-called AAGUID
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
Microsoft. This list is in the `config/webauthn-aaguid.json` file, and this file
needs to be moved to your SimpleSAMLphp configuration directory.

If you want, you can also manually update this file, if you believe there might
be new models listed. In order to do that, run the `bin/updateMetadata.php` script
like this:

```bash
% php bin/updateMetadata.php <MDS_TOKEN>
```

where `MDS_TOKEN` is the API token you get after registering
[here](https://mds2.fidoalliance.org).

As a consequence, depending on the token model the user uses, even if the AAGUID
is being sent as part of the registration process, it may be that the device is
still stored as unknown model/unknown vendor.

I contacted FIDO Alliance to ask about the lack of complete information in their
MDS. Purportedly, listing in the MDS has chances of becoming mandatory in a
future FIDO Certification. Until then, there is no good solution to the problem.

Disabling WebAuthn
------------------
You can disable the module entirely by not listing it as an authprocfilter.

You can disable the module by default by setting default_enable = false. You can
then enable WebAuthn second-factor authentication for individual users by adding
them with status "FIDO2Enabled" to the `userstatus` table or if you don't want to
use the `userstatus` table, you can send an attribute whose name is stored in `attrib_toggle`
for this.

If the module is enabled by default, you can selectively disable WebAuthn 
second-factor authentication by adding the username with status FIDO2Disabled to
the `userstatus` table or if you don't want to use the `userstatus` table, you can
send an attribute whose name is stored in `attrib_toggle` for this.

Limitations / Design Decisions
------------------------------
This implementation does not validate token bindings, if sent by the 
authenticator (§7.1 Step 7 / §7.2 Step 11 skip token binding information 
validation if present). That is because Yubikeys do not support token binding 
and the corresponding functionality thus has no test case.

This implementation does not distinguish between User Presence (user has proven
to be near the authenticator) and User Verification (user has proven to be near
the authenticator AND to have unlocked the authenticator with a personal asset
such as PIN or fingerprint). Both variants are considered sufficient to 
authenticate successfully (§7.1 steps 11 and 12 are joined into one condition)

The implementation requests ECDSA keys (algorithm -7) because all Yubikeys 
support that. It is trivial to add RSA support if there are keys which don't.

The implementation does not request any client extensions. The specification
gives implementations a policy choice on what to do if a client sends extensions
anyway: this implementation chose to then fail the registration/authentication.

The implementation supports the attestation formats "none", "packed / x5c" and
"packed / self", and "fido-u2f". Other attestation formats lead to a 
registration failure.

For the attation type "packed / x5c", 
* the optional OCSP checks are not performed (this is explicitly permitted in 
  the spec due to other means of revocation checking in the FIDO MDS).

For bith "packed / x5c" and "fido-u2f":
* due to the lack of any externally provided knowledge about CAs(???) all
  attestations are classified as "Basic" (i.e. no "AttCA" level)

Given the sorry state of completeness of the FIDO MDS, only very few attestation
root CAs are known and validation as per §7.1 Step 18 would often fail. That
step is therefore ignored. All the "None", "Self" and "Basic" attestation levels
are considered acceptable; meaning §7.1 Step 21 does not apply.

If the implementation detects signs of physical object cloning (not incremented
signature counter), it follows the policy of failing authentication.
