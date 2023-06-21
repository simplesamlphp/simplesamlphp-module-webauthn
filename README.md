# WebAuthn as Second Factor module

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-webauthn/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-webauthn/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-webauthn)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-webauthn/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-webauthn/?branch=master)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-webauthn/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-webauthn)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-webauthn/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-webauthn)

<!-- {{TOC}} -->

The module is implemented as an Authentication Processing Filter. That
means it can be configured in the global config.php file or the SP remote or
IdP hosted metadata.

## Installation

You can install this module with composer:

```bash
% composer require simplesamlphp/simplesamlphp-module-webauthn
```

If you are using PHP 7, you also need to install either the GMP extension (recommended) or the BCMath extension.

## How to setup the webauthn module as an authprocfilter

You need to enable the module's authprocfilter at a priority level
so that it takes place AFTER the first-factor authentication. E.g. at 100 and
if standalone registration and name2oid are used together, then the WebAuthn
auth proc filter has to run after name2oid.

The authproc filter takes a number of optional parameter that steer which users
will be forced into 2FA.

```php
100 => [
    'class' => 'webauthn:WebAuthn',

    /* should FIDO2 be enabled by default for all users? If not, users need to
     * be white-listed in the database - other users simply pass through the
     * filter without being subjected to 2FA.
     *
     * defaults to "disabled by default" === false
     */
    'default_enable' => false,

    /* only if default_enable is false:
     * the toggle to turn on 2FA can either be a database lookup in the module's
     * internal database or be dependent on the existence or absence of a
     * user attribute as retrieved in the first-factor auth. The following
     * options control which variant to use.
     */

    /*
     * this parameter determines if the database will be used to check
     * whether to trigger second factor authentication or use the "attrib_toggle" instead.
     * Default value of this attribute is true
     */
    'use_database' => true,

    /* this parameter is used only if "use_database" is false. If the value of
     * "force" is true then we trigger WebAuthn only if "attrib_toggle" from the
     * user is not empty. If the value of "force" is false then we switch the value of
     * "default_enable" only if "attrib_toggle" from the user is not empty.
     * Default falue is true.
     */
    'force' => true,

    /* this parameter stores the name of the attribute that is sent with user and which
     * determines whether to trigger WebAuthn.
     * Default value is 'toggle'
     */
    'attrib_toggle' => 'toggle',

    /**
     * The module can be configured to assert that MFA was executed towards the
     * SP by setting an appropriate <AuthnContextClassRef> tag in the response.
     * The original SAML 2.0 spec in that regard contains only contexts which
     * are rather useless in a FIDO2 context.
     *
     * FIDO alliance has its own to indicate that a FIDO key was used, and it
     * is the default if unset. The semantics does not indicate then that an
     * additional authentication besides the FIDO key was used (i.e. your
     * first-factor authsource authentication). Thus, you may want to consider
     * setting the more accurate REFEDS identifier below instead.
     *
     * Defaults to 'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO' if not set
     *
     * If you authenticate towards Microsoft 365 SPs which may trigger their
     * own variant of 2FA, then you can tell them to skip this by
     * - setting the SP tenant parameter "supportsMFA" to "true"
     * - returning the AuthnContextClassRef
     *   "http://schemas.microsoft.com/claims/multipleauthn"
     */

    // 'authncontextclassref' => 'https://refeds.org/profile/mfa',
],
```

Then you need to copy config-templates/module_webauthn.php to your config directory
and adjust settings accordingly. See the file for parameters description.

## How to set up Passwordless authentication

In passwordless mode, the module provides an AuthSource, to be configured as
usual in simpleSAMLphp's config/authsources.php

Users' FIDO2 Keys need to be registered with the "Passwordless" checkbox set -
this triggers the mandatory registration with a second factor intrinsic to the
key (fingerprint, face recognition, transaction PIN, etc. ).

This authsource takes little configuration because authentications happen before
the username is known - so no user-specific configuration is possible.

The authsource takes the following parameters in authsources.php:

```php
'name-your-source' => [
    'webauthn:Passwordless',
    /*
     * Defaults to 'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO' if not set
     *
     * If you authenticate towards Microsoft 365 SPs which may trigger their
     * own variant of 2FA, then you can tell them to skip this by
     * - setting the SP tenant parameter "supportsMFA" to "true"
     * - returning the AuthnContextClassRef
     *   "http://schemas.microsoft.com/claims/multipleauthn"
     */

    // 'authncontextclassref' => 'https://refeds.org/profile/mfa',
],
```

## Using storage

The database schema sets itself up on first use automatically. The schema can be
found in the sources at src/WebAuthN/Store/Database.php (\_\_construct).

If you want to trim down permissions for the database user, here is the minimal
set of required permissions:

```sql

GRANT SELECT,INSERT,UPDATE,DELETE ON ...credentials TO '...dbuser'@'1.2.3.4' IDENTIFIED BY '...dbpass';


GRANT SELECT ON ...userstatus TO '...dbuser'@'1.2.3.4' IDENTIFIED BY '...dbpass';
```

The `webauthn:Database` backend storage has the following options:

`class`
: Must be set to `webauthn:Database`.

`database.dsn`
: Data Source Name must comply to the syntax for the PHP PDO layer.

`database.username`
: Username for the database user to be used for the connection.

`database.password`
: Password for the database user used for the connection.

`timeout`
: The number of seconds to wait for a connection to the database server. This option is optional. If unset, it uses the default from the database-driver.

Example config using PostgreSQL database:

```php
100 => [
    'class' => 'webauthn:WebAuthn',
    'store' => [
        'webauthn:Database',
        'database.dsn' => 'pgsql:host=sql.example.org;dbname=fido2',
        'database.username' => 'simplesaml',
        'database.password' => 'sdfsdf',
    ],
],
```

Example config using MySQL database:

```php
100 => [
    'class' => 'webauthn:WebAuthn',
    'store' => [
        'webauthn:Database',
        'database.dsn' => 'mysql:host=db.example.org;dbname=fido2',
        'database.username' => 'simplesaml',
        'database.password' => 'sdfsdf',
    ],
],
```

## Options

`scope`
: FIDO2 is phishing-resistent by binding generated credentials to a scope. Browsers will only invoke the registration/authentication if the scope matches the principal domain name the user is currently visiting. If not specified, the scope will be the hostname of the IdP as per its metadata. It is permissible to widen the scope up to the prinicpal domain though (e.g. authentication service is "saml.example.com" => scope can be extended to "example.com"; but not "examp1e.com". A registered FIDO2 token can then also be used on other servers in the same domain. If configuring this item, be sure that the authentication server name and the desired scope are a suffix match.

`default_enable`
: Should WebAuthn be enabled by default for all users? If not, users need to be white-listed in the database - other users simply pass through the filter without being subjected to 2FA. Defaults to "disabled by default" === false

`force`
: This parameter is used only if "use_database" is false. If the value of "force" is true then we trigger WebAuthn only if "attrib_toggle" from the user is not empty. If the value of "force" is false then we switch the value of "default_enable" only if "attrib_toggle" from the user is not empty. Default value is true.

`attrib_toggle`
: This parameter stores the name of the attribute that is sent with user and which determines whether to trigger WebAuthn. Default value is 'toggle'.

`use_database`
: This parameter determines if the database will be used to check whether to trigger second factor authentication or use the "attrib_toggle" instead. Default value of this attribute is true.

`registration / use_inflow_registration`
: Optional parameter which determines whether you will be able to register and manage tokens while authenticating or you want to use the standalone registration page for these purposes. If set to false => standalone registration page, if true => inflow registration. If this parameter is not explicitly set, the value is considered to be true.

`registration / auth_source`
: Optional parameter to define how the user authenticates to the dedicated registration page. Defaults to "default-sp"; ignored if inflow registration was configured.

`registration / minimum_certification_level`
`registration / aaguid_whitelist`
`registration / attestation_format_whitelist`
: These options steer which authenticators are considered acceptable for registration at the deployment.

## User Experience / Workflow

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

If the standalone registration page is used, the user can't optionally enroll
and manage tokens while logging in.
The standalone registration page can be found under `<basedir>module.php/webauthn/registration`,
it requires authentication (with the auth source registration_auth_source) and
after that you are redirected to a page where you can manage tokens.

## Device model detection

The option `registration / minimum_certification_level` can be used to get a
token's so-called AAGUID which uniquely identifies the model and manufacturer
(it is not a serial number). You can then make decisions about the acceptability
of a certain authenticator model.

Mapping the AAGUID to a cleartext model and manufacturer name is done by having
(or not) meta-information about the AAGUID. The FIDO Alliance operates a
Metadata Service (MDS) which has a good number of AAGUIDs registered. However,
manufacturers are not required to submit their AAGUIDs and metadata to that MDS,
and indeed, some manufacturers are missing.

The module contains a full list of AAGUIDs and relevant metadata as pulled from
the FIDO MDS. This list is in the `config/webauthn-aaguid.json` file, and this
file needs to be moved to your SimpleSAMLphp configuration directory.

If you want, you can also manually update this file, if you believe there might
be new models listed. In order to do that, run the `bin/updateMetadata.php`
script like this:

```bash
% php bin/updateMetadata.php <blob file>
```

where `<blob file>` is the metadata JWT blob you get from
[here](https://mds3.fidoalliance.org).

As a consequence, depending on the token model the user uses, even if the AAGUID
is being sent as part of the registration process, it may be that the device is
still stored as unknown model/unknown vendor.

I contacted FIDO Alliance to ask about the lack of complete information in their
MDS. Purportedly, listing in the MDS has chances of becoming mandatory in a
future FIDO Certification. Until then, there is no good solution to the problem.

## Disabling WebAuthn

You can disable the module entirely by not listing it as an authprocfilter.

You can disable the module by default by setting default_enable = false. You can
then enable WebAuthn second-factor authentication for individual users by adding
them with status "FIDO2Enabled" to the `userstatus` table or if you don't want to
use the `userstatus` table, you can send an attribute whose name is stored in
`attrib_toggle` for this.

If the module is enabled by default, you can selectively disable WebAuthn
second-factor authentication by adding the username with status FIDO2Disabled to
the `userstatus` table or if you don't want to use the `userstatus` table, you
can send an attribute whose name is stored in `attrib_toggle` for this.

## Limitations / Design Decisions

This implementation does not validate token bindings, if sent by the
authenticator (§7.1 Step 7 / §7.2 Step 11 skip token binding information
validation if present). That is because Yubikeys do not support token binding
and the corresponding functionality thus has no test case.

Both User Present and User Verified variants are considered sufficient to
authenticate successfully in second-factor scenarios (§7.1 steps 11 and 12 are
joined into one condition).
The module logs into the credential database which of the two was used during
registration time and does not allow downgrades during authentication time.
Passwordless authentication always requires User Verified during registration
and authentication transactions.

The implementation requests and supports ECDSA and RSA keys (algorithms -7,
-257).

The implementation does not request any client extensions. The specification
gives implementations a policy choice on what to do if a client sends extensions
anyway: this implementation chose to then fail the registration/authentication.

The implementation supports the attestation formats

- "none" (No Attestation)
- "packed / x5c" (Packed Attestation, X.509 certificate)
- "packed / self" (Packed Attestation, Self-Attestation)
- "fido-u2f" (FIDO U2F Attestation)
- "apple" (Apple Anonymous Attestation)
  Other attestation formats lead to a registration failure.

For the attation type "packed / x5c",

- the optional OCSP checks are not performed (this is explicitly permitted in
  the spec due to other means of revocation checking in the FIDO MDS).

For both "packed / x5c" and "fido-u2f":

- all attestations are classified as "Basic" (i.e. no "AttCA" level); i.e.
  validation as per §7.1 Step 18 is not executed.
- Regarding §7.1 Step 21: When minimum certification levels are configured,
  "Self" and "Basic" attestation levels are considered acceptable; "None" is
  not acceptable.

If the implementation detects signs of physical object cloning (not incremented
signature counter), it follows the policy of failing authentication.
