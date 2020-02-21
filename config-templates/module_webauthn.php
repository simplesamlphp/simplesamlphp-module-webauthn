<?php

$config = [
    /* required configuration parameters */
    'store' => [
        'webauthn:Database',
        'database.dsn' => 'mysql:host=db.example.org;dbname=fido2',
        'database.username' => 'simplesaml',
        'database.password' => 'sdfsdf',
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
     *
     * If you do not control the entirety of your second-level domain, you must
     * set the scope here explicitly to your own hostname to prevent some
     * contrived attack scenarios with other servers in that same second-level
     * domain.
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

    /* this parameter determines if the database will be used to check
     * whether to trigger second factor authentication or use the "attrib_toggle" instead.
     * Default value of this attribute is true
     */
    'use_database' => true,

    /* optional parameter which determines whether you will be able to register and manage tokens
     * while authenticating or you want to use the standalone registration page for these
     * purposes. If set to false => standalone registration page, if true => inflow registration.
     * Defaults to true.
     */
    'use_inflow_registration' => true,

    /* optional parameter that determines what auth source will be used in standalone registration page.
     * Defaults to 'default-sp'.
     */
    'registration_auth_source' => 'default-sp',
];
