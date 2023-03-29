<?php

$config = [
    /* Enable/disable Debug made */
    'debug' => false,

    /* required configuration parameters */
    'store' => [
        'webauthn:Database',
        'database.dsn' => 'mysql:host=db.example.org;dbname=fido2',
        'database.username' => 'simplesaml',
        'database.password' => 'sdfsdf',
    ],

    'identifyingAttribute' => 'uid',
    'attrib_displayname' => 'urn:oid:2.5.4.3',

    /* FIDO2 is phishing-resistent by binding generated credentials to a scope.
     * Browsers will only invoke the registration/authentication if the scope
     * matches the principal domain name the user is currently visiting.
     * If not specified, the scope will be the hostname of the IdP as per
     * its metadata. It is permissible to widen the scope up to the prinicpal
     * domain though (e.g. authentication service is "saml.example.com" => scope
     * can be extended to "example.com"; but not "examp1e2.com". A registered
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
    
    /**
     * The following options control how new FIDO2 keys are registered for a
     * given user.
     */
    'registration' => [
        /* the following will interactively ask the user if he is willing to
         * share manufacturer and model information during credential 
         * registration. The user can decline, in which case registration will 
         * still succeed but vendor and model will be logged as 
         * "unknown model [unknown vendor]"
         *
         * When not requesting this, there is one less user interaction during
         * the registration process; and no model information will be saved.
         *
         * defaults to "false"
         */
        'request_tokenmodel' => true,

        /* optional parameter which determines whether you will be able to 
         * register and manage tokens while authenticating or you want to use 
         * the standalone registration page for these purposes. 
         * If false => standalone registration page (user needs to visit 
         *             dedicated token management page and authenticate to that)
         * if true => inflow registration (automatically ask for registration
         *            if no key registered; enable key management with a
         *            checkbox post-authentication)
         * Defaults to true.
         */
        'use_inflow_registration' => true,

        /* optional parameter that determines what auth source will be used to
         * authenticate to the standalone registration page.
         * Defaults to 'default-sp'.
         */
        'auth_source' => 'default-sp',
    ],
];
