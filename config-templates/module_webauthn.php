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
       
        /*
         * You can specify which authenticators are considered acceptable.
         * This can be done with the following two configuration parameters.
         * 
         * They are additive; if either the level is acceptable OR the authenti-
         * cator is in the whitelist, OR the attestation format matches,
         * registration will succeed.
         */
        
        /*
         * Do you require authenticators to be FIDO Certified, and if so, which
         * certification level?
         * 
         * Setting this to anything but "0" will require the user to accept that
         * make and model are sent during the registration process, so that the
         * characteristics of the authenticator can be verified.
         * 
         * "0" is probably acceptable for second-factor use, but most certainly
         * not for Passwordless.
         * 
         * Possible values:
         * "0" =>     no restriction (even authenticators which are NOT FIDO 
         *            Certified are acceptable!)
         * "1" =>     FIDO Certified Level 1
         * "1plus" => FIDO Certified Level 1+
         * "2" =>     FIDO Certified Level 2
         * "3" =>     FIDO Certified Level 3
         * "3plus" => FIDO Certified Level 3+
         */
        'minimum_certification_level' => "2",

        /*
         * If you specify a level above, you may want to make exceptions for
         * specific authenticators that are not on that level. This array
         * holds all the authenticators that are considered acceptable by 
         * exception.
         * 
         */
        'aaguid_whitelist' => [ ],
        
        /*
         * Some authenticators are more equal than others. Apple TouchID and
         * FaceID set their AAGUID to all-zeroes so can't be whitelisted. But
         * they do send their attestation data in a Apple-specific attestation
         * format. So seeing that format means an Apple product is identified.
         * Since these authenticators are quite common, here is an option that
         * allows to whitelist authenticators by their attestation format. 
         * 
         * The example is the obvious and single really useful value.
         * 
         * https://webkit.org/blog/11312/meet-face-id-and-touch-id-for-the-web/
         */
        'attestation_format_whitelist' => ['apple'],
        
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
