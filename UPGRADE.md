# Upgrade instructions

## Upgrade from 0.11.x to 2.0.x

Note that the database schema has additional columns as of 2.0.0:

    algo INT DEFAULT NULL,
    presenceLevel INT DEFAULT NULL,
    isResidentKey BOOL DEFAULT NULL,
    `hashedId` VARCHAR(100) DEFAULT '---',

If you have a previous installation of the module, you need to add this column
manually (
ALTER TABLE credentials ADD COLUMN `algo` INT DEFAULT NULL AFTER `credential`;
ALTER TABLE credentials ADD COLUMN `presenceLevel` INT DEFAULT NULL AFTER `algo`;
ALTER TABLE credentials ADD COLUMN `isResidentKey` BOOL DEFAULT NULL AFTER `presenceLevel`;
ALTER TABLE credentials ADD COLUMN `hashedId` VARCHAR(100) DEFAULT '---' AFTER `friendlyName`;
).
The updated schema is compatible with the 0.11.x releases, so a roll-back to an
older version is still possible without removing the column.

Also note that the parameter attribute_username was changed to
identifyingAttribute to achieve better consistency with other authproc filters.

## Upgrade from 2.0.x to 2.1.x

Two more columns were added to record the AAGUID of the authenticator and its
attestation level:

aaguid VARCHAR(64) DEFAULT NULL,
attLevel ENUM('None','Basic','AttCA') NOT NULL DEFAULT 'None',

On existing installs, you need to add those with

ALTER TABLE credentials ADD COLUMN aaguid VARCHAR(64) DEFAULT NULL AFTER `hashedId`;
ALTER TABLE credentials ADD COLUMN attLevel ENUM('None','Basic','Self','AttCA') NOT NULL DEFAULT 'None' AFTER `aaguid`;

The configuration options around request_tokenmodel morphed into three
attributes that specify which category of authenticators is acceptable for the
deployment at hand:

minimum_certification_level = "0" means the authenticator model is not important
and corresponds to request_tokenmodel = false. Every other setting will trigger
behaviour matching the previous request_tokenmodel = true.

## Upgrade from 2.1.x to 2.2.x

There are minor schema changes. The following two columns MUST be added before
upgrading:

ALTER TABLE credentials ADD COLUMN lastUsedTime TIMESTAMP DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP() AFTER `attLevel`;
ALTER TABLE credentials ADD COLUMN lastUsedIp VARCHAR(64) DEFAULT NULL AFTER `lastUsedTime`;

For consistency with new deployments, the following changes SHOULD be executed
to align table definitions to new deployments. The module will not break
if the old definition remains in place, but you may encounter issue #76 then.

When using MySQL or MariaDB:

ALTER TABLE credentials MODIFY COLUMN credentialId varchar(1024) CHARACTER SET 'binary' NOT NULL;

