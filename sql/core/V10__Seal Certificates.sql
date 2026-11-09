-- A client's own PDF seal certificate per app (Rust only, crate::seal_certs): made by the platform's private
-- document-seal CA (GENERATED) or a certificate the client bought and uploaded (UPLOADED). TemplateToPdf with
-- seal true seals a PDF with the certificate of the request's client for that app, else with the platform's.
-- The .p12 and its password are kept encrypted (AES-256-GCM under [seal] encryption_key, bound to the client
-- and app) and never read back: the API shows only the subject, issuer, validity and fingerprint.
CREATE TABLE IF NOT EXISTS `core`.`core_seal_certificates` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `CLIENT_CODE` char(12) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'The client the certificate seals for',
  `APP_CODE` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'The app it seals for',
  `KIND` enum('GENERATED','UPLOADED') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Made by the platform CA or uploaded',
  `SUBJECT` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Certificate subject (RFC 4514)',
  `ISSUER` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Certificate issuer (RFC 4514)',
  `NOT_BEFORE` datetime NOT NULL COMMENT 'Valid from (UTC)',
  `NOT_AFTER` datetime NOT NULL COMMENT 'Valid until (UTC)',
  `FINGERPRINT` char(64) CHARACTER SET ascii NOT NULL COMMENT 'SHA-256 of the certificate, hex',
  `P12` mediumblob NOT NULL COMMENT 'The .p12, encrypted (nonce + AES-256-GCM)',
  `PASSWORD` blob NOT NULL COMMENT 'Its password, encrypted (nonce + AES-256-GCM)',
  `CREATED_BY` bigint unsigned DEFAULT NULL COMMENT 'User who generated or uploaded it',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_SEAL_CERT_CLIENT_APP` (`CLIENT_CODE`, `APP_CODE`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
