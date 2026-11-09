-- Rolls back V10__Seal Certificates.sql: every client's own seal certificate is lost (generated ones can be
-- made again in Settings; uploaded ones must be uploaded again). PDFs are then sealed with the platform's
-- certificate, or not at all where the environment has none. Already sealed PDFs keep their seals.
DROP TABLE IF EXISTS `core`.`core_seal_certificates`;
