-- Rolls back V89__User request reject reason.sql: the reasons typed on rejected requests are lost.
-- Run it only after security is back on a build that does not read REJECT_REASON; a build that
-- reads it fails every request query once the column is gone.
-- Re-runnable: the column is dropped only when information_schema still lists it.

USE `security`;

SET @`v_has_reject_reason` = (SELECT COUNT(*)
                              FROM `information_schema`.`COLUMNS`
                              WHERE `TABLE_SCHEMA` = 'security'
                                AND `TABLE_NAME` = 'security_user_request'
                                AND `COLUMN_NAME` = 'REJECT_REASON');

SET @`v_sql` = IF(@`v_has_reject_reason` = 1,
                  'ALTER TABLE `security`.`security_user_request` DROP COLUMN `REJECT_REASON`',
                  'SELECT ''REJECT_REASON already absent'' AS `V89_rollback`');

PREPARE `v_stmt` FROM @`v_sql`;
EXECUTE `v_stmt`;
DEALLOCATE PREPARE `v_stmt`;
