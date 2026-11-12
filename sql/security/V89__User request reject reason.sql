-- =====================================================================================
-- Access request reject reason: the optional text an admin types when rejecting a request
-- (POST /api/security/users/rejectRequest/{requestId} with {"reason": "..."}). Security keeps
-- it on the request and sends it in the USER_REQUEST_REJECTED event, so the reject mail can
-- tell the person why. At most 500 characters (security answers 400 above that).
--
-- Re-runnable: the column is added only when information_schema does not list it yet.
-- Rollback: sql/rollback/security/V89__User request reject reason.sql
-- =====================================================================================

USE `security`;

SET @`v_has_reject_reason` = (SELECT COUNT(*)
                              FROM `information_schema`.`COLUMNS`
                              WHERE `TABLE_SCHEMA` = 'security'
                                AND `TABLE_NAME` = 'security_user_request'
                                AND `COLUMN_NAME` = 'REJECT_REASON');

SET @`v_sql` = IF(@`v_has_reject_reason` = 0,
                  'ALTER TABLE `security`.`security_user_request` ADD COLUMN `REJECT_REASON` VARCHAR(500) NULL DEFAULT NULL COMMENT ''Reason given when the request was rejected, sent to the requester'' AFTER `STATUS`',
                  'SELECT ''REJECT_REASON already present'' AS `V89`');

PREPARE `v_stmt` FROM @`v_sql`;
EXECUTE `v_stmt`;
DEALLOCATE PREPARE `v_stmt`;
