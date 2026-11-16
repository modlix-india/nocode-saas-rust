-- Rolls back V91__Billing config activated at.sql. Lost: when each config was switched on. With an
-- older security build every existing client of an ACTIVE config goes on the default plan again at the
-- next user count.
-- Re-runnable: the column is dropped only when information_schema still lists it.

USE `security`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'ACTIVATED_AT');
SET @`v_sql` = IF(@`v_has` > 0,
    'ALTER TABLE `security`.`security_app_billing_config` DROP COLUMN `ACTIVATED_AT`',
    'SELECT ''ACTIVATED_AT already gone'' AS `V91 rollback`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;
