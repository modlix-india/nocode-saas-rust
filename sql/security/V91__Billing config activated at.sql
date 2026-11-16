-- =====================================================================================
-- When a billing config was last switched on.
--
-- Switching an app's billing on used to put every existing client of the app on the default (Free) plan
-- at the next user count: on local 78 leadzumptwo clients, 261 cxzump. A client created before
-- ACTIVATED_AT that has no wallet yet is now left out of billing until it joins (subscribes to a plan,
-- buys credits or is granted them). Clients created after it start on the default plan as before.
--
-- Security stamps ACTIVATED_AT whenever a config is saved going from not ACTIVE to ACTIVE. Configs that
-- are ACTIVE already get their last update time.
--
-- Re-runnable: the column is added only when information_schema does not list it; the backfill only
-- touches rows still NULL.
-- Rollback: sql/rollback/security/V91__Billing config activated at.sql
-- =====================================================================================

USE `security`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'ACTIVATED_AT');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_app_billing_config` ADD COLUMN `ACTIVATED_AT` timestamp NULL DEFAULT NULL COMMENT ''When the config was last switched ACTIVE; clients created before it are billed only once they join'' AFTER `STATUS`',
    'SELECT ''ACTIVATED_AT already present'' AS `V91`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

UPDATE `security`.`security_app_billing_config`
   SET `ACTIVATED_AT` = COALESCE(`UPDATED_AT`, `CREATED_AT`)
 WHERE `STATUS` = 'ACTIVE' AND `ACTIVATED_AT` IS NULL;
