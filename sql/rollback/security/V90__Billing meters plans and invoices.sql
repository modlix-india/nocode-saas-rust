-- Rolls back V90__Billing meters plans and invoices.sql. Lost: every meter, plan, wallet plan, credit lot,
-- usage record, invoice line, AI model rate and billing setting; the config's suspension mode, credit
-- validity, invoice day, due days and currency; the invoice kind, period, due date and period key.
-- Monthly invoices stay as rows but lose their lines.
--
-- Run it only after security is back on a build that does not read these. Narrowing the enums fails while a
-- row still holds OVERDUE or EXPIRE, and narrowing the decimals rounds balances to four places: clear or
-- update those rows first if that is acceptable.
-- Re-runnable: each column is dropped only when information_schema still lists it.

USE `security`;

DROP TABLE IF EXISTS `security`.`security_billing_setting`;
DROP TABLE IF EXISTS `security`.`security_ai_model_rate`;
DROP TABLE IF EXISTS `security`.`security_invoice_line`;
DROP TABLE IF EXISTS `security`.`security_usage_record`;
DROP TABLE IF EXISTS `security`.`security_wallet_lot`;
DROP TABLE IF EXISTS `security`.`security_wallet_plan`;
DROP TABLE IF EXISTS `security`.`security_billing_plan`;
DROP TABLE IF EXISTS `security`.`security_billing_meter`;

ALTER TABLE `security`.`security_wallet`
  MODIFY COLUMN `BALANCE` decimal(19,4) NOT NULL DEFAULT 0 COMMENT 'Current token balance (may go negative once, then suspended)';

ALTER TABLE `security`.`security_wallet_transaction`
  MODIFY COLUMN `TYPE` enum('CREDIT','DEBIT','ADJUST','SUSPEND','REACTIVATE','REFUND') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Transaction type',
  MODIFY COLUMN `TOKENS` decimal(19,4) NOT NULL COMMENT 'Token amount (positive)',
  MODIFY COLUMN `BALANCE_AFTER` decimal(19,4) NOT NULL COMMENT 'Balance after this transaction',
  MODIFY COLUMN `QUANTITY` decimal(19,4) DEFAULT NULL COMMENT 'Raw usage units charged';

ALTER TABLE `security`.`security_invoice`
  MODIFY COLUMN `STATUS` enum('PENDING','PAID','FAILED','UNDER_REVIEW') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'PENDING' COMMENT 'Invoice status';

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_invoice' AND `COLUMN_NAME` = 'PERIOD_KEY');
SET @`v_sql` = IF(@`v_has` = 1,
    'ALTER TABLE `security`.`security_invoice` DROP KEY `UK2_INVOICE_PERIOD_KEY`, DROP COLUMN `PERIOD_KEY`, DROP COLUMN `DUE_DATE`, DROP COLUMN `PERIOD_END`, DROP COLUMN `PERIOD_START`',
    'SELECT ''invoice period columns already absent'' AS `V90_rollback`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_invoice' AND `COLUMN_NAME` = 'KIND');
SET @`v_sql` = IF(@`v_has` = 1,
    'ALTER TABLE `security`.`security_invoice` DROP COLUMN `KIND`',
    'SELECT ''KIND already absent'' AS `V90_rollback`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'SUSPEND_MODE');
SET @`v_sql` = IF(@`v_has` = 1,
    'ALTER TABLE `security`.`security_app_billing_config` DROP COLUMN `CURRENCY`, DROP COLUMN `INVOICE_DUE_DAYS`, DROP COLUMN `INVOICE_DAY`, DROP COLUMN `PURCHASED_CREDIT_VALIDITY_MONTHS`, DROP COLUMN `SUSPEND_MODE`',
    'SELECT ''config columns already absent'' AS `V90_rollback`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;
-- (The starting AI rates and the AI_FX_RATE setting go with their tables above.)
