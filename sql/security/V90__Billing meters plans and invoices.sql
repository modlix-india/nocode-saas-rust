-- =====================================================================================
-- Billing for any app (expand step). The seven fixed rate columns of a billing config could only
-- bill appbuilder and sitezump; this adds what lets any app bill what it sells:
--
--   security_billing_meter    what a config charges for, one row per meter, TOKENS (prepaid wallet)
--                             or INVOICE (monthly invoice)
--   security_billing_plan     plans of a config (Free / Starter / ...), paid from the wallet or invoiced
--   security_wallet_plan      the plan a wallet is on, and its current period
--   security_wallet_lot       each credit added to a wallet, with its expiry (plan credits end with the
--                             period, bought credits after the config's validity)
--   security_usage_record     daily counts and usage events of INVOICE meters, until they are invoiced
--   security_invoice_line     the lines of a monthly invoice
--   security_ai_model_rate    provider price per model, so an AI call costs what it cost us x markup
--   security_billing_setting  platform values (the USD to INR rate for AI pricing)
--
-- and, on existing tables: config columns for suspension, credit validity and invoicing; invoice
-- columns for monthly invoices (KIND, period, due date, OVERDUE); the EXPIRE ledger type; six decimals on
-- the wallet balance and ledger so small rates accrue instead of rounding to nothing.
--
-- Contract step, a later release: drop the 14 old rate/free columns of security_app_billing_config
-- (APP_RENT_PER_MONTH ... FREE_AI_TOKENS_PER_MONTH). They keep their defaults until then and nothing reads them.
--
-- Re-runnable: CREATE TABLE IF NOT EXISTS, each ADD COLUMN guarded by information_schema, MODIFY to the
-- same definition is harmless, seeds are INSERT IGNORE.
-- Rollback: sql/rollback/security/V90__Billing meters plans and invoices.sql
-- =====================================================================================

USE `security`;

-- ---------------------------------------------------------------------
-- 1. Config: suspension effect, bought-credit validity, invoicing
-- ---------------------------------------------------------------------

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'SUSPEND_MODE');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_app_billing_config` ADD COLUMN `SUSPEND_MODE` enum(''AI_ONLY'',''AI_AND_BANNER'',''BLOCK_APP'') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT ''AI_AND_BANNER'' COMMENT ''What stops when the client is suspended or has an overdue invoice'' AFTER `SUSPEND_CLIENT_CODE`',
    'SELECT ''SUSPEND_MODE already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'PURCHASED_CREDIT_VALIDITY_MONTHS');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_app_billing_config` ADD COLUMN `PURCHASED_CREDIT_VALIDITY_MONTHS` int DEFAULT 12 COMMENT ''Months a bought credit lasts; NULL never expires'' AFTER `SUSPEND_MODE`',
    'SELECT ''PURCHASED_CREDIT_VALIDITY_MONTHS already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'INVOICE_DAY');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_app_billing_config` ADD COLUMN `INVOICE_DAY` int NOT NULL DEFAULT 1 COMMENT ''Day of the month monthly invoices are raised (1-28)'' AFTER `PURCHASED_CREDIT_VALIDITY_MONTHS`',
    'SELECT ''INVOICE_DAY already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'INVOICE_DUE_DAYS');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_app_billing_config` ADD COLUMN `INVOICE_DUE_DAYS` int NOT NULL DEFAULT 15 COMMENT ''Days after issue a monthly invoice falls due'' AFTER `INVOICE_DAY`',
    'SELECT ''INVOICE_DUE_DAYS already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_app_billing_config' AND `COLUMN_NAME` = 'CURRENCY');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_app_billing_config` ADD COLUMN `CURRENCY` char(4) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT ''INR'' COMMENT ''Currency of invoiced rates and plan prices'' AFTER `INVOICE_DUE_DAYS`',
    'SELECT ''CURRENCY already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

-- ---------------------------------------------------------------------
-- 2. Meters: what a config charges for
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security`.`security_billing_meter` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `BILLING_CONFIG_ID` bigint unsigned NOT NULL COMMENT 'Config this meter belongs to',
  `METER_KEY` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Key the app and the ledger use (users, leads, ai.tokens)',
  `LABEL` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Name shown to buyers',
  `UNIT_LABEL` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Unit shown to buyers (user, lead, 1M tokens)',
  `KIND` enum('GAUGE','COUNTER') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'GAUGE counted on a schedule, COUNTER recorded when it happens',
  `SOURCE` enum('USERS','APPS','SITES','STORAGE_ROWS','STORAGE_COUNT','FILES_GB','AI_TOKENS','EVENT') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'What produces the quantity',
  `SOURCE_CONFIG` json DEFAULT NULL COMMENT 'Source options: profileIds, storageName, countArchived',
  `RATE` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Credits (TOKENS) or currency (INVOICE) per RATE_UNIT; for AI_TOKENS the markup on cost',
  `RATE_UNIT` enum('MONTH','EACH','PER_MILLION','PERCENT','MARKUP') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'MONTH' COMMENT 'MONTH per unit per month, EACH per event, PER_MILLION, PERCENT of BASIS, MARKUP on cost',
  `FREE_QUANTITY` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Free units (gauge) or free units per calendar month (counter; credits for AI)',
  `CHARGE_MODE` enum('TOKENS','INVOICE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'TOKENS' COMMENT 'TOKENS debits the wallet, INVOICE goes on the monthly invoice',
  `BASIS` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Reported figure to charge on (default quantity)',
  `MIN_CHARGE` decimal(19,6) DEFAULT NULL COMMENT 'Least charge per event',
  `MAX_CHARGE` decimal(19,6) DEFAULT NULL COMMENT 'Most charge per event',
  `REFUND_POLICY` enum('NONE','WITHIN_DAYS') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'NONE' COMMENT 'Whether a reversed event is refunded',
  `REFUND_DAYS` int DEFAULT NULL COMMENT 'Days after the event a reversal still refunds',
  `DISPLAY_ORDER` int NOT NULL DEFAULT 0 COMMENT 'Order shown to buyers',
  `STATUS` enum('ACTIVE','INACTIVE','DELETED') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'Status',
  `CREATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who created this row',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who updated this row',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK1_BILLING_METER_CONFIG_KEY` (`BILLING_CONFIG_ID`,`METER_KEY`),
  KEY `IDX1_BILLING_METER_SOURCE_STATUS` (`SOURCE`,`STATUS`),
  CONSTRAINT `FK1_BILLING_METER_CONFIG_ID` FOREIGN KEY (`BILLING_CONFIG_ID`) REFERENCES `security_app_billing_config` (`ID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 3. Plans
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security`.`security_billing_plan` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `BILLING_CONFIG_ID` bigint unsigned NOT NULL COMMENT 'Config this plan belongs to',
  `CODE` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Code (free, starter, growth)',
  `LABEL` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Name shown to buyers',
  `DESCRIPTION` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT 'Description shown to buyers',
  `PERIOD` enum('MONTH','YEAR') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'MONTH' COMMENT 'Billing period',
  `PAYMENT_MODE` enum('WALLET','INVOICE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'INVOICE' COMMENT 'WALLET debits PRICE_TOKENS, INVOICE bills PRICE_AMOUNT',
  `PRICE_TOKENS` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Price per period in credits (WALLET)',
  `PRICE_AMOUNT` decimal(19,4) NOT NULL DEFAULT 0 COMMENT 'Price per period before tax (INVOICE)',
  `CURRENCY` char(4) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'INR' COMMENT 'Currency of PRICE_AMOUNT',
  `INCLUDED_TOKENS` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Credits given with the plan',
  `INCLUDED_TOKENS_RECURRING` tinyint(1) NOT NULL DEFAULT 1 COMMENT '1 every period (expire at period end), 0 once',
  `METER_OVERRIDES` json DEFAULT NULL COMMENT '{meterKey: {free, rate, hardCap}}',
  `AI_MODELS_ALLOWED` json DEFAULT NULL COMMENT '{"patterns": [...]}: model name substrings this plan may use; NULL or empty any',
  `IS_DEFAULT` tinyint(1) NOT NULL DEFAULT 0 COMMENT 'The plan a new client starts on and a lapsed plan falls back to',
  `DISPLAY_ORDER` int NOT NULL DEFAULT 0 COMMENT 'Order shown to buyers',
  `STATUS` enum('ACTIVE','INACTIVE','DELETED') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'Status',
  `CREATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who created this row',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who updated this row',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK1_BILLING_PLAN_CONFIG_CODE` (`BILLING_CONFIG_ID`,`CODE`),
  CONSTRAINT `FK1_BILLING_PLAN_CONFIG_ID` FOREIGN KEY (`BILLING_CONFIG_ID`) REFERENCES `security_app_billing_config` (`ID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `security`.`security_wallet_plan` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `WALLET_ID` bigint unsigned NOT NULL COMMENT 'Wallet on the plan',
  `PLAN_ID` bigint unsigned NOT NULL COMMENT 'Plan',
  `PERIOD_START` date NOT NULL COMMENT 'First day of the current period',
  `PERIOD_END` date NOT NULL COMMENT 'Day after the last day of the current period',
  `STATUS` enum('ACTIVE','LAPSED','CANCELLED','ENDED') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE the current plan; the others are history',
  `AUTO_RENEW` tinyint(1) NOT NULL DEFAULT 1 COMMENT 'Renew at period end',
  `NEXT_PLAN_ID` bigint unsigned DEFAULT NULL COMMENT 'Plan to move to at period end (a downgrade waits for it)',
  `CREATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who created this row',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who updated this row',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`ID`),
  KEY `IDX1_WALLET_PLAN_WALLET_STATUS` (`WALLET_ID`,`STATUS`),
  KEY `IDX2_WALLET_PLAN_STATUS_END` (`STATUS`,`PERIOD_END`),
  CONSTRAINT `FK1_WALLET_PLAN_WALLET_ID` FOREIGN KEY (`WALLET_ID`) REFERENCES `security_wallet` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT `FK2_WALLET_PLAN_PLAN_ID` FOREIGN KEY (`PLAN_ID`) REFERENCES `security_billing_plan` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 4. Credit lots: every credit with its expiry
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security`.`security_wallet_lot` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `WALLET_ID` bigint unsigned NOT NULL COMMENT 'Wallet credited',
  `SOURCE` enum('PLAN','PURCHASE','GRANT','ADJUST') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Where the credits came from',
  `REFERENCE_TYPE` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'INVOICE, WALLET_PLAN, ...',
  `REFERENCE_ID` bigint unsigned DEFAULT NULL COMMENT 'Reference id',
  `TOKENS_ADDED` decimal(19,6) NOT NULL COMMENT 'Credits added',
  `TOKENS_LEFT` decimal(19,6) NOT NULL COMMENT 'Credits not used yet',
  `ADDED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'When the credits were added',
  `EXPIRES_AT` timestamp NULL DEFAULT NULL COMMENT 'When what is left expires; NULL never',
  PRIMARY KEY (`ID`),
  KEY `IDX1_WALLET_LOT_WALLET_EXPIRES` (`WALLET_ID`,`EXPIRES_AT`),
  KEY `IDX2_WALLET_LOT_EXPIRES` (`EXPIRES_AT`),
  CONSTRAINT `FK1_WALLET_LOT_WALLET_ID` FOREIGN KEY (`WALLET_ID`) REFERENCES `security_wallet` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 5. Usage of INVOICE meters, until invoiced
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security`.`security_usage_record` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `CLIENT_ID` bigint unsigned NOT NULL COMMENT 'Billed client',
  `APP_ID` bigint unsigned NOT NULL COMMENT 'App',
  `METER_ID` bigint unsigned NOT NULL COMMENT 'Meter',
  `USAGE_DATE` date NOT NULL COMMENT 'Day of the count or event',
  `KIND` enum('SNAPSHOT','EVENT','REVERSAL') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'SNAPSHOT a day''s count, EVENT one use, REVERSAL an undone event',
  `QUANTITY` decimal(19,6) NOT NULL COMMENT 'Units (a reversal holds the units it undoes)',
  `FIGURES` json DEFAULT NULL COMMENT 'Named figures the app reported with the event',
  `REFERENCE` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'The app''s reference for the event',
  `UNIQUE_KEY` varchar(300) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'snap:<date>, ev:<reference> or rev:<reference>; a retry never counts twice',
  `INVOICE_ID` bigint unsigned DEFAULT NULL COMMENT 'Invoice that billed it',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK1_USAGE_RECORD_METER_CLIENT_KEY` (`METER_ID`,`CLIENT_ID`,`UNIQUE_KEY`),
  KEY `IDX1_USAGE_RECORD_CLIENT_APP_DATE` (`CLIENT_ID`,`APP_ID`,`USAGE_DATE`),
  KEY `IDX2_USAGE_RECORD_INVOICE` (`INVOICE_ID`),
  CONSTRAINT `FK1_USAGE_RECORD_CLIENT_ID` FOREIGN KEY (`CLIENT_ID`) REFERENCES `security_client` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT `FK2_USAGE_RECORD_APP_ID` FOREIGN KEY (`APP_ID`) REFERENCES `security_app` (`ID`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT `FK3_USAGE_RECORD_METER_ID` FOREIGN KEY (`METER_ID`) REFERENCES `security_billing_meter` (`ID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 6. Monthly invoices: the invoice columns, then the lines
-- ---------------------------------------------------------------------

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_invoice' AND `COLUMN_NAME` = 'KIND');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_invoice` ADD COLUMN `KIND` enum(''BUNDLE'',''MONTHLY'') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT ''BUNDLE'' COMMENT ''BUNDLE a credit purchase, MONTHLY a monthly invoice'' AFTER `STATUS`',
    'SELECT ''KIND already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

SET @`v_has` = (SELECT COUNT(*) FROM `information_schema`.`COLUMNS`
                WHERE `TABLE_SCHEMA` = 'security' AND `TABLE_NAME` = 'security_invoice' AND `COLUMN_NAME` = 'PERIOD_START');
SET @`v_sql` = IF(@`v_has` = 0,
    'ALTER TABLE `security`.`security_invoice` ADD COLUMN `PERIOD_START` date DEFAULT NULL COMMENT ''First day of the usage month (MONTHLY)'' AFTER `KIND`, ADD COLUMN `PERIOD_END` date DEFAULT NULL COMMENT ''Day after the usage month (MONTHLY)'' AFTER `PERIOD_START`, ADD COLUMN `DUE_DATE` date DEFAULT NULL COMMENT ''Day the invoice falls due (MONTHLY)'' AFTER `PERIOD_END`, ADD COLUMN `PERIOD_KEY` varchar(96) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT ''<client>:<app>:<period start> for MONTHLY, so a rerun raises no second invoice'' AFTER `DUE_DATE`, ADD UNIQUE KEY `UK2_INVOICE_PERIOD_KEY` (`PERIOD_KEY`)',
    'SELECT ''PERIOD_START already present'' AS `V90`');
PREPARE `v_stmt` FROM @`v_sql`; EXECUTE `v_stmt`; DEALLOCATE PREPARE `v_stmt`;

ALTER TABLE `security`.`security_invoice`
  MODIFY COLUMN `STATUS` enum('PENDING','PAID','FAILED','UNDER_REVIEW','OVERDUE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'PENDING' COMMENT 'Invoice status',
  MODIFY COLUMN `TOKENS_PURCHASED` decimal(19,4) DEFAULT NULL COMMENT 'Tokens credited on payment (BUNDLE)';

CREATE TABLE IF NOT EXISTS `security`.`security_invoice_line` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `INVOICE_ID` bigint unsigned NOT NULL COMMENT 'Invoice',
  `KIND` enum('PLAN','METER','ADJUSTMENT') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'What the line bills',
  `METER_ID` bigint unsigned DEFAULT NULL COMMENT 'Meter (METER)',
  `PLAN_ID` bigint unsigned DEFAULT NULL COMMENT 'Plan (PLAN)',
  `DESCRIPTION` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Text on the invoice',
  `PERIOD_START` date DEFAULT NULL COMMENT 'First day billed',
  `PERIOD_END` date DEFAULT NULL COMMENT 'Day after the last day billed',
  `QUANTITY` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Units used',
  `FREE_QUANTITY` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Units free',
  `RATE` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Price per unit',
  `AMOUNT` decimal(19,4) NOT NULL COMMENT 'Line amount before tax',
  `DISPLAY_ORDER` int NOT NULL DEFAULT 0 COMMENT 'Order on the invoice',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  PRIMARY KEY (`ID`),
  KEY `FK1_INVOICE_LINE_INVOICE_ID` (`INVOICE_ID`),
  CONSTRAINT `FK1_INVOICE_LINE_INVOICE_ID` FOREIGN KEY (`INVOICE_ID`) REFERENCES `security_invoice` (`ID`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 7. Ledger and balance: the EXPIRE type, six decimals
-- ---------------------------------------------------------------------
ALTER TABLE `security`.`security_wallet_transaction`
  MODIFY COLUMN `TYPE` enum('CREDIT','DEBIT','ADJUST','SUSPEND','REACTIVATE','REFUND','EXPIRE') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Transaction type',
  MODIFY COLUMN `TOKENS` decimal(19,6) NOT NULL COMMENT 'Token amount (positive)',
  MODIFY COLUMN `BALANCE_AFTER` decimal(19,6) NOT NULL COMMENT 'Balance after this transaction',
  MODIFY COLUMN `QUANTITY` decimal(19,6) DEFAULT NULL COMMENT 'Raw usage units charged';

ALTER TABLE `security`.`security_wallet`
  MODIFY COLUMN `BALANCE` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Current token balance (may go negative, then suspended)';

-- ---------------------------------------------------------------------
-- 8. AI pricing per model, and platform settings
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security`.`security_ai_model_rate` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `MODEL_PATTERN` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Lower-case substring of the model name; the longest match wins',
  `PROVIDER` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Provider',
  `INPUT_PER_M` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Price per 1M input tokens',
  `OUTPUT_PER_M` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Price per 1M output tokens',
  `CACHE_READ_PER_M` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Price per 1M cache-read tokens',
  `CACHE_WRITE_PER_M` decimal(19,6) NOT NULL DEFAULT 0 COMMENT 'Price per 1M cache-write tokens',
  `CURRENCY` char(4) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'USD' COMMENT 'Currency of the prices',
  `STATUS` enum('ACTIVE','INACTIVE','DELETED') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'Status',
  `CREATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who created this row',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who updated this row',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK1_AI_MODEL_RATE_PATTERN` (`MODEL_PATTERN`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `security`.`security_billing_setting` (
  `NAME` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Setting',
  `VALUE` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Value',
  `UPDATED_BY` bigint unsigned DEFAULT NULL COMMENT 'ID of the user who updated this row',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 9. Starting AI rates (USD per million tokens) and the USD to INR rate, as published in November
--    2026. Starting values only: SYSTEM keeps them current through /api/security/billing-ai-rates
--    and /api/security/billing-settings. A model matches its longest pattern; an unmatched model
--    is charged at the dearest rate.
-- ---------------------------------------------------------------------
INSERT IGNORE INTO `security`.`security_ai_model_rate`
  (`MODEL_PATTERN`, `PROVIDER`, `INPUT_PER_M`, `OUTPUT_PER_M`, `CACHE_READ_PER_M`, `CACHE_WRITE_PER_M`, `CURRENCY`) VALUES
  ('opus',              'anthropic', 4.000000, 20.000000, 0.200000, 5.000000, 'USD'),
  ('sonnet',            'anthropic', 2.000000, 10.000000, 0.100000, 2.500000, 'USD'),
  ('claude-sonnet-4-',  'anthropic', 3.000000, 15.000000, 0.300000, 3.750000, 'USD'),
  ('haiku',             'anthropic', 0.100000,  0.500000, 0.010000, 0.125000, 'USD'),
  ('claude-haiku-4-5',  'anthropic', 1.000000,  5.000000, 0.100000, 1.250000, 'USD'),
  ('gpt-4o',            'openai',    2.500000, 10.000000, 1.250000, 0.000000, 'USD'),
  ('gpt-4o-mini',       'openai',    0.150000,  0.600000, 0.075000, 0.000000, 'USD'),
  ('deepseek',          'deepseek',  0.300000,  1.200000, 0.006000, 0.000000, 'USD'),
  ('deepseek-v4-pro',   'deepseek',  1.320000,  3.960000, 0.044000, 0.000000, 'USD'),
  ('minimax',           'minimax',   0.300000,  1.200000, 0.060000, 0.000000, 'USD');

INSERT IGNORE INTO `security`.`security_billing_setting` (`NAME`, `VALUE`) VALUES ('AI_FX_RATE', '94');
