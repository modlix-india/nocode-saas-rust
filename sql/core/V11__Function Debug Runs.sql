-- One row per server side KIRun run made with the `x-debug` header by a caller who may
-- edit functions (Authorities.Function_UPDATE), so the function editor can show the
-- steps of a run after it finished.
--
-- LOG is the run's execution log in the shape kirun-js `DebugCollector.getExecution()`
-- returns (executionId, startTime, endTime, errored, logs). Nested definition calls are
-- inside it, under the step that called them. Secrets are masked and every step's
-- arguments and result are capped at 10 KB (unless the debug id starts with `full-`);
-- the whole LOG is capped at 1 MB.
--
-- Rows are kept per (CLIENT_CODE, APP_CODE, FUNCTION_NAMESPACE, FUNCTION_NAME): the newest
-- 100, none older than 14 days. Both are enforced at insert time for the key written;
-- POST /api/core/functions/debugRuns/internal/cleanupOlderThan deletes expired rows of
-- every key.
--
-- Times are UTC. DATETIME rather than TIMESTAMP so no session time zone ever converts them.

CREATE TABLE IF NOT EXISTS `core`.`core_function_debug_runs`
(
    `ID`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
    `DEBUG_ID`           VARCHAR(128)    NOT NULL COMMENT 'The x-debug header value',
    `APP_CODE`           CHAR(64)        NOT NULL COMMENT 'App the function ran in',
    `CLIENT_CODE`        CHAR(12)        NOT NULL COMMENT 'Client the function ran for',
    `FUNCTION_NAMESPACE` VARCHAR(255)    NOT NULL DEFAULT '' COMMENT 'Function namespace',
    `FUNCTION_NAME`      VARCHAR(255)    NOT NULL COMMENT 'Function name',
    `USER_ID`            BIGINT UNSIGNED NULL COMMENT 'User who ran it',
    `USER_NAME`          VARCHAR(255)    NULL COMMENT 'Display name (or user name) of the user, at write time',
    `IS_DRAFT`           TINYINT(1)      NOT NULL DEFAULT 0 COMMENT 'Ran on the draft surface',
    `ERRORED`            TINYINT(1)      NOT NULL DEFAULT 0 COMMENT 'The run or a step failed',
    `STEP_COUNT`         INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Steps logged, nested ones included',
    `STARTED_AT`         DATETIME(3)     NOT NULL COMMENT 'UTC',
    `FINISHED_AT`        DATETIME(3)     NULL COMMENT 'UTC',
    `DURATION_MS`        INT UNSIGNED    NULL COMMENT 'Milliseconds from start to finish',
    `LOG`                JSON            NULL COMMENT 'Execution log, masked and capped',
    `LOG_BYTES`          INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Size of LOG as stored',

    PRIMARY KEY (`ID`),
    -- The list, newest first, and the per key rollover.
    KEY `K1_CLIENT_APP_FN_STARTED` (`CLIENT_CODE`, `APP_CODE`, `FUNCTION_NAMESPACE`, `FUNCTION_NAME`, `STARTED_AT`),
    -- Age cleanup across every key.
    KEY `K2_STARTED` (`STARTED_AT`),
    KEY `K3_DEBUG_ID` (`DEBUG_ID`)
)
    ENGINE = INNODB
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
