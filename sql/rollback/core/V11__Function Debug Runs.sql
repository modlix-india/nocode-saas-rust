-- Rolls back V11__Function Debug Runs.sql: every stored debug run of server functions is lost. Nothing
-- else reads the table; functions run as before, and new debug runs are not stored until V11 is back.
DROP TABLE IF EXISTS `core`.`core_function_debug_runs`;
