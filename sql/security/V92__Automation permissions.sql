-- =====================================================================================
-- Automations (core, Rust only): the authorities core checks on /api/core/automations,
-- /api/core/automations/check, /catalog, /test and /api/core/automationRuns.
--
-- Seeds, in the shape of V88:
--   * permissions 'Automation CREATE' / READ / UPDATE / DELETE -> Authorities.Automation_<M>
--   * V2 role 'Automation Manager' holding all four
--
-- No profile gets the role here. Which profiles may manage automations differs per app
-- (leadzumptwo, adzumptwo, cxzump, sitezump) and is decided in each app's access model first.
--
-- APP_ID is NULL on purpose: an app-scoped name is prefixed with the app code
-- (Authorities.LEADZUMPTWO.Automation_READ), which core never checks.
--
-- Re-runnable: permissions are UNIQUE on NAME (INSERT IGNORE); the role is guarded by
-- NOT EXISTS; role-permission links are UNIQUE (ROLE_ID, PERMISSION_ID).
-- =====================================================================================

USE `security`;

SELECT `ID` FROM `security`.`security_client` WHERE `CODE` = 'SYSTEM' LIMIT 1 INTO @`v_system_client_id`;

INSERT IGNORE INTO `security`.`security_permission` (`CLIENT_ID`, `NAME`, `DESCRIPTION`) VALUES
    (@`v_system_client_id`, 'Automation CREATE', 'Create automations. Yields Authorities.Automation_CREATE.'),
    (@`v_system_client_id`, 'Automation READ', 'See automations, their catalog and their runs. Yields Authorities.Automation_READ.'),
    (@`v_system_client_id`, 'Automation UPDATE', 'Change, publish, pause, test automations and stop runs. Yields Authorities.Automation_UPDATE.'),
    (@`v_system_client_id`, 'Automation DELETE', 'Delete automations. Yields Authorities.Automation_DELETE.');

INSERT INTO `security`.`security_v2_role` (`CLIENT_ID`, `NAME`, `SHORT_NAME`, `DESCRIPTION`)
SELECT @`v_system_client_id`, 'Automation Manager', 'Automations', 'Create, change, test and delete automations and see their runs'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM `security`.`security_v2_role`
                    WHERE `NAME` = 'Automation Manager' AND `CLIENT_ID` = @`v_system_client_id`
                      AND `APP_ID` IS NULL);

SELECT `ID` FROM `security`.`security_v2_role`
 WHERE `NAME` = 'Automation Manager' AND `CLIENT_ID` = @`v_system_client_id` AND `APP_ID` IS NULL
 ORDER BY `ID` LIMIT 1 INTO @`v_role_automation_manager`;

INSERT IGNORE INTO `security`.`security_v2_role_permission` (`ROLE_ID`, `PERMISSION_ID`)
SELECT @`v_role_automation_manager`, `ID` FROM `security`.`security_permission`
 WHERE `NAME` IN ('Automation CREATE', 'Automation READ', 'Automation UPDATE', 'Automation DELETE');
