-- Rolls back push_device.sql: the devices are lost; apps register again on their next sign-in.
DROP TABLE IF EXISTS `notification_push_device`
