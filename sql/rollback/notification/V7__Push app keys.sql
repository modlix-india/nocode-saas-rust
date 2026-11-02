-- Rolls back V7__Push app keys.sql: browsers subscribed with an app's key stop getting push until
-- they subscribe again (quietly, at their next sign-in) with the platform's key.
DROP TABLE IF EXISTS `notification_push_app_key`
