-- Rolls back V6__Push keys.sql: the uploaded keys are lost; clients upload them again, and until
-- then their own apps get no push.
DROP TABLE IF EXISTS `notification_push_key`
