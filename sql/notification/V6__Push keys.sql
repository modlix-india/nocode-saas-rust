-- Push keys (Rust only): the Firebase service account or Apple push key of a client's own
-- developer accounts, uploaded from the mobile app screens for an app on those accounts. Keys
-- never leave the notification service; the sender picks the one whose project or team the
-- device was built against.
CREATE TABLE IF NOT EXISTS `notification_push_key` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `CLIENT_ID` bigint unsigned NOT NULL COMMENT 'Client that uploaded the key and owns it',
  `APP_CODE` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'App whose devices it reaches',
  `PLATFORM` enum('ANDROID','IOS') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'FCM or APNs',
  `ACCOUNT` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Firebase project id or Apple team id',
  `KEY_ID` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'APNs key id',
  `SECRET` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Service account JSON or the .p8 key',
  `CREATED_BY` bigint unsigned NOT NULL COMMENT 'Created by',
  `UPDATED_BY` bigint unsigned NOT NULL COMMENT 'Updated by',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  `UPDATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Time when this row is updated',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_PUSH_KEY_ACCOUNT` (`APP_CODE`, `PLATFORM`, `ACCOUNT`),
  KEY `K_PUSH_KEY_CLIENT_APP` (`CLIENT_ID`, `APP_CODE`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
