-- Web push keys per app (Rust only): the VAPID pair browsers of one app subscribe with, made by
-- the notification service the first time the app's push settings are asked for. A browser that
-- subscribed before its app had one keeps the platform's key from the config until it subscribes
-- again. Keys never leave the notification service; only the public half is handed out.
CREATE TABLE IF NOT EXISTS `notification_push_app_key` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `APP_CODE` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'App whose browsers subscribe with it',
  `PUBLIC_KEY` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Uncompressed P-256 point, base64url',
  `PRIVATE_KEY` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'PKCS#8 document, base64',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_PUSH_APP_KEY_APP` (`APP_CODE`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
