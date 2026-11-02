-- Push devices (Rust only): one row per browser subscription or mobile token, owned by the
-- user and app it was registered from. Applied by hand per environment (local, dev, stage,
-- prod) in the `notification` schema; rolled back by push_device_rollback.sql.
CREATE TABLE IF NOT EXISTS `notification_push_device` (
  `ID` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'Primary key',
  `USER_ID` bigint unsigned NOT NULL COMMENT 'User the device delivers to',
  `CLIENT_ID` bigint unsigned NOT NULL COMMENT 'Client of the user',
  `APP_CODE` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'App it was registered from',
  `PLATFORM` enum('WEB','ANDROID','IOS') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Delivery route: Web Push, FCM or APNs',
  `TOKEN` varchar(2048) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Web Push endpoint, FCM token or APNs token',
  `TOKEN_HASH` char(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL COMMENT 'SHA-256 hex of PLATFORM:TOKEN',
  `WEB_P256DH` varchar(256) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL COMMENT 'Web Push subscription public key',
  `WEB_AUTH` varchar(64) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL COMMENT 'Web Push subscription auth secret',
  `APP_IDENTIFIER` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Android package or iOS bundle id',
  `PROVIDER_ACCOUNT` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Firebase project id, Apple team id or VAPID key id',
  `APNS_ENV` enum('production','sandbox') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'APNs host for iOS tokens',
  `USER_AGENT` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Browser or app that registered it',
  `LAST_SEEN_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Last registration',
  `CREATED_AT` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Time when this row is created',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_PUSH_DEVICE_TOKEN` (`TOKEN_HASH`),
  KEY `K_PUSH_DEVICE_USER_APP` (`USER_ID`, `APP_CODE`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
