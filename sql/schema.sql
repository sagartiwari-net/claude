-- Claude-only database for cld.1clkaccess.store + cldup.1clkaccess.store
-- Structure matches toolsmandirefct dump; seeded with Claude only (no cookies/logs).
-- Import once: mysql -u USER -p < sql/schema.sql

CREATE DATABASE IF NOT EXISTS `claude_1clk` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `claude_1clk`;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `ahrefs_switch_logs`;
DROP TABLE IF EXISTS `ahrefs_security_logs`;
DROP TABLE IF EXISTS `ahrefs_violations_logs`;
DROP TABLE IF EXISTS `ahrefs_login_logs`;
DROP TABLE IF EXISTS `ahrefs_automation_ingest_logs`;
DROP TABLE IF EXISTS `ahrefs_credit_logs`;
DROP TABLE IF EXISTS `ahrefs_export_logs`;
DROP TABLE IF EXISTS `ahrefs_blocked_ips`;
DROP TABLE IF EXISTS `ahrefs_admin_sessions`;
DROP TABLE IF EXISTS `ahrefs_tokens`;
DROP TABLE IF EXISTS `ahrefs_sessions`;
DROP TABLE IF EXISTS `ahrefs_users`;
DROP TABLE IF EXISTS `ahrefs_products`;
DROP TABLE IF EXISTS `ahrefs_accounts`;
DROP TABLE IF EXISTS `ahrefs_reseller_websites`;
DROP TABLE IF EXISTS `ahrefs_proxies`;
DROP TABLE IF EXISTS `ahrefs_websites`;
DROP TABLE IF EXISTS `ahrefs_tools`;
DROP TABLE IF EXISTS `ahrefs_resellers`;

CREATE TABLE `ahrefs_tools` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `category` varchar(100) COLLATE utf8mb4_general_ci DEFAULT 'seo',
  `limit_label_1` varchar(100) COLLATE utf8mb4_general_ci DEFAULT 'Daily Credits',
  `limit_label_2` varchar(100) COLLATE utf8mb4_general_ci DEFAULT 'Export Rows',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_websites` (
  `id` int NOT NULL AUTO_INCREMENT,
  `tool_id` int NOT NULL,
  `name` varchar(150) COLLATE utf8mb4_general_ci NOT NULL,
  `domain` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `secret_key` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `session_duration` int DEFAULT 30,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `default_credit_limit` int DEFAULT 50,
  `default_export_limit` int DEFAULT 100000,
  `proxy` varchar(500) COLLATE utf8mb4_general_ci DEFAULT '',
  `session_security_enabled` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `domain` (`domain`),
  KEY `tool_id` (`tool_id`),
  CONSTRAINT `ahrefs_websites_ibfk_1` FOREIGN KEY (`tool_id`) REFERENCES `ahrefs_tools` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_resellers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `password_hash` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `role` enum('master','reseller') COLLATE utf8mb4_general_ci DEFAULT 'reseller',
  `status` enum('active','suspended') COLLATE utf8mb4_general_ci DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_reseller_websites` (
  `reseller_id` int NOT NULL,
  `website_id` int NOT NULL,
  PRIMARY KEY (`reseller_id`,`website_id`),
  KEY `website_id` (`website_id`),
  CONSTRAINT `ahrefs_reseller_websites_ibfk_1` FOREIGN KEY (`reseller_id`) REFERENCES `ahrefs_resellers` (`id`) ON DELETE CASCADE,
  CONSTRAINT `ahrefs_reseller_websites_ibfk_2` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_admin_sessions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `session_token` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
  `reseller_id` int NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_token` (`session_token`),
  KEY `reseller_id` (`reseller_id`),
  CONSTRAINT `ahrefs_admin_sessions_ibfk_1` FOREIGN KEY (`reseller_id`) REFERENCES `ahrefs_resellers` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_accounts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `name` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `cookie` mediumtext COLLATE utf8mb4_general_ci NOT NULL,
  `user_agent` text COLLATE utf8mb4_general_ci NOT NULL,
  `proxy` varchar(255) COLLATE utf8mb4_general_ci DEFAULT '',
  `status` enum('active','logged_out','blocked') COLLATE utf8mb4_general_ci DEFAULT 'active',
  `last_used_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `failure_count` int DEFAULT 0,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `show_limit` tinyint(1) DEFAULT 1,
  `automation_task_uid` varchar(255) COLLATE utf8mb4_general_ci DEFAULT '',
  `automation_ingest_key` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `goauto_task_uid` varchar(255) COLLATE utf8mb4_general_ci DEFAULT '',
  `automation_api_url` varchar(500) COLLATE utf8mb4_general_ci DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `status` (`status`),
  CONSTRAINT `ahrefs_accounts_ibfk_1` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `credit_limit` int DEFAULT 50,
  `export_limit` int DEFAULT 100000,
  `export_cycle_start` datetime DEFAULT CURRENT_TIMESTAMP,
  `status` enum('active','suspended') COLLATE utf8mb4_general_ci DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `custom_limit_expire_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_user_website` (`username`,`website_id`),
  KEY `website_id` (`website_id`),
  KEY `username` (`username`),
  CONSTRAINT `ahrefs_users_ibfk_1` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_sessions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL,
  `session_token` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `client_ip` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `assigned_account_id` int DEFAULT NULL,
  `device_token` varchar(64) COLLATE utf8mb4_general_ci DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_token` (`session_token`),
  KEY `website_id` (`website_id`),
  KEY `expires_at` (`expires_at`),
  KEY `assigned_account_id` (`assigned_account_id`),
  CONSTRAINT `ahrefs_sessions_ibfk_1` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_sessions_accounts` FOREIGN KEY (`assigned_account_id`) REFERENCES `ahrefs_accounts` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL,
  `token` varchar(128) COLLATE utf8mb4_general_ci NOT NULL,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `client_ip` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `website_id` (`website_id`),
  KEY `expires_at` (`expires_at`),
  CONSTRAINT `ahrefs_tokens_ibfk_1` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_products` (
  `id` int NOT NULL AUTO_INCREMENT,
  `product_id` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `product_name` varchar(200) COLLATE utf8mb4_general_ci DEFAULT '',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `website_id` int NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_proxies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(150) COLLATE utf8mb4_general_ci NOT NULL,
  `proxy_type` enum('SOCKS5','HTTP','HTTPS') COLLATE utf8mb4_general_ci DEFAULT 'SOCKS5',
  `endpoint` varchar(500) COLLATE utf8mb4_general_ci NOT NULL,
  `status` enum('active','inactive') COLLATE utf8mb4_general_ci DEFAULT 'active',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_credit_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `endpoint` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `username` (`username`),
  KEY `timestamp` (`timestamp`),
  CONSTRAINT `ahrefs_credit_logs_ibfk_1` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_export_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `rows_count` int NOT NULL,
  `endpoint` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `username` (`username`),
  KEY `timestamp` (`timestamp`),
  CONSTRAINT `ahrefs_export_logs_ibfk_1` FOREIGN KEY (`website_id`) REFERENCES `ahrefs_websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_login_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL,
  `username` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `client_ip` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
  `user_agent` text COLLATE utf8mb4_general_ci,
  `logged_in_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_security_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `username` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `client_ip` varchar(64) COLLATE utf8mb4_general_ci DEFAULT '',
  `event_type` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
  `attempted_url` varchar(500) COLLATE utf8mb4_general_ci DEFAULT '',
  `details` text COLLATE utf8mb4_general_ci,
  `user_agent` text COLLATE utf8mb4_general_ci,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `username` (`username`),
  KEY `event_type` (`event_type`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_blocked_ips` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 0,
  `client_ip` varchar(64) COLLATE utf8mb4_general_ci NOT NULL,
  `reason` varchar(255) COLLATE utf8mb4_general_ci DEFAULT '',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_website_ip` (`website_id`,`client_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_switch_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `session_token` varchar(128) COLLATE utf8mb4_general_ci DEFAULT '',
  `username` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `from_account_id` int DEFAULT 0,
  `from_account_name` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `to_account_id` int DEFAULT 0,
  `to_account_name` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `reason` varchar(255) COLLATE utf8mb4_general_ci DEFAULT '',
  `switched_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `switched_at` (`switched_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_violations_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 1,
  `username` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `client_ip` varchar(64) COLLATE utf8mb4_general_ci DEFAULT '',
  `attempted_path` varchar(500) COLLATE utf8mb4_general_ci DEFAULT '',
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `ahrefs_automation_ingest_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `website_id` int NOT NULL DEFAULT 0,
  `account_id` int NOT NULL DEFAULT 0,
  `ingest_key` varchar(100) COLLATE utf8mb4_general_ci NOT NULL DEFAULT '',
  `account_name` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `website_name` varchar(100) COLLATE utf8mb4_general_ci DEFAULT '',
  `status` enum('saved','failed') COLLATE utf8mb4_general_ci NOT NULL,
  `error_message` varchar(500) COLLATE utf8mb4_general_ci DEFAULT '',
  `bytes_saved` int DEFAULT 0,
  `client_ip` varchar(45) COLLATE utf8mb4_general_ci DEFAULT '',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `website_id` (`website_id`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- ────────────────────────────────────────────────────────────────────
-- Claude-only seed (no account cookies — add via cldup panel)
-- Admin password: toolsmandi_admin_xyz123
-- ────────────────────────────────────────────────────────────────────

INSERT INTO `ahrefs_tools` (`id`, `name`, `category`, `limit_label_1`, `limit_label_2`, `created_at`) VALUES
(1, 'Claude', 'AI', 'Daily Requests', '', NOW());

INSERT INTO `ahrefs_websites` (`id`, `tool_id`, `name`, `domain`, `secret_key`, `session_duration`, `created_at`, `default_credit_limit`, `default_export_limit`, `proxy`, `session_security_enabled`) VALUES
(1, 1, 'ToolsMandi Claude', 'cld.1clkaccess.store', 'toolsmandi_claude_secret_xyz123', 30, NOW(), 50, 100000, '', 1);

INSERT INTO `ahrefs_resellers` (`id`, `username`, `password_hash`, `role`, `status`, `created_at`) VALUES
(1, 'admin', 'ba4c67e586af55b0893ebf15909d4c122b4d4bc1e96ff7f956f6479b2b8d2ac7', 'master', 'active', NOW());
