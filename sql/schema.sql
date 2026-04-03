-- BanTrack - Database Schema
-- Database: bans

CREATE DATABASE IF NOT EXISTS `bans`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE `bans`;

CREATE TABLE `ban_log` (
  -- Core ban info
  `id`              int unsigned    NOT NULL AUTO_INCREMENT,
  `ip`              varchar(45)     NOT NULL,
  `jail_name`       varchar(64)     NOT NULL,
  `failures`        smallint        DEFAULT NULL,
  `banned_at`       datetime        NOT NULL,
  `ban_duration`    int             DEFAULT NULL,
  `unbanned_at`     datetime        DEFAULT NULL,
  `matches`         text,
  `server_hostname` varchar(64)     NOT NULL,
  `rcd_created_at`  timestamp       default current_timestamp

  -- Geolocation (via ip-api.com)
  `geo_continent_code` varchar(2)   DEFAULT NULL,
  `geo_continent`      varchar(64)  DEFAULT NULL,
  `geo_country_code`   varchar(2)   DEFAULT NULL,
  `geo_country`        varchar(64)  DEFAULT NULL,
  `geo_city`           varchar(64)  DEFAULT NULL,
  `geo_latitude`       decimal(9,6) DEFAULT NULL,
  `geo_longitude`      decimal(9,6) DEFAULT NULL,
  `geo_isp`            varchar(256) DEFAULT NULL,
  `geo_org`            varchar(256) DEFAULT NULL,
  `geo_as`             varchar(256) DEFAULT NULL,
  `geo_mobile`         tinyint(1)   DEFAULT NULL,
  `geo_proxy`          tinyint(1)   DEFAULT NULL,
  `geo_hosting`        tinyint(1)   DEFAULT NULL,

  -- Metadata
  `notes`   text,
  `status`  tinyint(1) NOT NULL DEFAULT '0',  -- 0 = unbanned, 1 = banned

  PRIMARY KEY (`id`),
  KEY `idx_ip`                 (`ip`),
  KEY `idx_jail_name`          (`jail_name`),
  KEY `idx_banned_at`          (`banned_at`),
  KEY `idx_server_hostname`    (`server_hostname`),
  KEY `idx_geo_continent_code` (`geo_continent_code`),
  KEY `idx_geo_country_code`   (`geo_country_code`),
  KEY `idx_geo_isp`            (`geo_isp`),
  KEY `idx_geo_mobile`         (`geo_mobile`),
  KEY `idx_geo_proxy`          (`geo_proxy`),
  KEY `idx_geo_hosting`        (`geo_hosting`)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;
