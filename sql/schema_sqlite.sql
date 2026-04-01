-- BanTrack - SQLite Fallback Schema
-- Path: /var/lib/fail2ban/fallback.db
-- Used when MySQL is unreachable. Records are retried by db-retry.py.

CREATE TABLE IF NOT EXISTS `ban_log` (
  -- Core ban info
  `id`              INTEGER PRIMARY KEY,
  `ip`              TEXT    NOT NULL,
  `jail_name`       TEXT    NOT NULL,
  `failures`        INTEGER,
  `banned_at`       TEXT    NOT NULL,  -- ISO 8601 string (Python 3.12+ compatibility)
  `ban_duration`    INTEGER,
  `unbanned_at`     TEXT,
  `matches`         TEXT,
  `server_hostname` TEXT    NOT NULL,

  -- Geolocation (via ip-api.com)
  `geo_fetched`        INTEGER NOT NULL,  -- 0 = fetch failed, 1 = fetch succeeded
  `geo_continent_code` TEXT,
  `geo_continent`      TEXT,
  `geo_country_code`   TEXT,
  `geo_country`        TEXT,
  `geo_city`           TEXT,
  `geo_latitude`       REAL,
  `geo_longitude`      REAL,
  `geo_isp`            TEXT,
  `geo_org`            TEXT,
  `geo_as`             TEXT,
  `geo_mobile`         INTEGER,
  `geo_proxy`          INTEGER,
  `geo_hosting`        INTEGER,

  -- Metadata
  `notes`         TEXT,
  `status`        INTEGER,

  -- Retry logic (managed by db-retry.py)
  `retry_count`   INTEGER,
  `error_message` TEXT
);
