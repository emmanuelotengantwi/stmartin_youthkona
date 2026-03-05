-- Import this schema into an already created database.

CREATE TABLE IF NOT EXISTS youth (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  contact VARCHAR(120) NOT NULL,
  date_of_birth VARCHAR(5) NOT NULL,
  gender ENUM('Male','Female') NOT NULL,
  marital_status ENUM('Single','Married','Separated','Divorced') NOT NULL,
  profession VARCHAR(120) NOT NULL,
  area_of_interest VARCHAR(255) NOT NULL,
  societal_groups TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_youth_name (name)
);

ALTER TABLE youth
  ADD COLUMN IF NOT EXISTS date_of_birth VARCHAR(5) NOT NULL AFTER contact;

ALTER TABLE youth
  MODIFY COLUMN date_of_birth VARCHAR(5) NOT NULL;

ALTER TABLE youth
  ADD COLUMN IF NOT EXISTS gender ENUM('Male','Female') NOT NULL AFTER date_of_birth;

ALTER TABLE youth
  ADD COLUMN IF NOT EXISTS societal_groups TEXT NOT NULL AFTER area_of_interest;

ALTER TABLE youth
  ADD UNIQUE KEY uq_youth_name (name);

CREATE TABLE IF NOT EXISTS admins (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(120) NOT NULL,
  username VARCHAR(80) NOT NULL UNIQUE,
  role ENUM('super_admin','viewer') NOT NULL DEFAULT 'super_admin',
  must_change_password TINYINT(1) NOT NULL DEFAULT 0,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE admins
  ADD COLUMN IF NOT EXISTS role ENUM('super_admin','viewer') NOT NULL DEFAULT 'super_admin' AFTER username;

ALTER TABLE admins
  ADD COLUMN IF NOT EXISTS must_change_password TINYINT(1) NOT NULL DEFAULT 0 AFTER role;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  admin_id INT UNSIGNED NULL,
  event_type VARCHAR(80) NOT NULL,
  event_details VARCHAR(255) NOT NULL DEFAULT '',
  ip_address VARCHAR(45) NOT NULL,
  user_agent VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_created_at (created_at),
  INDEX idx_audit_admin_id (admin_id),
  CONSTRAINT fk_audit_admin FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS admin_login_attempts (
  username VARCHAR(80) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  last_failed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (username, ip_address),
  INDEX idx_locked_until (locked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
