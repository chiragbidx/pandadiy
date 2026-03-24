-- Basic auth schema for PostgreSQL
-- Run once against your application database.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS app_users_email_idx ON app_users (email);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS app_users_set_updated_at ON app_users;
CREATE TRIGGER app_users_set_updated_at
  BEFORE UPDATE ON app_users
  FOR EACH ROW
  EXECUTE PROCEDURE set_updated_at();

