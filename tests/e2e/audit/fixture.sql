-- Scratch fixture for tests/e2e/audit/run.sh. Run as a superuser on a scratch DB.
-- 40 tables in public + 3 in schema billing = 43 tables. app_user owns all of
-- public's tables (41 incl. 1 RLS table) and has broad grants elsewhere.
CREATE ROLE fwa_app_user LOGIN;
CREATE ROLE fwa_admin NOLOGIN;
CREATE ROLE fwa_proxy LOGIN;
CREATE ROLE fwa_readers NOLOGIN;
GRANT fwa_readers TO fwa_app_user;           -- inherited privileges path
CREATE SCHEMA billing AUTHORIZATION fwa_admin;
GRANT USAGE ON SCHEMA billing TO fwa_readers;
GRANT CREATE ON SCHEMA public TO fwa_app_user;

SET ROLE fwa_app_user;
CREATE TABLE users (id serial PRIMARY KEY, email text, name text, password_hash text, created_at timestamptz DEFAULT now());
CREATE TABLE api_tokens (id serial PRIMARY KEY, user_id int, token text, label text);
CREATE TABLE customers (id serial PRIMARY KEY, name text, ssn text, city text);
CREATE TABLE orders (id serial PRIMARY KEY, customer_id int, total numeric, status text);
CREATE TABLE tickets (id serial PRIMARY KEY, subject text, body text, status text);
CREATE TABLE "Weird Table" (id int, "Mixed Case" text, "select" text, "a""quote" text);
CREATE TABLE tenant_notes (id serial PRIMARY KEY, tenant text, note text);
ALTER TABLE tenant_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_notes_all ON tenant_notes USING (true);
DO $$ BEGIN
  FOR i IN 1..33 LOOP
    EXECUTE format('CREATE TABLE filler_%s (id serial PRIMARY KEY, label text, amount int)', lpad(i::text, 2, '0'));
  END LOOP;
END $$;
CREATE VIEW user_logins AS SELECT id, email, password_hash FROM users;
CREATE VIEW order_totals AS SELECT customer_id, sum(total) AS total FROM orders GROUP BY 1;
INSERT INTO users (email, name, password_hash) VALUES ('a@example.com', 'A', 'x'), ('b@example.com', 'B', 'y');
INSERT INTO orders (customer_id, total, status) VALUES (1, 10, 'new'), (2, 20, 'paid');
INSERT INTO tickets (subject, body, status) VALUES ('hi', 'body', 'open');
RESET ROLE;

-- billing: owned by admin, app_user gets broad grants via fwa_readers + direct
SET ROLE fwa_admin;
CREATE TABLE billing.invoices (id serial PRIMARY KEY, amount numeric, card_token text);
CREATE TABLE billing.payouts (id serial PRIMARY KEY, amount numeric);
CREATE TABLE billing.ledger (id serial PRIMARY KEY, entry text);
GRANT SELECT ON ALL TABLES IN SCHEMA billing TO fwa_readers;
GRANT INSERT, UPDATE, DELETE, TRUNCATE ON billing.invoices, billing.payouts TO fwa_app_user;
RESET ROLE;

-- leave the RLS table forced off: app_user owns it, so RLS does not apply to it
