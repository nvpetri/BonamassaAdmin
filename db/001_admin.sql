-- Execute no SQL Editor do Neon como proprietário, depois das 8 migrations da API 0.13.1.
-- Não usa a URL de proprietário na aplicação. Este script não altera tabelas da API.
BEGIN;
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bonamassa_admin_reader') THEN
    CREATE ROLE bonamassa_admin_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bonamassa_admin_logger') THEN
    CREATE ROLE bonamassa_admin_logger LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
CREATE SCHEMA IF NOT EXISTS bonamassa_admin;
CREATE SCHEMA IF NOT EXISTS bonamassa_admin_private;
REVOKE ALL ON SCHEMA bonamassa_admin, bonamassa_admin_private FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM bonamassa_admin_reader, bonamassa_admin_logger;

CREATE OR REPLACE FUNCTION bonamassa_admin_private.safe_json(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE result jsonb; item record;
BEGIN
  IF value IS NULL THEN RETURN NULL; END IF;
  IF jsonb_typeof(value) = 'object' THEN
    result := '{}'::jsonb;
    FOR item IN SELECT * FROM jsonb_each(value) LOOP
      IF lower(item.key) ~ '(password|token|secret|authorization|cookie|codehash|sessionkey|credential)'
        OR lower(item.key) IN ('bytes','email','phone','customer','address','recipient','note','reference','reason','location','origin','destination','latitude','longitude','lat','lng','lon') THEN
        result := result || jsonb_build_object(item.key, '[REDACTED]');
      ELSE result := result || jsonb_build_object(item.key, bonamassa_admin_private.safe_json(item.value)); END IF;
    END LOOP;
    RETURN result;
  ELSIF jsonb_typeof(value) = 'array' THEN
    SELECT COALESCE(jsonb_agg(bonamassa_admin_private.safe_json(v)), '[]'::jsonb)
      INTO result FROM jsonb_array_elements(value) v;
    RETURN result;
  END IF;
  RETURN value;
END $$;
REVOKE ALL ON FUNCTION bonamassa_admin_private.safe_json(jsonb) FROM PUBLIC;

CREATE TABLE IF NOT EXISTS bonamassa_admin_private."AdminAccessLog" (
  id bigserial PRIMARY KEY,
  "requestId" uuid NOT NULL,
  actor text NOT NULL,
  event varchar(30) NOT NULL,
  outcome varchar(30) NOT NULL,
  fingerprint char(64),
  "queryTemplate" text,
  tables text[] NOT NULL DEFAULT '{}',
  "rowCount" integer,
  "durationMs" integer,
  "peerHash" char(64),
  "createdAt" timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS admin_log_created_idx ON bonamassa_admin_private."AdminAccessLog" ("createdAt", id);
CREATE OR REPLACE FUNCTION bonamassa_admin_private.prevent_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN RAISE EXCEPTION 'AdminAccessLog is append-only'; END $$;
REVOKE ALL ON FUNCTION bonamassa_admin_private.prevent_change() FROM PUBLIC;
DROP TRIGGER IF EXISTS admin_log_immutable ON bonamassa_admin_private."AdminAccessLog";
CREATE TRIGGER admin_log_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bonamassa_admin_private."AdminAccessLog"
FOR EACH STATEMENT EXECUTE FUNCTION bonamassa_admin_private.prevent_change();

CREATE OR REPLACE VIEW bonamassa_admin."Store" WITH (security_barrier = true) AS
SELECT "id", "slug", "name", "open", "scheduleEnabled", "opensAt", "closesAt", "overrideOpen", "overrideUntil", bonamassa_admin_private.safe_json("address") AS "address", bonamassa_admin_private.safe_json("location") AS "location", "deliveryPricingMode", bonamassa_admin_private.safe_json("deliveryBands") AS "deliveryBands", "deliveryFee", "driverFee", "version", "nextNumber", "createdAt" FROM public."Store";

CREATE OR REPLACE VIEW bonamassa_admin."User" WITH (security_barrier = true) AS
SELECT "id", "storeId", "name", "role", "enabled", "available", "version", "createdAt", "emailVerifiedAt", "onboardingPending" FROM public."User";

CREATE OR REPLACE VIEW bonamassa_admin."VerificationCode" WITH (security_barrier = true) AS
SELECT "id", "userId", "purpose", "expiresAt", "consumedAt", "attempts", "createdAt" FROM public."VerificationCode";

CREATE OR REPLACE VIEW bonamassa_admin."Session" WITH (security_barrier = true) AS
SELECT "id", "userId", "expiresAt", "lastActivityAt", "createdAt" FROM public."Session";

CREATE OR REPLACE VIEW bonamassa_admin."Product" WITH (security_barrier = true) AS
SELECT "storeId", "id", "category", "nameKey", "version", bonamassa_admin_private.safe_json("data") AS "data", "imageId" FROM public."Product";

CREATE OR REPLACE VIEW bonamassa_admin."ProductImage" WITH (security_barrier = true) AS
SELECT "id", "storeId", "digest", "createdAt" FROM public."ProductImage";

CREATE OR REPLACE VIEW bonamassa_admin."Promotion" WITH (security_barrier = true) AS
SELECT "storeId", "id", "version", bonamassa_admin_private.safe_json("data") AS "data", "pizzaLimit", "reserved", "sold" FROM public."Promotion";

CREATE OR REPLACE VIEW bonamassa_admin."Quote" WITH (security_barrier = true) AS
SELECT "id", "storeId", "userId", bonamassa_admin_private.safe_json("priced") AS "priced", "fingerprint", "expiresAt", "createdAt" FROM public."Quote";

CREATE OR REPLACE VIEW bonamassa_admin."Order" WITH (security_barrier = true) AS
SELECT "id", "storeId", "number", "quoteId", "customerId", "driverId", "status", "scheduledFor", "deliveryStatus", "version", "mode", "channel", bonamassa_admin_private.safe_json("items") AS "items", "subtotal", "fee", "discount", "total", "payment", "paymentRecorded", "cashTendered", "driverFee", "promotionId", bonamassa_admin_private.safe_json("promotionSnapshot") AS "promotionSnapshot", "promotionQuantity", "createdAt", "updatedAt" FROM public."Order";

CREATE OR REPLACE VIEW bonamassa_admin."OrderEvent" WITH (security_barrier = true) AS
SELECT "id", "orderId", "version", "action", "actorId", bonamassa_admin_private.safe_json("data") AS "data", "createdAt" FROM public."OrderEvent";

CREATE OR REPLACE VIEW bonamassa_admin."Idempotency" WITH (security_barrier = true) AS
SELECT "storeId", "userId", "createdAt" FROM public."Idempotency";

CREATE OR REPLACE VIEW bonamassa_admin."RateBucket" WITH (security_barrier = true) AS
SELECT "count", "resetsAt" FROM public."RateBucket";

CREATE OR REPLACE VIEW bonamassa_admin."Audit" WITH (security_barrier = true) AS
SELECT "id", "storeId", "actorId", "action", bonamassa_admin_private.safe_json("data") AS "data", "createdAt" FROM public."Audit";

CREATE OR REPLACE VIEW bonamassa_admin."StaffInvitation" WITH (security_barrier = true) AS
SELECT "id", "userId", "expiresAt", "consumedAt", "sentAt", "createdAt" FROM public."StaffInvitation";

CREATE OR REPLACE VIEW bonamassa_admin."AuditTrail" WITH (security_barrier = true) AS
SELECT "id", "storeId", "tableName", "recordId", "operation", "actorId", "actorName", "actorRole", "sharedAccount", "origin", "clientSource", "requestId", "action", "method", "path", "databaseUser", "transactionId", "changedFields", bonamassa_admin_private.safe_json("before") AS "before", bonamassa_admin_private.safe_json("after") AS "after", "createdAt" FROM public."AuditTrail";


CREATE OR REPLACE VIEW bonamassa_admin."AdminAccessLog" WITH (security_barrier = true) AS
SELECT id, "requestId", actor, event, outcome, fingerprint, "queryTemplate", tables, "rowCount", "durationMs", "createdAt"
FROM bonamassa_admin_private."AdminAccessLog";

GRANT USAGE ON SCHEMA bonamassa_admin, bonamassa_admin_private TO bonamassa_admin_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA bonamassa_admin TO bonamassa_admin_reader;
GRANT EXECUTE ON FUNCTION bonamassa_admin_private.safe_json(jsonb) TO bonamassa_admin_reader;
GRANT USAGE ON SCHEMA bonamassa_admin_private TO bonamassa_admin_logger;
GRANT INSERT ("requestId", actor, event, outcome, fingerprint, "queryTemplate", tables, "rowCount", "durationMs", "peerHash")
  ON bonamassa_admin_private."AdminAccessLog" TO bonamassa_admin_logger;
GRANT USAGE ON SEQUENCE bonamassa_admin_private."AdminAccessLog_id_seq" TO bonamassa_admin_logger;
ALTER ROLE bonamassa_admin_reader SET default_transaction_read_only = on;
ALTER ROLE bonamassa_admin_reader SET statement_timeout = '5s';
ALTER ROLE bonamassa_admin_reader SET lock_timeout = '1s';
ALTER ROLE bonamassa_admin_reader SET search_path = pg_catalog, bonamassa_admin;
ALTER ROLE bonamassa_admin_logger SET statement_timeout = '5s';
COMMIT;

-- Defina senhas fortes e diferentes para os dois papéis no Neon.
-- ALTER ROLE bonamassa_admin_reader PASSWORD 'SENHA_EXCLUSIVA_DE_LEITURA';
-- ALTER ROLE bonamassa_admin_logger PASSWORD 'OUTRA_SENHA_EXCLUSIVA_DE_AUDITORIA';
-- Não conceda neon_superuser, propriedade de objetos nem associação a outros papéis.
