-- Production only. Run AFTER schema.sql, as the schema owner/DBA, never as the API.
-- psql -X --set=ON_ERROR_STOP=1 --set=api_role=pam_api --file=app-permissions.sql
-- The admin provisions this existing LOGIN role separately, without role memberships.
\set ON_ERROR_STOP on
BEGIN;
SELECT set_config('pam.api_role', :'api_role', true);

DO $guard$
DECLARE
    api oid;
BEGIN
    SELECT oid INTO api FROM pg_roles WHERE rolname = current_setting('pam.api_role');
    IF api IS NULL THEN
        RAISE EXCEPTION 'The API role must already exist';
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE oid = api AND
        (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
        RAISE EXCEPTION 'The API role must not have administrative attributes';
    END IF;
    IF EXISTS (SELECT FROM pg_database WHERE datname = current_database()
        AND pg_has_role(api, datdba, 'MEMBER'))
        OR EXISTS (SELECT FROM pg_namespace WHERE nspname = 'public'
            AND pg_has_role(api, nspowner, 'MEMBER'))
        OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND pg_has_role(api, c.relowner, 'MEMBER')) THEN
        RAISE EXCEPTION 'The API role must not own the database, schema or application objects';
    END IF;
END
$guard$;

SELECT current_database() AS pam_database \gset
REVOKE CREATE ON DATABASE :"pam_database" FROM PUBLIC, :"api_role";
REVOKE CREATE ON SCHEMA public FROM PUBLIC, :"api_role";
GRANT CONNECT ON DATABASE :"pam_database" TO :"api_role";
GRANT USAGE ON SCHEMA public TO :"api_role";
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM :"api_role";
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM :"api_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"api_role";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO :"api_role";
REVOKE ALL PRIVILEGES ON TABLE public."__EFMigrationsHistory" FROM :"api_role";
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN
    ON TABLE public.audit_events FROM :"api_role";

-- Refuse inherited/PUBLIC grants that would defeat these restrictions.
DO $verify$
DECLARE
    api text := current_setting('pam.api_role');
BEGIN
    IF has_database_privilege(api, current_database(), 'CREATE')
        OR has_schema_privilege(api, 'public', 'CREATE')
        OR has_table_privilege(api, 'public.audit_events', 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
        OR has_table_privilege(api, 'public."__EFMigrationsHistory"',
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
        OR EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public'
            AND has_table_privilege(api, format('%I.%I', schemaname, tablename),
                'TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')) THEN
        RAISE EXCEPTION 'Inherited or PUBLIC privileges bypass the API restrictions; remove those grants first';
    END IF;
END
$verify$;
COMMIT;
