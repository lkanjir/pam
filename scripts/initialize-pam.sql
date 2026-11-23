-- Review and replace these three values with a dedicated PAM-realm user's
-- validated OIDC issuer, verified immutable subject and display name.
-- Run once as a database administrator after applying the reviewed schema.
-- No passwords or tokens belong in this script or the PAM database.
BEGIN;
SELECT pg_advisory_xact_lock(1885433137, 1768843636);
LOCK TABLE pam_roles IN EXCLUSIVE MODE;
DO $installation$
DECLARE
    verified_issuer text := 'SET_VALIDATED_ISSUER';
    verified_subject text := 'SET_VERIFIED_SUBJECT';
    bootstrap_name text := 'SET_BOOTSTRAP_DISPLAY_NAME';
    bootstrap_id bigint;
    admin_role_id integer;
    installed_at timestamptz := clock_timestamp();
BEGIN
    IF verified_issuer = 'SET_VALIDATED_ISSUER' OR verified_subject = 'SET_VERIFIED_SUBJECT'
        OR bootstrap_name = 'SET_BOOTSTRAP_DISPLAY_NAME'
        OR length(btrim(verified_issuer)) = 0 OR length(verified_issuer) > 2048
        OR length(btrim(verified_subject)) = 0 OR length(verified_subject) > 255
        OR length(btrim(bootstrap_name)) = 0 OR length(btrim(bootstrap_name)) > 200 THEN
        RAISE EXCEPTION 'Replace and validate the installation identity before running this script';
    END IF;
    IF EXISTS (SELECT 1 FROM pam_installation)
        OR EXISTS (SELECT 1 FROM pam_role_assignments a JOIN pam_roles r ON r.id = a.role_id WHERE r.code = 'admin') THEN
        RAISE EXCEPTION 'Installation already initialized or an administrator already exists';
    END IF;
    IF EXISTS (SELECT 1 FROM principals WHERE issuer = verified_issuer AND subject = verified_subject) THEN
        RAISE EXCEPTION 'Installation identity is already mapped';
    END IF;
    INSERT INTO principals (issuer, subject, display_name, is_enabled, created_at, modified_at)
        VALUES (verified_issuer, verified_subject, btrim(bootstrap_name), TRUE, installed_at, installed_at)
        RETURNING id INTO bootstrap_id;
    INSERT INTO pam_roles (code, description, created_at, created_by_principal_id)
        VALUES ('admin', 'Explicit administrative permission bundle', installed_at, bootstrap_id)
        ON CONFLICT (code) DO NOTHING;
    SELECT id INTO STRICT admin_role_id FROM pam_roles WHERE code = 'admin';
    INSERT INTO pam_role_assignments (principal_id, role_id, assigned_at, assigned_by_principal_id)
        VALUES (bootstrap_id, admin_role_id, installed_at, bootstrap_id);
    INSERT INTO pam_installation (id, bootstrap_principal_id, initialized_at)
        VALUES (1, bootstrap_id, installed_at);
    INSERT INTO audit_events (event_type, schema_version, occurred_at, actor_kind, subject_principal_id,
        subject_snapshot, metadata, correlation_id, source, outcome, reason_code)
        SELECT 'bootstrap.initialized', 1, installed_at, 'system', bootstrap_id,
            jsonb_build_object('publicId', public_id, 'issuer', issuer, 'subject', subject, 'displayName', display_name),
            jsonb_build_object('roleCode', 'admin', 'reason', 'Controlled initial administrator installation'),
            uuidv7()::text, 'pam.installer', 'success', 'bootstrap_initialized'
        FROM principals WHERE id = bootstrap_id;
END
$installation$;
COMMIT;
