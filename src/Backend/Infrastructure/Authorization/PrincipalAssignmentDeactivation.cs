using System.Text.Json;
using Application.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Authorization;

// Callers hold the target principal's exclusive lock and own the audit transaction.
internal static class PrincipalAssignmentDeactivation
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static Task<int> EligibilityAsync(PamDbContext database, Principal target, AdministrativeActor actor, DateTimeOffset now,
        string reason, string correlationId, string reasonCode, CancellationToken cancellationToken)
    {
        string actorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions);
        string subjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions);
        return database.Database.ExecuteSqlAsync($"""
            WITH deactivated AS (
                UPDATE eligibility_rules SET is_enabled = FALSE
                WHERE principal_id = {target.Id} AND is_enabled
                RETURNING public_id, entitlement_id
            )
            INSERT INTO audit_events
                (event_type, schema_version, occurred_at, actor_kind, actor_principal_id,
                 subject_principal_id, resource_id, entitlement_id, actor_snapshot, subject_snapshot,
                 correlation_id, source, outcome, reason_code, metadata)
            SELECT 'eligibility.deactivated', 1, {now.UtcDateTime}, 'principal', {actor.Principal.Id},
                {target.Id}, e.resource_id, e.id, {actorSnapshot}::jsonb, {subjectSnapshot}::jsonb,
                {correlationId}, 'pam.api', 'success', {reasonCode},
                jsonb_build_object('eligibilityId', d.public_id, 'before', TRUE, 'after', FALSE,
                    'reason', {reason}::text)
            FROM deactivated d JOIN entitlements e ON e.id = d.entitlement_id
            """, cancellationToken);
    }

    public static Task<int> ResourceBindingsAsync(PamDbContext database, Principal target, AdministrativeActor actor, DateTimeOffset now,
        string reason, string correlationId, ResourceBindingKind kind, string reasonCode, CancellationToken cancellationToken)
    {
        string actorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions);
        string subjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions);
        string eventType = kind == ResourceBindingKind.ViewResource ? "resource_access.deactivated" : "approval_authority.deactivated";
        string storedKind = kind.ToString();
        return database.Database.ExecuteSqlAsync($"""
            WITH deactivated AS (
                UPDATE resource_principal_bindings
                SET is_active = FALSE, modified_at = {now.UtcDateTime}, modified_by_principal_id = {actor.Principal.Id}
                WHERE principal_id = {target.Id} AND kind = {storedKind} AND is_active
                RETURNING public_id, resource_id
            )
            INSERT INTO audit_events
                (event_type, schema_version, occurred_at, actor_kind, actor_principal_id,
                 subject_principal_id, resource_id, actor_snapshot, subject_snapshot,
                 correlation_id, source, outcome, reason_code, metadata)
            SELECT {eventType}, 1, {now.UtcDateTime}, 'principal', {actor.Principal.Id},
                {target.Id}, d.resource_id, {actorSnapshot}::jsonb, {subjectSnapshot}::jsonb,
                {correlationId}, 'pam.api', 'success', {reasonCode},
                jsonb_build_object('bindingId', d.public_id, 'before', TRUE, 'after', FALSE,
                    'reason', {reason}::text)
            FROM deactivated d
            """, cancellationToken);
    }

}
