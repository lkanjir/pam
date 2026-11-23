using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Application.Authorization;
using Application.Bootstrap;
using Infrastructure.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Bootstrap;

public sealed class BootstrapService(PamDbContext database, TimeProvider clock) : IBootstrapService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<BootstrapWriteResult> CompleteAsync(CompleteBootstrapRequest request, AdministrativeActor actor,
        uint expectedVersion, string correlationId, CancellationToken cancellationToken = default)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        if (!await AdministrativeAuthorization.LockAdministrationGuardAsync(database, cancellationToken))
        {
            return new(BootstrapWriteKind.Forbidden);
        }
        long? bootstrapId = await database.PamInstallations.Select(value => (long?)value.BootstrapPrincipalId)
            .SingleOrDefaultAsync(cancellationToken);
        long selectedBootstrapId = bootstrapId ?? 0;
        var principals = await database.Principals.FromSql(
            $"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} OR id = {selectedBootstrapId} ORDER BY id FOR UPDATE")
            .AsNoTracking().ToListAsync(cancellationToken);
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor, PamPermissions.BootstrapComplete, cancellationToken);
        if (decision != AdministrativeDecision.Allowed)
        {
            return new(decision == AdministrativeDecision.Forbidden
                ? BootstrapWriteKind.Forbidden : BootstrapWriteKind.RecentAuthenticationRequired);
        }
        if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
        {
            return new(BootstrapWriteKind.InvalidRequest);
        }
        var installation = await database.PamInstallations.FromSql($"SELECT *, xmin FROM pam_installation WHERE id = 1 FOR UPDATE")
            .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (installation is null)
        {
            return new(BootstrapWriteKind.NotInitialized);
        }
        if (installation.Version != expectedVersion)
        {
            return new(BootstrapWriteKind.PreconditionFailed);
        }
        if (installation.CompletedAt is not null)
        {
            return new(BootstrapWriteKind.Succeeded, await GetAsync(cancellationToken));
        }
        var target = principals.Single(value => value.Id == installation.BootstrapPrincipalId);
        var now = clock.GetUtcNow();
        string reason = request.Reason.Trim();
        await PrincipalAssignmentDeactivation.EligibilityAsync(database, target, actor, now, reason, correlationId,
            "bootstrap_completed", cancellationToken);
        await PrincipalAssignmentDeactivation.ResourceBindingsAsync(database, target, actor, now, reason, correlationId,
            ResourceBindingKind.ViewResource, "bootstrap_completed", cancellationToken);
        await PrincipalAssignmentDeactivation.ResourceBindingsAsync(database, target, actor, now, reason, correlationId,
            ResourceBindingKind.ApproveRequests, "bootstrap_completed", cancellationToken);
        await RemoveRolesAsync(target, actor, now, reason, correlationId, cancellationToken);
        await database.Principals.Where(value => value.Id == target.Id).ExecuteUpdateAsync(update => update
            .SetProperty(value => value.IsEnabled, false).SetProperty(value => value.ModifiedAt, now.UtcDateTime), cancellationToken);
        await database.PamInstallations.Where(value => value.Id == installation.Id).ExecuteUpdateAsync(update => update
            .SetProperty(value => value.CompletedAt, now.UtcDateTime)
            .SetProperty(value => value.CompletedByPrincipalId, actor.Principal.Id), cancellationToken);
        if (target.IsEnabled)
        {
            database.AuditEvents.Add(Audit("principal.disabled", "account_disabled", target, actor, now, correlationId,
                new { before = new { isEnabled = true }, after = new { isEnabled = false }, reason }));
        }
        database.AuditEvents.Add(Audit("bootstrap.completed", "bootstrap_completed", target, actor, now, correlationId,
            new { before = new { isPending = true }, after = new { isPending = false }, reason }));
        await database.SaveChangesAsync(cancellationToken);
        var state = await GetAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(BootstrapWriteKind.Succeeded, state);
    }

    private Task<int> RemoveRolesAsync(Principal target, AdministrativeActor actor, DateTimeOffset now,
        string reason, string correlationId, CancellationToken cancellationToken)
    {
        string actorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions);
        string subjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions);
        return database.Database.ExecuteSqlAsync($"""
            WITH removed AS (
                DELETE FROM pam_role_assignments WHERE principal_id = {target.Id} RETURNING role_id
            )
            INSERT INTO audit_events
                (event_type, schema_version, occurred_at, actor_kind, actor_principal_id, subject_principal_id,
                 actor_snapshot, subject_snapshot, correlation_id, source, outcome, reason_code, metadata)
            SELECT 'role.removed', 1, {now.UtcDateTime}, 'principal', {actor.Principal.Id}, {target.Id},
                {actorSnapshot}::jsonb, {subjectSnapshot}::jsonb, {correlationId}, 'pam.api', 'success', 'bootstrap_completed',
                jsonb_build_object('roleCode', r.code, 'before', TRUE, 'after', FALSE, 'reason', {reason}::text)
            FROM removed d JOIN pam_roles r ON r.id = d.role_id
            """, cancellationToken);
    }

    private static AuditEvent Audit(string eventType, string reasonCode, Principal target, AdministrativeActor actor,
        DateTimeOffset now, string correlationId, object metadata) => new()
        {
            EventType = eventType,
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = target.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(new { target.PublicId, target.Issuer, target.Subject, target.DisplayName }, JsonOptions),
            Metadata = JsonSerializer.Serialize(metadata, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = reasonCode
        };

    public async Task<BootstrapStateResponse> GetAsync(CancellationToken cancellationToken = default) =>
        await database.PamInstallations.AsNoTracking().Select(value => new BootstrapStateResponse(true,
            value.CompletedAt == null,
            value.BootstrapPrincipal == null ? null : value.BootstrapPrincipal.PublicId,
            value.InitializedAt, value.CompletedAt,
            value.CompletedByPrincipal == null ? null : value.CompletedByPrincipal.PublicId)
        { Version = value.Version }).SingleOrDefaultAsync(cancellationToken)
        ?? new BootstrapStateResponse(false, false, null, null, null, null);
}
