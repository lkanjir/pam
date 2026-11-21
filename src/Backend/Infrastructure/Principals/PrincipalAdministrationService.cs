using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Infrastructure.Authentication;
using Infrastructure.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Infrastructure.Principals;

public sealed class PrincipalAdministrationService(PamDbContext database, TimeProvider clock, ISessionTicketStore tickets) : IPrincipalAdministrationService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<PrincipalWriteResult> DisableAsync(Guid id, ChangePrincipalStatusRequest request, AdministrativeActor actor,
        uint expectedVersion, string correlationId, CancellationToken cancellationToken = default)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        if (!await AdministrativeAuthorization.LockAdministrationGuardAsync(database, cancellationToken))
        {
            return new(PrincipalWriteKind.Forbidden);
        }
        var principals = await database.Principals.FromSql(
            $"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} OR public_id = {id} ORDER BY id FOR UPDATE")
            .AsNoTracking().ToListAsync(cancellationToken);
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor,
            PamPermissions.PrincipalsManage, cancellationToken);
        if (decision != AdministrativeDecision.Allowed)
        {
            return new(decision == AdministrativeDecision.Forbidden
                ? PrincipalWriteKind.Forbidden : PrincipalWriteKind.RecentAuthenticationRequired);
        }
        var target = principals.SingleOrDefault(principal => principal.PublicId == id);
        if (target is null)
        {
            return new(PrincipalWriteKind.NotFound);
        }
        if (target.Id == actor.Principal.Id)
        {
            return new(PrincipalWriteKind.SelfChangeForbidden);
        }
        if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
        {
            return new(PrincipalWriteKind.InvalidRequest);
        }
        if (target.Version != expectedVersion)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        var before = new PrincipalResponse(target.PublicId, target.Issuer, target.Subject, target.DisplayName, target.IsEnabled,
            new DateTimeOffset(target.CreatedAt, TimeSpan.Zero), new DateTimeOffset(target.ModifiedAt, TimeSpan.Zero))
        { Version = target.Version };
        if (!target.IsEnabled)
        {
            return new(PrincipalWriteKind.Succeeded, before);
        }
        if (await AdministrativeAuthorization.WouldRemoveLastAdminAsync(database, target.Id, cancellationToken))
        {
            return new(PrincipalWriteKind.LastAdmin);
        }

        var now = clock.GetUtcNow();
        int changed = await database.Principals.Where(principal => principal.Id == target.Id && principal.Version == expectedVersion)
            .ExecuteUpdateAsync(update => update.SetProperty(principal => principal.IsEnabled, false)
                .SetProperty(principal => principal.ModifiedAt, now.UtcDateTime), cancellationToken);
        if (changed != 1)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        var after = await GetByIdAsync(id, cancellationToken) ?? throw new InvalidOperationException("Locked principal was not found.");
        database.AuditEvents.Add(new AuditEvent
        {
            EventType = "principal.disabled",
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = target.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(after, JsonOptions),
            Metadata = JsonSerializer.Serialize(new { before, after, reason = request.Reason.Trim() }, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = "account_disabled"
        });
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(PrincipalWriteKind.Succeeded, after);
    }

    public async Task<PrincipalWriteResult> EnableAsync(Guid id, ChangePrincipalStatusRequest request, AdministrativeActor actor,
        uint expectedVersion, string correlationId, CancellationToken cancellationToken = default)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        if (!await AdministrativeAuthorization.LockAdministrationGuardAsync(database, cancellationToken))
        {
            return new(PrincipalWriteKind.Forbidden);
        }
        var principals = await database.Principals.FromSql(
            $"SELECT *, xmin FROM principals WHERE id = {actor.Principal.Id} OR public_id = {id} ORDER BY id FOR UPDATE")
            .AsNoTracking().ToListAsync(cancellationToken);
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor,
            PamPermissions.PrincipalsManage, cancellationToken);
        if (decision != AdministrativeDecision.Allowed)
        {
            return new(decision == AdministrativeDecision.Forbidden
                ? PrincipalWriteKind.Forbidden : PrincipalWriteKind.RecentAuthenticationRequired);
        }
        var target = principals.SingleOrDefault(principal => principal.PublicId == id);
        if (target is null)
        {
            return new(PrincipalWriteKind.NotFound);
        }
        if (target.Id == actor.Principal.Id)
        {
            return new(PrincipalWriteKind.SelfChangeForbidden);
        }
        if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true))
        {
            return new(PrincipalWriteKind.InvalidRequest);
        }
        if (target.Version != expectedVersion)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        var before = new PrincipalResponse(target.PublicId, target.Issuer, target.Subject, target.DisplayName, target.IsEnabled,
            new DateTimeOffset(target.CreatedAt, TimeSpan.Zero), new DateTimeOffset(target.ModifiedAt, TimeSpan.Zero))
        { Version = target.Version };
        if (target.IsEnabled)
        {
            return new(PrincipalWriteKind.Succeeded, before);
        }
        var recordedDisable = await database.AuditEvents
            .Where(audit => audit.SubjectPrincipalId == target.Id && audit.EventType == "principal.disabled")
            .OrderByDescending(audit => audit.Id).Select(audit => (DateTime?)audit.OccurredAt).FirstOrDefaultAsync(cancellationToken);
        var revokedAt = recordedDisable is { } recorded ? new DateTimeOffset(recorded, TimeSpan.Zero) : clock.GetUtcNow();
        if (!await PrincipalSessionRevocation.RevokeBeforeRestorationAsync(database, tickets, clock,
            target.Id, revokedAt, correlationId, cancellationToken))
        {
            return new(PrincipalWriteKind.SessionCleanupPending);
        }

        var now = clock.GetUtcNow();
        int changed = await database.Principals.Where(principal => principal.Id == target.Id && principal.Version == expectedVersion)
            .ExecuteUpdateAsync(update => update.SetProperty(principal => principal.IsEnabled, true)
                .SetProperty(principal => principal.ModifiedAt, now.UtcDateTime), cancellationToken);
        if (changed != 1)
        {
            return new(PrincipalWriteKind.PreconditionFailed);
        }
        var after = await GetByIdAsync(id, cancellationToken) ?? throw new InvalidOperationException("Locked principal was not found.");
        database.AuditEvents.Add(new AuditEvent
        {
            EventType = "principal.enabled",
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = target.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(after, JsonOptions),
            Metadata = JsonSerializer.Serialize(new { before, after, reason = request.Reason.Trim() }, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = "account_enabled"
        });
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(PrincipalWriteKind.Succeeded, after);
    }

    public async Task<PrincipalWriteResult> CreateAsync(CreatePrincipalRequest request, AdministrativeActor actor,
        string correlationId, CancellationToken cancellationToken = default)
    {
        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        if (!await AdministrativeAuthorization.LockAdministrationGuardAsync(database, cancellationToken))
        {
            return new(PrincipalWriteKind.Forbidden);
        }
        var decision = await AdministrativeAuthorization.CheckAsync(database, clock, actor,
            PamPermissions.PrincipalsManage, cancellationToken);
        if (decision != AdministrativeDecision.Allowed)
        {
            return new(decision == AdministrativeDecision.Forbidden
                ? PrincipalWriteKind.Forbidden : PrincipalWriteKind.RecentAuthenticationRequired);
        }
        // The configured OIDC realm supplies the actor's validated issuer. Subject is opaque;
        // do not silently normalize it into a different identity or use an email/display name.
        if (!Validator.TryValidateObject(request, new ValidationContext(request), null, validateAllProperties: true)
            || request.Issuer != actor.Principal.Issuer || request.Subject != request.Subject.Trim())
        {
            return new(PrincipalWriteKind.InvalidIdentity);
        }

        var now = clock.GetUtcNow();
        var principal = Principal.CreateMapping(request.Issuer, request.Subject, request.DisplayName, now);
        database.Principals.Add(principal);
        try
        {
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException error) when (error.InnerException is PostgresException
        { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "ix_principals_issuer_subject" })
        {
            return new(PrincipalWriteKind.Conflict);
        }

        var response = new PrincipalResponse(principal.PublicId, principal.Issuer, principal.Subject, principal.DisplayName,
            principal.IsEnabled, now, now);
        database.AuditEvents.Add(new AuditEvent
        {
            EventType = "principal.mapped",
            SchemaVersion = 1,
            OccurredAt = now.UtcDateTime,
            ActorKind = "principal",
            ActorPrincipalId = actor.Principal.Id,
            SubjectPrincipalId = principal.Id,
            ActorSnapshot = JsonSerializer.Serialize(actor.Principal, JsonOptions),
            SubjectSnapshot = JsonSerializer.Serialize(response, JsonOptions),
            Metadata = JsonSerializer.Serialize(new { before = (object?)null, after = response, reason = request.Reason.Trim() }, JsonOptions),
            CorrelationId = correlationId,
            Source = "pam.api",
            Outcome = "success",
            ReasonCode = "identity_mapping"
        });
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(PrincipalWriteKind.Succeeded, response);
    }

    public Task<PrincipalResponse?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        database.Principals.AsNoTracking().Where(principal => principal.PublicId == id)
            .Select(principal => new PrincipalResponse(principal.PublicId, principal.Issuer, principal.Subject,
                principal.DisplayName, principal.IsEnabled, new DateTimeOffset(principal.CreatedAt, TimeSpan.Zero),
                new DateTimeOffset(principal.ModifiedAt, TimeSpan.Zero))
            { Version = principal.Version })
            .SingleOrDefaultAsync(cancellationToken);

    public async Task<CursorPage<PrincipalResponse>> ListAsync(int limit, PrincipalCursor? cursor,
        CancellationToken cancellationToken = default)
    {
        var query = database.Principals.AsNoTracking();
        if (cursor is not null)
        {
            Guid lastId = cursor.LastPublicId;
            query = query.Where(principal => principal.PublicId.CompareTo(lastId) > 0);
        }
        var items = await query.OrderBy(principal => principal.PublicId).Take(limit + 1)
            .Select(principal => new PrincipalResponse(principal.PublicId, principal.Issuer, principal.Subject,
                principal.DisplayName, principal.IsEnabled, new DateTimeOffset(principal.CreatedAt, TimeSpan.Zero),
                new DateTimeOffset(principal.ModifiedAt, TimeSpan.Zero)))
            .ToListAsync(cancellationToken);
        bool hasMore = items.Count > limit;
        if (hasMore)
        {
            items.RemoveAt(limit);
        }
        return new(items, hasMore ? CursorCodec.Encode(new PrincipalCursor(items[^1].Id)) : null);
    }
}
