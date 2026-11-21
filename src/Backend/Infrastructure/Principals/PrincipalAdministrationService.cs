using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Infrastructure.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Infrastructure.Principals;

public sealed class PrincipalAdministrationService(PamDbContext database, TimeProvider clock) : IPrincipalAdministrationService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

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
