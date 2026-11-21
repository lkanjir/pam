using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Api.Resources;
using Application.Authorization;
using Application.Bootstrap;
using Application.Principals;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Infrastructure.Authentication;
using Infrastructure.Bootstrap;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection1.Name)]
public sealed class BootstrapHandoverTests(PostgresFixture postgres, RedisFixture redis)
{
    private const string CompleteUrl = "/api/authorization/bootstrap/complete";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Complete_PermanentFreshAdmin_RetiresAllBootstrapPermissionsWithExactAtomicAudits(bool retired)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var bootstrap = await SeedBootstrapAsync(test);
        await AddRetainedAssignmentsAsync(test, bootstrap);
        if (retired)
        {
            await test.Database.Context.ManagedResources.Where(value => value.Id == test.Resource.Id)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.DeletedAt, test.Clock.Now.UtcDateTime));
        }
        using var original = test.CreateClient();
        using var login = await original.GetAsync($"/login?principal-id={bootstrap.Id}");
        login.EnsureSuccessStatusCode();
        SessionTestHost.UpdateCookie(original, login);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string before = await SetVersionAsync(test);
        long previousAudit = await test.Database.Context.AuditEvents.MaxAsync(value => value.Id);

        // Act
        using var response = await CompleteAsync(test);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<BootstrapStateResponse>();
        Assert.NotNull(state);
        Assert.True(state.IsInitialized);
        Assert.False(state.IsPending);
        Assert.Equal(bootstrap.PublicId, state.BootstrapPrincipalId);
        Assert.Equal(test.Clock.Now, state.CompletedAt);
        var permanent = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        Assert.Equal(permanent.PublicId, state.CompletedByPrincipalId);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(before, response.Headers.ETag.Tag);
        Assert.False(await test.Database.Context.Principals.AnyAsync(value => value.Id == bootstrap.Id && value.IsEnabled));
        Assert.False(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == bootstrap.Id));
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.IgnoreQueryFilters().AnyAsync(value => value.PrincipalId == bootstrap.Id && value.IsActive));
        Assert.False(await test.Database.Context.EligibilityRules.IgnoreQueryFilters().AnyAsync(value => value.PrincipalId == bootstrap.Id && value.IsEnabled));
        var audits = await test.Database.Context.AuditEvents.Where(value => value.SubjectPrincipalId == bootstrap.Id
            && value.Id > previousAudit).ToListAsync();
        Assert.Equal(8, audits.Count); // Three roles, view, eligibility, authority, disable and completion.
        Assert.Equal(3, audits.Count(value => value.EventType == "role.removed"));
        Assert.Single(audits, value => value.EventType == "resource_access.deactivated");
        Assert.Single(audits, value => value.EventType == "eligibility.deactivated");
        Assert.Single(audits, value => value.EventType == "approval_authority.deactivated");
        Assert.Single(audits, value => value.EventType == "principal.disabled" && value.ReasonCode == "account_disabled");
        Assert.Single(audits, value => value.EventType == "bootstrap.completed");
        foreach (var audit in audits)
        {
            Assert.Equal(test.ActorId, audit.ActorPrincipalId);
            Assert.Equal(test.Clock.Now.UtcDateTime, audit.OccurredAt);
            Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
            using var metadata = JsonDocument.Parse(Assert.IsType<string>(audit.Metadata));
            Assert.Equal("Verified permanent administrator handover", metadata.RootElement.GetProperty("reason").GetString());
        }
        var session = await test.Database.Context.AuthenticationSessionLedgers.SingleAsync(value => value.PrincipalId == bootstrap.Id);
        await using var scope = test.CreateScope();
        Assert.True((await scope.ServiceProvider.GetRequiredService<ISessionTicketStore>().ObserveAsync(session.SessionIdHash)).HasTicket);
        using var rejected = await original.GetAsync("/api/principals");
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        using var stillAdmin = await test.Client.GetAsync("/api/principals");
        Assert.Equal(HttpStatusCode.OK, stillAdmin.StatusCode);
    }

    [Theory]
    [InlineData("completion")]
    [InlineData("disable")]
    [InlineData("role")]
    [InlineData("eligibility")]
    [InlineData("view")]
    [InlineData("authority")]
    public async Task Complete_AnyRequiredAuditRejected_RollsBackEntireHandover(string rejected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var bootstrap = await SeedBootstrapAsync(test);
        await AddRetainedAssignmentsAsync(test, bootstrap);
        string constraint = rejected switch
        {
            "completion" => "ALTER TABLE audit_events ADD CONSTRAINT reject_handover CHECK (event_type <> 'bootstrap.completed')",
            "disable" => "ALTER TABLE audit_events ADD CONSTRAINT reject_handover CHECK (event_type <> 'principal.disabled')",
            "role" => "ALTER TABLE audit_events ADD CONSTRAINT reject_handover CHECK (event_type <> 'role.removed')",
            "eligibility" => "ALTER TABLE audit_events ADD CONSTRAINT reject_handover CHECK (event_type <> 'eligibility.deactivated')",
            "view" => "ALTER TABLE audit_events ADD CONSTRAINT reject_handover CHECK (event_type <> 'resource_access.deactivated')",
            _ => "ALTER TABLE audit_events ADD CONSTRAINT reject_handover CHECK (event_type <> 'approval_authority.deactivated')"
        };
        await test.Database.Context.Database.ExecuteSqlRawAsync(constraint);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string version = await SetVersionAsync(test);

        // Act
        using var response = await CompleteAsync(test);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.True(await test.Database.Context.Principals.AnyAsync(value => value.Id == bootstrap.Id && value.IsEnabled));
        Assert.Equal(3, await test.Database.Context.PamRoleAssignments.CountAsync(value => value.PrincipalId == bootstrap.Id));
        Assert.Equal(2, await test.Database.Context.ResourcePrincipalBindings.IgnoreQueryFilters().CountAsync(value => value.PrincipalId == bootstrap.Id && value.IsActive));
        Assert.True(await test.Database.Context.EligibilityRules.IgnoreQueryFilters().AnyAsync(value => value.PrincipalId == bootstrap.Id && value.IsEnabled));
        await AssertPendingAsync(test);
        Assert.Equal(version, await SetVersionAsync(test));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.SubjectPrincipalId == bootstrap.Id));
    }

    [Fact]
    public async Task Complete_CurrentCompletedRetry_IsNoOpAndCannotReactivateBootstrap()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var bootstrap = await SeedBootstrapAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test);
        using var completed = await CompleteAsync(test);
        Assert.Equal(HttpStatusCode.OK, completed.StatusCode);
        await SetVersionAsync(test);
        int count = await test.Database.Context.AuditEvents.CountAsync();

        // Act
        using var replay = await CompleteAsync(test);
        await test.RefreshVersionAsync($"/api/principals/{bootstrap.PublicId}");
        using var enable = await test.Client.PostAsJsonAsync($"/api/principals/{bootstrap.PublicId}/enable",
            new ChangePrincipalStatusRequest { Reason = "Cannot reopen completed installation" });

        // Assert
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(completed.Headers.ETag, replay.Headers.ETag);
        Assert.Equal(await completed.Content.ReadAsStringAsync(), await replay.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Conflict, enable.StatusCode);
        Assert.Contains("bootstrap_identity_protected", await enable.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(count, await test.Database.Context.AuditEvents.CountAsync());
        Assert.False(await test.Database.Context.Principals.AnyAsync(value => value.Id == bootstrap.Id && value.IsEnabled));
    }

    [Theory]
    [InlineData("anonymous", 401)]
    [InlineData("user", 403)]
    [InlineData("bootstrap", 403)]
    [InlineData("no-time", 403)]
    [InlineData("old-time", 403)]
    [InlineData("csrf", 400)]
    [InlineData("no-version", 428)]
    [InlineData("weak-version", 400)]
    [InlineData("stale-version", 412)]
    [InlineData("empty-reason", 400)]
    [InlineData("long-reason", 400)]
    public async Task Complete_AuthenticationFreshnessCsrfVersionAndValidation_AreRequired(string fault, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: fault == "user" ? ["user"] : ["admin"]);
        if (fault == "bootstrap")
        {
            await BootstrapTestData.MarkActorAsync(test);
        }
        else
        {
            await SeedBootstrapAsync(test);
        }
        if (fault != "anonymous")
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: fault != "no-time");
        }
        var installation = await test.Database.Context.PamInstallations.AsNoTracking().SingleAsync();
        test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", ResourceEtags.Format(installation.Version));
        if (fault == "old-time")
        {
            test.Clock.Now = test.Clock.Now.AddSeconds(601);
        }
        if (fault == "csrf")
        {
            test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        }
        if (fault is "no-version" or "weak-version" or "stale-version")
        {
            test.Client.DefaultRequestHeaders.Remove("If-Match");
            if (fault != "no-version")
            {
                test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", fault == "weak-version"
                    ? "W/" + ResourceEtags.Format(installation.Version) : ResourceEtags.Format(1));
            }
        }
        var request = new CompleteBootstrapRequest
        { Reason = fault switch { "empty-reason" => " ", "long-reason" => new string('x', 501), _ => "Handover" } };

        // Act
        using var response = await test.Client.PostAsJsonAsync(CompleteUrl, request);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertPendingAsync(test);
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "bootstrap.completed"));
        if (fault is "no-time" or "old-time")
        {
            Assert.Contains("recent_auth_required", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("disabled", BootstrapWriteKind.Forbidden)]
    [InlineData("role-removed", BootstrapWriteKind.Forbidden)]
    [InlineData("public-id", BootstrapWriteKind.Forbidden)]
    [InlineData("issuer", BootstrapWriteKind.Forbidden)]
    [InlineData("subject", BootstrapWriteKind.Forbidden)]
    [InlineData("bootstrap", BootstrapWriteKind.Forbidden)]
    [InlineData("no-time", BootstrapWriteKind.RecentAuthenticationRequired)]
    [InlineData("old-time", BootstrapWriteKind.RecentAuthenticationRequired)]
    [InlineData("empty-reason", BootstrapWriteKind.InvalidRequest)]
    [InlineData("long-reason", BootstrapWriteKind.InvalidRequest)]
    public async Task Complete_DirectCaller_RechecksCurrentIdentityFreshnessAndValidation(string fault, BootstrapWriteKind expected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var bootstrap = await SeedBootstrapAsync(test);
        var actor = await ActorAsync(test);
        if (fault == "disabled")
        {
            await test.Database.Context.Principals.Where(value => value.Id == test.ActorId)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, false));
        }
        else if (fault == "role-removed")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == test.ActorId).ExecuteDeleteAsync();
        }
        else if (fault is "issuer" or "subject" or "public-id")
        {
            actor = actor with
            {
                Principal = fault switch
                {
                    "issuer" => actor.Principal with { Issuer = "other-issuer" },
                    "subject" => actor.Principal with { Subject = "other-subject" },
                    _ => actor.Principal with { PublicId = Guid.NewGuid() }
                }
            };
        }
        else if (fault == "bootstrap")
        {
            actor = new(new PrincipalSnapshot(bootstrap.Id, bootstrap.PublicId, bootstrap.DisplayName, bootstrap.Issuer, bootstrap.Subject), test.Clock.Now);
        }
        else if (fault is "no-time" or "old-time")
        {
            actor = actor with { AuthenticatedAt = fault == "no-time" ? null : test.Clock.Now.AddSeconds(-601) };
        }
        var request = new CompleteBootstrapRequest
        { Reason = fault switch { "empty-reason" => " ", "long-reason" => new string('x', 501), _ => "Review" } };
        var installation = await test.Database.Context.PamInstallations.AsNoTracking().SingleAsync();

        // Act
        var result = await new BootstrapService(test.Database.Context, test.Clock).CompleteAsync(request, actor,
            installation.Version, "direct");

        // Assert
        Assert.Equal(expected, result.Kind);
        await AssertPendingAsync(test);
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "bootstrap.completed"));
    }

    [Fact]
    public async Task Complete_OpenApi_DocumentsMethodVersionAndSecurityFailures()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var operation = document.RootElement.GetProperty("paths").GetProperty(CompleteUrl).GetProperty("post");
        Assert.Equal("Bootstrap.Complete", operation.GetProperty("operationId").GetString());
        var version = Assert.Single(operation.GetProperty("parameters").EnumerateArray(),
            value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(version.GetProperty("required").GetBoolean());
        foreach (string status in new[] { "200", "400", "401", "403", "409", "412", "428" })
        {
            Assert.True(operation.GetProperty("responses").TryGetProperty(status, out _));
        }
    }

    [Fact]
    public async Task Complete_ConcurrentHandoverWithSameVersion_OnlyOneCommits()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await SeedBootstrapAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test);

        // Act
        var responses = await Task.WhenAll(test.Client.PostAsJsonAsync(CompleteUrl, Reason()), test.Client.PostAsJsonAsync(CompleteUrl, Reason()));
        using var first = responses[0];
        using var second = responses[1];

        // Assert
        Assert.Single(responses, value => value.StatusCode == HttpStatusCode.OK);
        Assert.Single(responses, value => value.StatusCode == HttpStatusCode.PreconditionFailed);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "bootstrap.completed"));
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "principal.disabled"));
    }

    [Fact]
    public async Task Complete_NoInstallation_DoesNotCreateOrInferOne()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", ResourceEtags.Format(1));

        // Act
        using var response = await CompleteAsync(test);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("bootstrap_not_initialized", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.False(await test.Database.Context.PamInstallations.AnyAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "bootstrap.completed"));
    }

    private static async Task<Principal> SeedBootstrapAsync(ResourceTestContext test)
    {
        var principal = Principal.CreateMapping("issuer", "bootstrap", "Bootstrap", test.Clock.Now);
        test.Database.Context.Principals.Add(principal);
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Principals.Where(value => value.Id == principal.Id)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        await SessionTestHost.AssignRolesAsync(test.Database, principal.Id, "admin", "user", "approver");
        test.Database.Context.PamInstallations.Add(new PamInstallation
        { BootstrapPrincipalId = principal.Id, InitializedAt = test.Clock.Now.UtcDateTime });
        await test.Database.Context.SaveChangesAsync();
        return principal;
    }

    private static async Task AddRetainedAssignmentsAsync(ResourceTestContext test, Principal bootstrap)
    {
        test.AddViewBinding(test.Resource, bootstrap.Id);
        test.Database.Context.ResourcePrincipalBindings.Add(new ResourcePrincipalBinding
        {
            PrincipalId = bootstrap.Id,
            ResourceId = test.Resource.Id,
            Kind = ResourceBindingKind.ApproveRequests,
            AssignedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            AssignedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        });
        var entitlement = new Entitlement { ResourceId = test.Resource.Id, Code = "login", Name = "Login", IsActive = true, MaxDurationMinutes = 30 };
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        { PrincipalId = bootstrap.Id, Entitlement = entitlement, IsEnabled = true, CreatedAt = test.Clock.Now.UtcDateTime });
        await test.Database.Context.SaveChangesAsync();
    }

    private static async Task<AdministrativeActor> ActorAsync(ResourceTestContext test)
    {
        var principal = await test.Database.Context.Principals.SingleAsync(value => value.Id == test.ActorId);
        return new(new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject), test.Clock.Now);
    }

    private static async Task<string> SetVersionAsync(ResourceTestContext test)
    {
        using var response = await test.Client.GetAsync("/api/authorization/bootstrap");
        response.EnsureSuccessStatusCode();
        Assert.NotNull(response.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(response.Headers.ETag);
        return response.Headers.ETag.Tag;
    }

    private static async Task AssertPendingAsync(ResourceTestContext test)
    {
        var state = await test.Database.Context.PamInstallations.AsNoTracking().SingleAsync();
        Assert.Null(state.CompletedAt);
        Assert.Null(state.CompletedByPrincipalId);
    }

    private static Task<HttpResponseMessage> CompleteAsync(ResourceTestContext test) => test.Client.PostAsJsonAsync(CompleteUrl, Reason());
    private static CompleteBootstrapRequest Reason() => new() { Reason = " Verified permanent administrator handover " };
}
