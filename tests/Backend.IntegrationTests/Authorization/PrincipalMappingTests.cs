using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Authorization;
using Application.Principals;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Infrastructure.Principals;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class PrincipalMappingTests(PostgresFixture postgres, RedisFixture redis)
{
    private static readonly string[] ForgedRoles = ["admin"];

    [Fact]
    public async Task Create_VerifiedIdentity_StoresOnlyDisabledMappingAndAtomicAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        var request = Payload();

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", new
        {
            request.Issuer,
            request.Subject,
            request.DisplayName,
            request.Reason,
            IsEnabled = true,
            Roles = ForgedRoles,
            Password = "ignored-test-value"
        });

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.DoesNotContain("ignored-test-value", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var principal = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(principal);
        Assert.Equal(request.Issuer, principal.Issuer);
        Assert.Equal(request.Subject, principal.Subject);
        Assert.Equal("Bob", principal.DisplayName);
        Assert.False(principal.IsEnabled);
        Assert.Equal(test.Clock.Now, principal.CreatedAt);
        Assert.Equal(test.Clock.Now, principal.ModifiedAt);
        Assert.NotNull(response.Headers.Location);
        using var get = await test.Client.GetAsync(response.Headers.Location);
        Assert.Equal(principal, await get.Content.ReadFromJsonAsync<PrincipalResponse>());
        var saved = await test.Database.Context.Principals.SingleAsync(value => value.PublicId == principal.Id);
        Assert.False(saved.IsEnabled);
        Assert.False(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == saved.Id));
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "principal.mapped");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(saved.Id, audit.SubjectPrincipalId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.Equal(test.Clock.Now.UtcDateTime, audit.OccurredAt);
        Assert.Equal("success", audit.Outcome);
        Assert.NotNull(audit.ActorSnapshot);
        using var actor = JsonDocument.Parse(audit.ActorSnapshot);
        var actorId = await test.Database.Context.Principals.Where(value => value.Id == test.ActorId)
            .Select(value => value.PublicId).SingleAsync();
        Assert.Equal(actorId, actor.RootElement.GetProperty("publicId").GetGuid());
        Assert.Equal("ana", actor.RootElement.GetProperty("subject").GetString());
        Assert.NotNull(audit.SubjectSnapshot);
        using var subject = JsonDocument.Parse(audit.SubjectSnapshot);
        Assert.Equal(principal.Id, subject.RootElement.GetProperty("id").GetGuid());
        Assert.Equal(request.Subject, subject.RootElement.GetProperty("subject").GetString());
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(JsonValueKind.Null, metadata.RootElement.GetProperty("before").ValueKind);
        Assert.Equal("Verified in Keycloak", metadata.RootElement.GetProperty("reason").GetString());
        Assert.False(metadata.RootElement.GetProperty("after").GetProperty("isEnabled").GetBoolean());
        Assert.Equal(principal.Id, metadata.RootElement.GetProperty("after").GetProperty("id").GetGuid());
        Assert.DoesNotContain("ignored-test-value", audit.Metadata, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("user", true, 0, true, 403)]
    [InlineData("approver", true, 0, true, 403)]
    [InlineData("", true, 0, true, 403)]
    [InlineData("admin", false, 0, true, 401)]
    [InlineData("admin", true, 601, true, 403)]
    [InlineData("admin", true, 0, false, 403)]
    public async Task Create_WithoutCurrentAdministrativeSessionOrFreshness_DoesNotMap(string role, bool signIn, int age,
        bool authenticationTime, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: role.Length == 0 ? [] : [role]);
        if (signIn)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: authenticationTime);
        }
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", Payload());

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertUnchangedAsync(test);
        if (signIn && role == "admin")
        {
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("recent_auth_required", problem.RootElement.GetProperty("code").GetString());
        }
    }

    [Fact]
    public async Task Create_ConcurrentDuplicateIdentity_CreatesOneMappingAndAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        var responses = await Task.WhenAll(test.Client.PostAsJsonAsync("/api/principals", Payload()),
            test.Client.PostAsJsonAsync("/api/principals", Payload()));
        using var first = responses[0];
        using var second = responses[1];

        // Assert
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Created);
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Conflict);
        Assert.Equal(1, await test.Database.Context.Principals.CountAsync(value => value.Subject == "bob-subject"));
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "principal.mapped"));
    }

    [Fact]
    public async Task Create_MissingCsrfToken_RejectsWithoutMapping()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", Payload());

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertUnchangedAsync(test);
    }

    [Fact]
    public async Task Create_FieldsAtMaximumLength_AcceptsExactValues()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        var request = Payload() with
        {
            Subject = new string('s', 255),
            DisplayName = new string('n', 200),
            Reason = new string('r', 500)
        };

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var principal = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(principal);
        Assert.Equal(request.Subject, principal.Subject);
        Assert.Equal(request.DisplayName, principal.DisplayName);
        Assert.False(principal.IsEnabled);
        var metadata = await test.Database.Context.AuditEvents.Where(value => value.EventType == "principal.mapped")
            .Select(value => value.Metadata).SingleAsync();
        Assert.NotNull(metadata);
        using var audit = JsonDocument.Parse(metadata);
        Assert.Equal(request.Reason, audit.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Create_AuditRejected_RollsBackAlreadyInsertedMapping()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_mapping CHECK (event_type <> 'principal.mapped')");

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", Payload());

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await AssertUnchangedAsync(test);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("subject")]
    public async Task Create_AnotherRealmOrNormalizedSubject_RejectsIdentityChange(string field)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        var request = field == "issuer" ? Payload() with { Issuer = "https://other.example/realms/pam" }
            : Payload() with { Subject = " bob-subject " };

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertUnchangedAsync(test);
    }

    [Theory]
    [InlineData("Issuer", 0)]
    [InlineData("Subject", 0)]
    [InlineData("DisplayName", 0)]
    [InlineData("Reason", 0)]
    [InlineData("Issuer", 2049)]
    [InlineData("Subject", 256)]
    [InlineData("DisplayName", 201)]
    [InlineData("Reason", 501)]
    public async Task Create_InvalidDto_UsesFrameworkValidationBeforePersistence(string field, int length)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        var payload = new Dictionary<string, string>
        {
            ["Issuer"] = Payload().Issuer,
            ["Subject"] = "bob-subject",
            ["DisplayName"] = "Bob",
            ["Reason"] = "Verified"
        };
        payload[field] = new string('x', length);

        // Act
        using var response = await test.Client.PostAsJsonAsync("/api/principals", payload);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(problem.RootElement.GetProperty("errors").TryGetProperty(field, out _));
        await AssertUnchangedAsync(test);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("public-id", PrincipalWriteKind.Forbidden)]
    [InlineData("subject", PrincipalWriteKind.Forbidden)]
    [InlineData("missing-principal", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("invalid-request", PrincipalWriteKind.InvalidIdentity)]
    public async Task Create_DirectCaller_RechecksCurrentIdentityAndAuthority(string fault, PrincipalWriteKind expected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var principal = await test.Database.Context.Principals.SingleAsync(value => value.Id == test.ActorId);
        var snapshot = new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject);
        if (fault == "role")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == test.ActorId).ExecuteDeleteAsync();
        }
        if (fault == "disabled")
        {
            await test.Database.Context.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE principals SET is_enabled = false WHERE id = {test.ActorId}");
        }
        if (fault == "public-id")
        {
            snapshot = snapshot with { PublicId = Guid.NewGuid() };
        }
        if (fault == "subject")
        {
            snapshot = snapshot with { Subject = "another-user" };
        }
        if (fault == "missing-principal")
        {
            snapshot = snapshot with { Id = long.MaxValue };
        }
        var actor = new AdministrativeActor(snapshot, fault == "freshness" ? test.Clock.Now.AddMinutes(-11) : test.Clock.Now);
        var service = new PrincipalAdministrationService(test.Database.Context, test.Clock);

        // Act
        var request = fault == "invalid-request" ? Payload() with { Reason = string.Empty } : Payload();
        var result = await service.CreateAsync(request, actor, "direct-call");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Principal);
        await AssertUnchangedAsync(test);
    }

    private static CreatePrincipalRequest Payload() => new()
    {
        Issuer = "https://identity.example/realms/pam",
        Subject = "bob-subject",
        DisplayName = " Bob ",
        Reason = " Verified in Keycloak "
    };

    private static async Task AssertUnchangedAsync(ResourceTestContext test)
    {
        Assert.Equal(2, await test.Database.Context.Principals.CountAsync());
        Assert.False(await test.Database.Context.Principals.AnyAsync(value => value.Subject == "bob-subject"));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "principal.mapped"));
    }
}
