using Application.AccessRequests;

namespace Backend.UnitTests.AccessRequests;

public sealed class AccessRequestFingerprintTests
{
    private const string Fingerprint = "v1:37A2B5F272B1AC3EF264560965DD86DEE1DEBC4FCA166EF2769C93CC99837E39";

    [Fact]
    public void CreateV1_FrozenPayload_MatchesPersistedContractVector()
    {
        // Arrange
        var request = new CreateAccessRequestRequest
        {
            ResourceId = Guid.Parse("11111111-1111-4111-8111-111111111111"),
            EntitlementId = Guid.Parse("22222222-2222-4222-8222-222222222222"),
            RequestedDurationMinutes = 30,
            Justification = "Deploy release",
            TicketReference = "INC-1042"
        };

        // Act
        string result = AccessRequestFingerprint.CreateV1(request);

        // Assert
        Assert.Equal(Fingerprint, result);
    }

    [Theory]
    [InlineData(Fingerprint, true)]
    [InlineData("37A2B5F272B1AC3EF264560965DD86DEE1DEBC4FCA166EF2769C93CC99837E39", true)]
    [InlineData("v2:37A2B5F272B1AC3EF264560965DD86DEE1DEBC4FCA166EF2769C93CC99837E39", false)]
    [InlineData(null, false)]
    [InlineData("broken", false)]
    public void IsMatch_StoredVersions_AcceptsOnlyMatchingV1AndLegacy(string? stored, bool expected)
    {
        // Act
        bool result = AccessRequestFingerprint.IsMatch(stored, Fingerprint);

        // Assert
        Assert.Equal(expected, result);
    }
}
