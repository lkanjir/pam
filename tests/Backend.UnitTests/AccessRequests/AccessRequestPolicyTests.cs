using Application.AccessRequests;

namespace Backend.UnitTests.AccessRequests;

public sealed class AccessRequestPolicyTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(30)]
    [InlineData(60)]
    public void Evaluate_EligibleWithinDurationLimit_RequiresManualApproval(int minutes)
    {
        // Arrange
        var request = Request(minutes, "INC-1042");

        // Act
        var result = AccessRequestPolicy.Evaluate(request, 60, true, true);

        // Assert
        Assert.Equal(AccessRequestPolicyDecision.RequireApproval, result.Decision);
        Assert.Equal("approval_required", result.ReasonCode);
        Assert.Equal("The request requires manual approval.", result.Explanation);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Evaluate_IneligibleRequester_DeniesRequest()
    {
        // Arrange
        var request = Request(30, "INC-1042");

        // Act
        var result = AccessRequestPolicy.Evaluate(request, 60, true, false);

        // Assert
        Assert.Equal(AccessRequestPolicyDecision.Deny, result.Decision);
        Assert.Equal("not_eligible", result.ReasonCode);
        Assert.Equal("The requester is not eligible for this entitlement.", result.Explanation);
        Assert.Empty(result.Errors);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(61)]
    public void Evaluate_InvalidDuration_ReturnsDurationError(int minutes)
    {
        // Arrange
        var request = Request(minutes, "INC-1042");

        // Act
        var result = AccessRequestPolicy.Evaluate(request, 60, true, true);

        // Assert
        Assert.Null(result.Decision);
        var error = Assert.Single(result.Errors);
        Assert.Equal(nameof(request.RequestedDurationMinutes), error.Key);
        Assert.Equal("Duration must be positive and within the entitlement maximum.", Assert.Single(error.Value));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Evaluate_RequiredTicketMissing_ReturnsTicketError(string? ticket)
    {
        // Arrange
        var request = Request(30, ticket);

        // Act
        var result = AccessRequestPolicy.Evaluate(request, 60, true, true);

        // Assert
        Assert.Null(result.Decision);
        var error = Assert.Single(result.Errors);
        Assert.Equal(nameof(request.TicketReference), error.Key);
        Assert.Equal("A ticket reference is required for this entitlement.", Assert.Single(error.Value));
    }

    [Fact]
    public void Evaluate_OptionalTicketMissing_StillRequiresApproval()
    {
        // Arrange
        var request = Request(30, null);

        // Act
        var result = AccessRequestPolicy.Evaluate(request, 60, false, true);

        // Assert
        Assert.Equal(AccessRequestPolicyDecision.RequireApproval, result.Decision);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Evaluate_InvalidIneligibleRequest_ReportsAllValidationErrors()
    {
        // Arrange
        var request = Request(61, null);

        // Act
        var result = AccessRequestPolicy.Evaluate(request, 60, true, false);

        // Assert
        Assert.Null(result.Decision);
        Assert.Equal(2, result.Errors.Count);
        Assert.Contains(nameof(request.RequestedDurationMinutes), result.Errors.Keys);
        Assert.Contains(nameof(request.TicketReference), result.Errors.Keys);
    }

    private static CreateAccessRequestRequest Request(int minutes, string? ticket) => new()
    {
        ResourceId = Guid.Parse("019a0000-0000-7000-8000-000000000001"),
        EntitlementId = Guid.Parse("019a0000-0000-7000-8000-000000000002"),
        RequestedDurationMinutes = minutes,
        Justification = "Deploy release",
        TicketReference = ticket
    };
}
