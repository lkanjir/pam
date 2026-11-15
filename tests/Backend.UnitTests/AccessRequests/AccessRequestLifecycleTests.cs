using Application.AccessRequests;
using Infrastructure.Persistence.Entities;

namespace Backend.UnitTests.AccessRequests;

public sealed class AccessRequestLifecycleTests
{
    [Theory]
    [InlineData(AccessRequestPolicyDecision.Deny, "Denied")]
    [InlineData(AccessRequestPolicyDecision.RequireApproval, "PendingApproval")]
    public void Submit_ExplicitPolicyDecision_PreservesInitialWireCodes(AccessRequestPolicyDecision decision, string code)
    {
        // Act
        var request = new AccessRequest(decision.InitialState());
        var policy = new PolicyEvaluation(decision);

        // Assert
        Assert.Equal(code, request.State);
        Assert.Equal(code, policy.Decision);
        Assert.Equal(decision, AccessRequestPolicyDecisions.Parse(code));
    }

    [Theory]
    [InlineData(AccessRequestState.Approved, "Approved")]
    [InlineData(AccessRequestState.Rejected, "Rejected")]
    [InlineData(AccessRequestState.Cancelled, "Cancelled")]
    [InlineData(AccessRequestState.Expired, "Expired")]
    public void Transition_PendingRequest_EntersAllowedTerminalState(AccessRequestState next, string code)
    {
        // Arrange
        var request = new AccessRequest(AccessRequestState.PendingApproval);

        // Act
        request.TransitionTo(next);

        // Assert
        Assert.Equal(code, request.State);
    }

    [Theory]
    [InlineData(AccessRequestState.Denied, "Denied")]
    [InlineData(AccessRequestState.Approved, "Approved")]
    [InlineData(AccessRequestState.Rejected, "Rejected")]
    [InlineData(AccessRequestState.Cancelled, "Cancelled")]
    [InlineData(AccessRequestState.Expired, "Expired")]
    public void Transition_TerminalRequest_CannotReopen(AccessRequestState state, string code)
    {
        // Arrange
        var request = new AccessRequest(state == AccessRequestState.Denied ? state : AccessRequestState.PendingApproval);
        if (state != AccessRequestState.Denied)
        {
            request.TransitionTo(state);
        }

        // Act
        var error = Record.Exception(() => request.TransitionTo(AccessRequestState.PendingApproval));

        // Assert
        Assert.IsType<InvalidOperationException>(error);
        Assert.Equal(code, request.State);
    }

    [Theory]
    [InlineData(AccessRequestState.Approved)]
    [InlineData((AccessRequestState)999)]
    public void Submit_NonSubmissionState_IsRejected(AccessRequestState state)
    {
        // Act
        var error = Record.Exception(() => new AccessRequest(state));

        // Assert
        Assert.IsType<ArgumentOutOfRangeException>(error);
    }
}
