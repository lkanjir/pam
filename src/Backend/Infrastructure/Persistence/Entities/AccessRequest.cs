using Application.AccessRequests;

namespace Infrastructure.Persistence.Entities;

public sealed class AccessRequest
{
    private AccessRequest() { }

    public AccessRequest(AccessRequestState initialState)
    {
        if (initialState is not (AccessRequestState.Denied or AccessRequestState.PendingApproval))
        {
            throw new ArgumentOutOfRangeException(nameof(initialState), "Requests must start from a submission outcome.");
        }

        State = initialState.ToCode();
    }

    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long RequesterPrincipalId { get; init; }
    public long EntitlementId { get; init; }
    public int RequestedDurationMinutes { get; init; }
    public string Justification { get; init; } = string.Empty;
    public string? TicketReference { get; init; }
    public string State { get; private set; } = string.Empty;
    public string IdempotencyKey { get; init; } = string.Empty;
    public string? PayloadHash { get; init; }
    public DateTime CreatedAt { get; init; }

    public Principal RequesterPrincipal { get; set; } = null!;
    public Entitlement Entitlement { get; set; } = null!;

    public void TransitionTo(AccessRequestState next)
    {
        if (!AccessRequestStates.Parse(State).CanTransitionTo(next))
        {
            throw new InvalidOperationException("The request state transition is not allowed.");
        }

        State = next.ToCode();
    }
}
