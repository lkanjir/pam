using System.ComponentModel.DataAnnotations;

namespace Application.AccessRequests;

/// <summary>Requests temporary access to one entitlement on a managed resource.</summary>
public sealed record CreateAccessRequestRequest
{
    public required Guid ResourceId { get; init; }
    public required Guid EntitlementId { get; init; }

    [Range(1, int.MaxValue)]
    public int RequestedDurationMinutes { get; init; }

    [Required, StringLength(2000)]
    public required string Justification { get; init; }

    [StringLength(100)]
    public string? TicketReference { get; init; }
}
